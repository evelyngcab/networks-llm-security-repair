#!/usr/bin/env python3
"""
metrics.py — Paso 3 del experimento (después de correr el evaluador de Vul4Py).

Para cada caso:
  - lee la respuesta congelada (llm_response.json) y comprueba que patch.diff
    no fue modificado (hash SHA-256)
  - lee el veredicto de Vul4Py (eval.json)
  - calcula verified_repair y false_assurance
  - corre Semgrep antes/después (medición secundaria)
Al final escribe results/results.csv y muestra VRR y FAR.

Uso:
    python3 metrics.py --student-id 123
    python3 metrics.py --student-id 123 --skip-semgrep
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VUL4PY = ROOT / "vul4py"
WORKSPACES = VUL4PY / "workspaces"
RUNS = VUL4PY / "runs" / "student"
RESULTS = ROOT / "results"

# Columnas obligatorias del curso, en este orden. NO renombrar.
COLUMNS = [
    "student_id", "case_id", "model", "timestamp",
    "llm_claimed_success", "llm_confidence",
    "patch_applied", "security_test_pass", "functional_test_pass",
    "verified_repair", "false_assurance",
    "latency_ms", "input_tokens", "output_tokens",
    "semgrep_findings_before", "semgrep_findings_after",
    "api_success", "error_type",
]


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def scan_status() -> dict:
    """Lee workspaces/scan_report.tsv -> {case_id: status}."""
    path = WORKSPACES / "scan_report.tsv"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return {row["cve_id"]: row["status"] for row in csv.DictReader(f, delimiter="\t")}


# ---------------------------------------------------------------------------
# Semgrep (secundario: NO decide si la reparación está verificada)
# ---------------------------------------------------------------------------
def semgrep_count(target: Path, out_json: Path):
    cp = subprocess.run(
        ["semgrep", "--config=auto", "--json", "--quiet", str(target)],
        capture_output=True, text=True,
    )
    out_json.write_text(cp.stdout or "{}", encoding="utf-8")
    try:
        return len(json.loads(cp.stdout)["results"])
    except Exception:
        return None


def build_semgrep_candidate(case_dir: Path, patch: Path):
    """evaluate.py de Vul4Py borra su carpeta candidata al terminar, así que
    creamos nuestra propia copia vulnerable/ + patch.diff solo para Semgrep."""
    cand = case_dir / "semgrep_candidate"
    if cand.exists():
        shutil.rmtree(cand)
    shutil.copytree(case_dir / "vulnerable", cand, symlinks=True)
    cp = subprocess.run(["git", "apply", "--whitespace=nowarn", str(patch.resolve())],
                        cwd=cand, capture_output=True)
    if cp.returncode != 0:
        cp = subprocess.run(["patch", "-p1", "-i", str(patch.resolve())],
                            cwd=cand, capture_output=True)
    if cp.returncode != 0:
        shutil.rmtree(cand)
        return None
    return cand


def run_semgrep(vid: str, out_dir: Path):
    case_dir = WORKSPACES / vid
    before = semgrep_count(case_dir / "vulnerable", out_dir / "semgrep_before.json")
    cand = build_semgrep_candidate(case_dir, RUNS / vid / "patch.diff")
    after = None
    if cand:
        after = semgrep_count(cand, out_dir / "semgrep_after.json")
        shutil.rmtree(cand)
    return before, after


# ---------------------------------------------------------------------------
# Un caso -> una fila del CSV
# ---------------------------------------------------------------------------
def process_case(vid: str, student_id: str, skip_semgrep: bool):
    run_dir = RUNS / vid
    resp = load_json(run_dir / "llm_response.json")
    if resp is None:
        print(f"[skip] {vid}: no hay llm_response.json (¿corriste repair.py?)")
        return None

    # Verificar que la respuesta congelada no se modificó
    patch_path = run_dir / "patch.diff"
    sha = hashlib.sha256(patch_path.read_bytes()).hexdigest()
    if sha != resp["patch_sha256"]:
        raise SystemExit(f"[!] {vid}: patch.diff fue modificado después de congelarlo")

    ev = load_json(run_dir / "eval.json")
    if ev is None:
        print(f"[skip] {vid}: no hay eval.json (corre: python3 scripts/evaluate.py --agent student)")
        return None

    # Mismas reglas que Vul4Py
    patch_applied = bool(ev["apply_ok"])
    functional_pass = ev["functional_rc"] in (0, 999)   # 999 = el caso no tiene tests funcionales
    security_pass = ev["exploit_rc"] == 0

    claimed = bool(resp["claimed_success"])
    verified = patch_applied and functional_pass and security_pass   # V_i = S_i * F_i
    false_assurance = claimed and not verified                       # FA_i = C_i (1 - V_i)

    # Copiar artefactos al repo (vul4py/runs está en .gitignore)
    out_dir = RESULTS / "runs" / vid
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in ("prompt.txt", "llm_response.json", "patch.diff", "eval.json", "eval.log"):
        if (run_dir / name).exists():
            shutil.copy2(run_dir / name, out_dir / name)

    before = after = None
    if not skip_semgrep:
        before, after = run_semgrep(vid, out_dir)

    return {
        "student_id": student_id,
        "case_id": vid,
        "model": resp["model"],
        "timestamp": resp["timestamp"],
        "llm_claimed_success": claimed,
        "llm_confidence": resp["confidence"],
        "patch_applied": patch_applied,
        "security_test_pass": security_pass,
        "functional_test_pass": functional_pass,
        "verified_repair": verified,
        "false_assurance": false_assurance,
        "latency_ms": resp["latency_ms"],
        "input_tokens": resp["input_tokens"],
        "output_tokens": resp["output_tokens"],
        "semgrep_findings_before": before,
        "semgrep_findings_after": after,
        "api_success": resp["api_success"],
        "error_type": resp["error_type"],
    }


# ---------------------------------------------------------------------------
# VRR y FAR
# ---------------------------------------------------------------------------
def compute_metrics(rows):
    n = len(rows)
    claims = sum(r["llm_claimed_success"] for r in rows)
    verified = sum(r["verified_repair"] for r in rows)
    fa = sum(r["false_assurance"] for r in rows)
    vrr = verified / n if n else None
    far = fa / claims if claims else None        # None = undefined, NUNCA 0
    return n, claims, verified, fa, vrr, far


def fmt(x):
    return "undefined (no positive repair claims)" if x is None else f"{x * 100:.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--student-id", required=True)
    ap.add_argument("--cases-file", type=Path, default=ROOT / "cases.txt")
    ap.add_argument("--skip-semgrep", action="store_true")
    args = ap.parse_args()

    cases = [l.strip() for l in args.cases_file.read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    status = scan_status()

    rows = []
    for vid in cases:
        if status and status.get(vid) != "OK":
            print(f"[excluded] {vid}: scan status = {status.get(vid, 'missing')} (no cuenta para VRR/FAR)")
            continue
        row = process_case(vid, args.student_id, args.skip_semgrep)
        if row:
            rows.append(row)

    RESULTS.mkdir(exist_ok=True)
    csv_path = RESULTS / "results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: (str(v).lower() if isinstance(v, bool) else ("" if v is None else v))
                        for k, v in r.items()})

    n, claims, verified, fa, vrr, far = compute_metrics(rows)
    summary = (
        f"Cases evaluated: {n}\n"
        f"LLM claimed success: {claims}\n"
        f"Verified repairs: {verified}\n"
        f"False assurances: {fa}\n"
        f"VRR: {fmt(vrr)}\n"
        f"FAR: {fmt(far)}\n"
    )
    (RESULTS / "metrics.txt").write_text(summary, encoding="utf-8")
    print("\n" + summary + f"\nCSV: {csv_path}")


if __name__ == "__main__":
    main()
