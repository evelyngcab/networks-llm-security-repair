#!/usr/bin/env python3
"""
repair.py — Paso 1 del experimento.

Para cada caso de Vul4Py:
  1. Lee el código vulnerable de workspaces/<ID>/vulnerable/ (NUNCA fixed/)
  2. Construye el prompt obligatorio del curso + el código fuente
  3. Llama a la API de OpenAI por HTTPS y mide la latencia end-to-end
  4. Guarda y CONGELA: prompt.txt, llm_response.json, patch.diff

Si llm_response.json ya existe para un caso, NO se vuelve a llamar a la API
(la respuesta está congelada: una sola oportunidad de reparación).

Uso:
    export OPENAI_API_KEY="..."
    python3 repair.py --cases-file cases.txt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import openai
from openai import OpenAI

# ---------------------------------------------------------------------------
# Configuración (el modelo se define UNA sola vez, aquí)
# ---------------------------------------------------------------------------
MODEL = "gpt-6-luna"   # GPT-6 Luna, modelo indicado en el documento del proyecto
AGENT = "student"                         # carpeta runs/student/ que usa Vul4Py
API_HOST = "api.openai.com"
TIMEOUT_S = 300                           # timeout de la petición HTTP

ROOT = Path(__file__).resolve().parent
VUL4PY = ROOT / "vul4py"
WORKSPACES = VUL4PY / "workspaces"
RUNS = VUL4PY / "runs" / AGENT

# Prompt obligatorio del curso. NO MODIFICAR.
REQUIRED_PROMPT = (
    "You are given vulnerable Python source code from a real software project. "
    "Repair the security vulnerability while preserving the intended functionality. "
    "You have only one repair attempt. Return a unified diff patch that can be "
    "applied to the original project. Also report: 1. whether you believe the "
    "vulnerability has been successfully repaired; 2. your confidence in that "
    "assessment as a number between 0.0 and 1.0. Do not assume access to external "
    "verification results."
)

# Esquema JSON que obliga a la API a devolver exactamente estos 3 campos.
# Se envía como parámetro de la API, así el texto del prompt queda intacto.
RESPONSE_SCHEMA = {
    "type": "json_schema",
    "name": "repair_result",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "claimed_success": {"type": "boolean"},
            "confidence": {"type": "number"},
            "patch": {"type": "string"},
        },
        "required": ["claimed_success", "confidence", "patch"],
        "additionalProperties": False,
    },
}


# ---------------------------------------------------------------------------
# Lectura del código vulnerable
# ---------------------------------------------------------------------------
def collect_source_files(case_dir: Path, max_files: int = 4, max_bytes: int = 60_000):
    """Devuelve [(ruta_relativa, contenido)] desde vulnerable/.

    Usa la misma regla que el harness oficial de Vul4Py (run_agent.py):
    los archivos de código listados en meta.json -> new_code_files.
    Solo se lee de vulnerable/; fixed/ nunca se toca.
    """
    meta = json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))
    vuln_dir = case_dir / "vulnerable"
    out, used = [], 0
    for rel in meta.get("new_code_files", []):
        if len(out) >= max_files:
            break
        full = vuln_dir / rel
        if not full.is_file():
            continue
        data = full.read_text(encoding="utf-8", errors="replace")
        if used + len(data) > max_bytes:
            continue
        out.append((rel, data))
        used += len(data)
    return out


def build_prompt(files) -> str:
    parts = [REQUIRED_PROMPT, ""]
    for rel, data in files:
        parts.append(f"--- FILE: {rel} ---")
        parts.append(data.rstrip())
        parts.append(f"--- END FILE: {rel} ---")
        parts.append("")
    return "\n".join(parts)


def normalize_patch(text: str) -> str:
    """Normalización automática y determinista (igual que Vul4Py):
    quita bloques ``` si el modelo los puso y asegura salto de línea final.
    No es una modificación manual del parche."""
    s = text.strip()
    if s.startswith("```"):
        lines = s.splitlines()[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines)
    return s + "\n" if s else ""


# ---------------------------------------------------------------------------
# Medición de red
# ---------------------------------------------------------------------------
def resolve_dns(host: str):
    """Resuelve el hostname a IP (lo mismo que hará la librería internamente).
    Se mide aparte solo como dato informativo."""
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
        return ips, round((time.perf_counter() - t0) * 1000, 2), None
    except socket.gaierror as e:
        return [], round((time.perf_counter() - t0) * 1000, 2), str(e)


def classify_error(e: Exception):
    """Traduce la excepción del SDK a (error_type, http_status)."""
    if isinstance(e, openai.APITimeoutError):
        return "timeout", None
    if isinstance(e, openai.APIConnectionError):
        return "connection_error", None          # DNS, TCP o TLS fallaron
    if isinstance(e, openai.AuthenticationError):
        return "auth_error_401", 401
    if isinstance(e, openai.RateLimitError):
        return "rate_limit_429", 429
    if isinstance(e, openai.InternalServerError):
        return f"server_error_{e.status_code}", e.status_code
    if isinstance(e, openai.APIStatusError):
        return f"http_{e.status_code}", e.status_code
    return type(e).__name__, None


# ---------------------------------------------------------------------------
# Un caso
# ---------------------------------------------------------------------------
def repair_case(client: OpenAI, vuln_id: str) -> None:
    case_dir = WORKSPACES / vuln_id
    out_dir = RUNS / vuln_id
    frozen = out_dir / "llm_response.json"

    if frozen.exists():
        print(f"[frozen] {vuln_id}: ya existe una respuesta, no se vuelve a llamar a la API")
        return
    if not (case_dir / "meta.json").exists():
        print(f"[skip] {vuln_id}: no existe {case_dir}/meta.json (¿corriste prepare.py?)")
        return

    files = collect_source_files(case_dir)
    if not files:
        print(f"[skip] {vuln_id}: no se encontraron archivos de código en vulnerable/")
        return

    prompt = build_prompt(files)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    ips, dns_ms, dns_err = resolve_dns(API_HOST)

    record = {
        "case_id": vuln_id,
        "model": MODEL,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "context_files": [r for r, _ in files],
        "api_host": API_HOST,
        "resolved_ips": ips,
        "dns_lookup_ms": dns_ms,
        "api_success": False,
        "error_type": "",
        "http_status": None,
        "latency_ms": None,
        "input_tokens": None,
        "output_tokens": None,
        "claimed_success": None,
        "confidence": None,
        "raw_output_text": None,
        "patch_sha256": None,
    }

    start = time.perf_counter()                       # justo antes de la petición
    try:
        response = client.responses.create(
            model=MODEL,
            input=prompt,
            text={"format": RESPONSE_SCHEMA},
        )
        end = time.perf_counter()                     # justo después de recibirla
        record["latency_ms"] = round((end - start) * 1000, 2)
        record["http_status"] = 200
        record["raw_output_text"] = response.output_text
        if response.usage:
            record["input_tokens"] = response.usage.input_tokens
            record["output_tokens"] = response.usage.output_tokens

        parsed = json.loads(response.output_text)
        record["claimed_success"] = bool(parsed["claimed_success"])
        record["confidence"] = float(parsed["confidence"])
        patch = normalize_patch(parsed["patch"])
        record["api_success"] = True
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        # La API respondió (red OK) pero el contenido no tiene el formato esperado
        record["error_type"] = "invalid_json_response"
        patch = None
    except Exception as e:  # errores de red / HTTP
        record["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
        record["error_type"], record["http_status"] = classify_error(e)
        if dns_err:
            record["error_type"] = "dns_resolution_failed"
        record["error_message"] = str(e)[:500]
        patch = None

    if not record["api_success"]:
        # Un fallo de red no es un intento de reparación: se registra en un log
        # aparte y el caso NO queda congelado (se puede reintentar la conexión).
        with open(out_dir / "api_errors.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        print(f"[error] {vuln_id}: {record['error_type']} ({record['latency_ms']} ms)")
        return

    # --- CONGELAR -----------------------------------------------------------
    (out_dir / "patch.diff").write_text(patch, encoding="utf-8")
    record["patch_sha256"] = hashlib.sha256(patch.encode("utf-8")).hexdigest()
    frozen.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(
        f"[ok] {vuln_id}: claimed_success={record['claimed_success']} "
        f"confidence={record['confidence']} latency={record['latency_ms']} ms "
        f"tokens={record['input_tokens']}/{record['output_tokens']}"
    )


def main():
    ap = argparse.ArgumentParser(description="Generate one frozen LLM repair per Vul4Py case.")
    ap.add_argument("--cases-file", type=Path, default=ROOT / "cases.txt")
    args = ap.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY no está configurada (usa: export OPENAI_API_KEY=...)")
    if MODEL == "MODEL_PROVIDED_BY_INSTRUCTOR":
        sys.exit("Edita MODEL en repair.py con el nombre del modelo que dio el profesor.")

    cases = [l.strip() for l in args.cases_file.read_text().splitlines()
             if l.strip() and not l.startswith("#")]

    # max_retries=0: una sola petición por caso, así la latencia medida es real
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=TIMEOUT_S, max_retries=0)
    for vid in cases:
        repair_case(client, vid)


if __name__ == "__main__":
    main()
