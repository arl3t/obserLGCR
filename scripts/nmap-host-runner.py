#!/usr/bin/env python3
"""
Runner nmap en el host — escanea la LAN real (p. ej. 192.168.200.0/24).

Docker (sobre todo Docker Desktop en Mac) aísla la red del contenedor: nmap
dentro del contenedor no alcanza el segmento físico del host.

Uso:
  brew install nmap          # si falta
  python3 scripts/nmap-host-runner.py

Variables:
  NMAP_RUNNER_PORT=8791
  NMAP_RUNNER_BIND=0.0.0.0   # host.docker.internal debe poder conectar
  NMAP_RUNNER_TOKEN=change-me-nmap-runner

En .env / docker-compose (servicio ipam):
  NMAP_RUNNER_URL=http://host.docker.internal:8791
  NMAP_RUNNER_TOKEN=change-me-nmap-runner
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return int(raw)


PORT = _env_int("NMAP_RUNNER_PORT", 8791)
BIND = os.environ.get("NMAP_RUNNER_BIND", "0.0.0.0").strip() or "0.0.0.0"
TOKEN = os.environ.get("NMAP_RUNNER_TOKEN", "change-me-nmap-runner").strip()
DEFAULT_TIMEOUT = _env_int("NMAP_TIMEOUT_SEC", 600)
DEFAULT_HOST_TIMEOUT = _env_int("NMAP_HOST_TIMEOUT_SEC", 5)

SCAN_PROFILES: dict[str, list[str]] = {
    "discovery": ["-sn", "-R"],
    "quick": ["-T4", "-F"],
    "standard": ["-T4", "-sV", "-sC", "--version-light"],
    "full": ["-T4", "-sV", "-sC", "-p-"],
    "stealth": ["-T2", "-sS", "-F"],
    "vulnerabilities": ["-T4", "-sV", "--version-light", "--script", "vuln", "--script-timeout", "120s"],
}

VULN_SCRIPT_ARGS = ["--script", "vuln", "--script-timeout", "120s"]


def validate_targets(raw: str) -> list[str]:
    text = (raw or "").strip()
    if not text:
        raise ValueError("targets requerido")
    parts = [p.strip() for p in text.replace("\n", ",").split(",") if p.strip()]
    out: list[str] = []
    for part in parts:
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            if net.version != 4:
                raise ValueError(f"Solo IPv4: {part}")
            out.append(str(net))
        else:
            ip = ipaddress.ip_address(part)
            if ip.version != 4:
                raise ValueError(f"Solo IPv4: {part}")
            out.append(str(ip))
    return out


def validate_cidr(raw: str) -> str:
    return validate_targets(raw)[0]


def authorized(headers: dict[str, str]) -> bool:
    if not TOKEN:
        return True
    auth = headers.get("Authorization", "")
    if auth == f"Bearer {TOKEN}":
        return True
    return headers.get("X-Nmap-Runner-Token", "") == TOKEN


def run_nmap_scan(
    targets: list[str],
    host_timeout_sec: int,
    timeout_sec: int,
    profile: str = "discovery",
    custom_args: list[str] | None = None,
    scan_cves: bool = False,
) -> dict[str, Any]:
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {"error": "nmap no instalado en el host. Instale: brew install nmap"}

    effective = profile
    if scan_cves and profile == "discovery":
        effective = "vulnerabilities"

    if effective == "custom" and custom_args:
        profile_args = list(custom_args)
        if scan_cves:
            profile_args.extend(VULN_SCRIPT_ARGS)
    else:
        profile_args = list(SCAN_PROFILES.get(effective, SCAN_PROFILES["discovery"]))
        if scan_cves and effective not in ("vulnerabilities", "discovery"):
            profile_args.extend(VULN_SCRIPT_ARGS)

    cmd = [
        nmap_bin,
        *profile_args,
        "-oX",
        "-",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{host_timeout_sec}s",
        *targets,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Tiempo de espera agotado ({timeout_sec}s) escaneando {', '.join(targets)}"}

    if proc.returncode not in (0, 1):
        stderr = (proc.stderr or "").strip()
        return {"error": stderr or f"nmap terminó con código {proc.returncode}"}

    summary = (proc.stderr or "").splitlines()[0] if proc.stderr else "nmap (host)"
    return {"xml": proc.stdout or "", "summary": summary, "command": " ".join(cmd)}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[nmap-host-runner] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "nmap-host-runner",
                    "nmap": shutil.which("nmap") is not None,
                    "bind": BIND,
                    "port": PORT,
                },
            )
            return
        self._send_json(404, {"detail": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/scan":
            self._send_json(404, {"detail": "not found"})
            return

        if not authorized({k: v for k, v in self.headers.items()}):
            self._send_json(401, {"detail": "no autorizado"})
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"detail": "JSON inválido"})
            return

        try:
            cidr = body.get("cidr")
            targets_raw = body.get("targets") or cidr
            targets = validate_targets(str(targets_raw))
        except ValueError as exc:
            self._send_json(400, {"detail": str(exc)})
            return

        profile = str(body.get("profile") or "discovery")
        custom_args = body.get("custom_args")
        if custom_args and isinstance(custom_args, list):
            custom_args = [str(a) for a in custom_args]
        else:
            custom_args = None

        host_timeout = int(body.get("host_timeout_sec") or DEFAULT_HOST_TIMEOUT)
        timeout = int(body.get("timeout_sec") or DEFAULT_TIMEOUT)
        scan_cves = bool(body.get("scan_cves"))
        result = run_nmap_scan(
            targets,
            host_timeout,
            timeout,
            profile=profile,
            custom_args=custom_args,
            scan_cves=scan_cves,
        )
        status = 502 if result.get("error") else 200
        self._send_json(status, result)


def main() -> None:
    if not shutil.which("nmap"):
        print("ERROR: nmap no está en PATH. Instale: brew install nmap", file=sys.stderr)
        sys.exit(1)

    server = ThreadingHTTPServer((BIND, PORT), Handler)
    print(
        f"nmap host runner en http://{BIND}:{PORT} "
        f"(health: /health, scan: POST /scan). Ctrl+C para salir.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDetenido.", flush=True)


if __name__ == "__main__":
    main()
