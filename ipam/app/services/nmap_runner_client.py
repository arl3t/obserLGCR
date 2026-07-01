"""Cliente HTTP al runner nmap en el host (fuera del namespace de red Docker)."""

from __future__ import annotations

import httpx

from app.config import settings


class NmapRunnerError(RuntimeError):
    pass


def _runner_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    token = (settings.nmap_runner_token or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def check_nmap_runner_health() -> bool:
    url = (settings.nmap_runner_url or "").strip()
    if not url:
        return False
    try:
        with httpx.Client(timeout=5.0) as client:
            res = client.get(f"{url.rstrip('/')}/health", headers=_runner_headers())
            return res.status_code == 200 and res.json().get("ok") is True
    except (httpx.HTTPError, ValueError):
        return False


def run_nmap_via_runner(cidr: str) -> tuple[str, str]:
    """
    Pide al host que ejecute nmap y devuelve (xml_stdout, summary).
    """
    url = (settings.nmap_runner_url or "").strip()
    if not url:
        raise NmapRunnerError("NMAP_RUNNER_URL no configurado")

    endpoint = f"{url.rstrip('/')}/scan"
    timeout = float(settings.nmap_timeout_sec + 60)

    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.post(
                endpoint,
                json={
                    "cidr": cidr,
                    "host_timeout_sec": settings.nmap_host_timeout_sec,
                    "timeout_sec": settings.nmap_timeout_sec,
                },
                headers=_runner_headers(),
            )
    except httpx.ConnectError as exc:
        raise NmapRunnerError(
            "No se pudo conectar al runner nmap en el host. "
            "En Mac/Linux con Docker Desktop arranque en el host: "
            "python3 scripts/nmap-host-runner.py "
            "(requiere nmap instalado: brew install nmap).",
        ) from exc
    except httpx.TimeoutException as exc:
        raise NmapRunnerError(
            f"Tiempo de espera agotado ({settings.nmap_timeout_sec}s) escaneando {cidr} vía host runner",
        ) from exc
    except httpx.HTTPError as exc:
        raise NmapRunnerError(f"Error HTTP al runner nmap: {exc}") from exc

    if res.status_code == 401:
        raise NmapRunnerError("Token del runner nmap inválido (NMAP_RUNNER_TOKEN)")
    if res.status_code >= 400:
        detail = res.text.strip() or res.reason_phrase
        try:
            detail = res.json().get("detail", detail)
        except ValueError:
            pass
        raise NmapRunnerError(str(detail))

    try:
        payload = res.json()
    except ValueError as exc:
        raise NmapRunnerError("Respuesta inválida del runner nmap") from exc

    xml = payload.get("xml") or ""
    summary = payload.get("summary") or "nmap (host runner)"
    if payload.get("error"):
        raise NmapRunnerError(str(payload["error"]))
    return xml, summary


def run_nmap_scan_via_runner(
    *,
    targets: str,
    profile: str = "discovery",
    custom_args: list[str] | None = None,
) -> dict:
    """Escaneo nmap completo vía host runner (perfiles discovery/quick/standard/full)."""
    url = (settings.nmap_runner_url or "").strip()
    if not url:
        raise NmapRunnerError("NMAP_RUNNER_URL no configurado")

    endpoint = f"{url.rstrip('/')}/scan"
    timeout = float(settings.nmap_timeout_sec + 60)
    body: dict = {
        "targets": targets,
        "cidr": targets.split(",")[0].strip(),
        "profile": profile,
        "host_timeout_sec": settings.nmap_host_timeout_sec,
        "timeout_sec": settings.nmap_timeout_sec,
    }
    if custom_args:
        body["custom_args"] = custom_args

    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.post(endpoint, json=body, headers=_runner_headers())
    except httpx.ConnectError as exc:
        raise NmapRunnerError(
            "No se pudo conectar al runner nmap en el host. Arranque: python3 scripts/nmap-host-runner.py",
        ) from exc
    except httpx.TimeoutException as exc:
        raise NmapRunnerError(
            f"Tiempo de espera agotado ({settings.nmap_timeout_sec}s) escaneando {targets}",
        ) from exc
    except httpx.HTTPError as exc:
        raise NmapRunnerError(f"Error HTTP al runner nmap: {exc}") from exc

    if res.status_code == 401:
        raise NmapRunnerError("Token del runner nmap inválido (NMAP_RUNNER_TOKEN)")
    if res.status_code >= 400:
        detail = res.text.strip() or res.reason_phrase
        try:
            detail = res.json().get("detail", detail)
        except ValueError:
            pass
        raise NmapRunnerError(str(detail))

    try:
        payload = res.json()
    except ValueError as exc:
        raise NmapRunnerError("Respuesta inválida del runner nmap") from exc

    if payload.get("error"):
        raise NmapRunnerError(str(payload["error"]))
    return payload
