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


def _runner_base_urls() -> list[str]:
    """URLs del runner; incluye fallback al gateway Docker en Linux."""
    raw = (settings.nmap_runner_url or "").strip()
    if not raw:
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        u = part.strip().rstrip("/")
        if not u or u in seen:
            continue
        seen.add(u)
        urls.append(u)
    primary = urls[0] if urls else ""
    if primary and "host.docker.internal" in primary:
        try:
            from urllib.parse import urlparse

            parsed = urlparse(primary)
            port = parsed.port or 8791
            fallback = f"http://172.17.0.1:{port}"
            if fallback not in seen:
                urls.append(fallback)
        except Exception:
            pass
    return urls


def _request_runner(
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
    timeout: float = 5.0,
) -> httpx.Response:
    headers = _runner_headers()
    last_exc: Exception | None = None
    for base in _runner_base_urls():
        url = f"{base.rstrip('/')}{path}"
        try:
            with httpx.Client(timeout=timeout) as client:
                if method == "GET":
                    return client.get(url, headers=headers)
                return client.post(url, json=json_body or {}, headers=headers)
        except httpx.HTTPError as exc:
            last_exc = exc
            continue
    if last_exc:
        raise NmapRunnerError(
            "No se pudo conectar al runner nmap en el host. "
            "Arranque: docker compose up -d nmap-runner "
            "o ./scripts/start-nmap-runner.sh",
        ) from last_exc
    raise NmapRunnerError("NMAP_RUNNER_URL no configurado")


def check_nmap_runner_health() -> bool:
    if not _runner_base_urls():
        return False
    try:
        res = _request_runner("GET", "/health", timeout=5.0)
        return res.status_code == 200 and res.json().get("ok") is True
    except (NmapRunnerError, ValueError):
        return False


def run_nmap_via_runner(cidr: str) -> tuple[str, str]:
    """
    Pide al host que ejecute nmap y devuelve (xml_stdout, summary).
    """
    if not _runner_base_urls():
        raise NmapRunnerError("NMAP_RUNNER_URL no configurado")

    timeout = float(settings.nmap_timeout_sec + 60)

    try:
        res = _request_runner(
            "POST",
            "/scan",
            json_body={
                "cidr": cidr,
                "host_timeout_sec": settings.nmap_host_timeout_sec,
                "timeout_sec": settings.nmap_timeout_sec,
            },
            timeout=timeout,
        )
    except NmapRunnerError:
        raise
    except httpx.TimeoutException as exc:
        raise NmapRunnerError(
            f"Tiempo de espera agotado ({settings.nmap_timeout_sec}s) escaneando {cidr} vía host runner",
        ) from exc

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
    scan_cves: bool = False,
) -> dict:
    """Escaneo nmap completo vía host runner (perfiles discovery/quick/standard/full)."""
    if not _runner_base_urls():
        raise NmapRunnerError("NMAP_RUNNER_URL no configurado")

    timeout = float(settings.nmap_timeout_sec + 60)
    body: dict = {
        "targets": targets,
        "cidr": targets.split(",")[0].strip(),
        "profile": profile,
        "host_timeout_sec": settings.nmap_host_timeout_sec,
        "timeout_sec": settings.nmap_timeout_sec,
        "scan_cves": scan_cves,
    }
    if custom_args:
        body["custom_args"] = custom_args

    try:
        res = _request_runner("POST", "/scan", json_body=body, timeout=timeout)
    except NmapRunnerError:
        raise
    except httpx.TimeoutException as exc:
        raise NmapRunnerError(
            f"Tiempo de espera agotado ({settings.nmap_timeout_sec}s) escaneando {targets}",
        ) from exc

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
