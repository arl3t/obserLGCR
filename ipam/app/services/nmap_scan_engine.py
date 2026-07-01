"""Motor nmap completo: perfiles, ejecución (contenedor o host runner) y parseo XML."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.config import settings
from app.services.nmap_discovery import NmapNotAvailableError, NmapScanError, normalize_mac
from app.services.nmap_runner_client import NmapRunnerError, run_nmap_via_runner

SCAN_PROFILES: dict[str, list[str]] = {
    "discovery": ["-sn", "-R"],
    "quick": ["-T4", "-F"],
    "standard": ["-T4", "-sV", "-sC", "--version-light"],
    "full": ["-T4", "-sV", "-sC", "-p-"],
    "stealth": ["-T2", "-sS", "-F"],
}

PROFILE_LABELS: dict[str, str] = {
    "discovery": "Descubrimiento de hosts (-sn)",
    "quick": "Rápido — 100 puertos top (-F)",
    "standard": "Estándar — servicios + scripts (-sV -sC)",
    "full": "Completo — todos los puertos (-p-)",
    "stealth": "Sigiloso SYN (-sS -F)",
    "custom": "Personalizado (custom_args)",
}


@dataclass(slots=True)
class ParsedPort:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass(slots=True)
class ParsedHost:
    ip: str
    status: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    ports: list[ParsedPort] = field(default_factory=list)


def is_scan_available() -> bool:
    from app.services.nmap_discovery import is_nmap_available

    return is_nmap_available()


def validate_targets(raw: str) -> str:
    parts = [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]
    if not parts:
        raise ValueError("Indique al menos un objetivo (IP, CIDR o lista separada por comas)")
    normalized: list[str] = []
    for part in parts:
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            if net.version != 4:
                raise ValueError(f"Solo IPv4 soportado: {part}")
            normalized.append(str(net))
        else:
            ip = ipaddress.ip_address(part)
            if ip.version != 4:
                raise ValueError(f"Solo IPv4 soportado: {part}")
            normalized.append(str(ip))
    return ",".join(normalized)


def parse_custom_args(raw: str | None) -> list[str]:
    if not raw or not raw.strip():
        return []
    return raw.strip().split()


def build_nmap_command(
    targets: str,
    profile: str,
    custom_args: str | None = None,
) -> list[str]:
    nmap_bin = shutil.which("nmap") or "nmap"
    if profile == "custom":
        args = parse_custom_args(custom_args)
        if not args:
            raise ValueError("Perfil custom requiere custom_args")
    else:
        args = list(SCAN_PROFILES.get(profile, SCAN_PROFILES["discovery"]))

    cmd = [
        nmap_bin,
        *args,
        "--max-retries",
        "1",
        "--host-timeout",
        f"{settings.nmap_host_timeout_sec}s",
        "-oX",
        "-",
    ]
    for target in targets.split(","):
        cmd.append(target.strip())
    return cmd


def parse_nmap_full_xml(xml_text: str) -> list[ParsedHost]:
    if not xml_text.strip():
        return []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapScanError("Salida XML de nmap inválida") from exc

    hosts: list[ParsedHost] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"

        ip: str | None = None
        mac: str | None = None
        for addr in host_el.findall("address"):
            addr_type = addr.get("addrtype")
            addr_val = addr.get("addr")
            if not addr_val:
                continue
            if addr_type == "ipv4":
                ip = addr_val
            elif addr_type == "mac":
                mac = normalize_mac(addr_val)

        if not ip:
            continue

        hostname: str | None = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = hn.get("name")
                if name:
                    hostname = name
                    break

        os_guess: str | None = None
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None and osmatch.get("name"):
                os_guess = osmatch.get("name")

        ports: list[ParsedPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_id = port_el.get("portid")
                protocol = port_el.get("protocol", "tcp")
                if not port_id:
                    continue
                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                svc_el = port_el.find("service")
                service = product = version = extra = None
                if svc_el is not None:
                    service = svc_el.get("name")
                    product = svc_el.get("product")
                    version = svc_el.get("version")
                    extra = svc_el.get("extrainfo")
                ports.append(
                    ParsedPort(
                        port=int(port_id),
                        protocol=protocol,
                        state=state,
                        service=service,
                        product=product,
                        version=version,
                        extra_info=extra,
                    ),
                )

        hosts.append(
            ParsedHost(
                ip=ip,
                status=status,
                hostname=hostname,
                mac=mac,
                os_guess=os_guess,
                ports=ports,
            ),
        )

    return hosts


def _run_local(cmd: list[str]) -> tuple[str, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.nmap_timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapScanError(
            f"Tiempo de espera agotado ({settings.nmap_timeout_sec}s)",
        ) from exc

    if proc.returncode not in (0, 1):
        stderr = (proc.stderr or "").strip()
        raise NmapScanError(stderr or f"nmap terminó con código {proc.returncode}")

    summary = (proc.stderr or "").splitlines()[0] if proc.stderr else "nmap"
    return proc.stdout or "", summary, " ".join(cmd)


def run_network_scan(
    targets: str,
    profile: str,
    custom_args: str | None = None,
) -> tuple[list[ParsedHost], str, str, str]:
    """
    Ejecuta nmap y devuelve (hosts, summary, command, raw_xml).
    """
    normalized = validate_targets(targets)
    from app.services.nmap_discovery import is_nmap_runner_configured

    if is_nmap_runner_configured():
        custom_list = parse_custom_args(custom_args) if profile == "custom" else None
        try:
            xml_text, summary, command = _run_via_runner(normalized, profile, custom_list)
        except NmapRunnerError as exc:
            raise NmapScanError(str(exc)) from exc
    else:
        if not shutil.which("nmap"):
            raise NmapNotAvailableError("nmap no disponible")
        cmd = build_nmap_command(normalized, profile, custom_args)
        xml_text, summary, command = _run_local(cmd)

    hosts = parse_nmap_full_xml(xml_text)
    return hosts, summary, command, xml_text


def _run_via_runner(targets: str, profile: str, custom_args: list[str] | None) -> tuple[str, str, str]:
    from app.services.nmap_runner_client import run_nmap_scan_via_runner

    payload = run_nmap_scan_via_runner(
        targets=targets,
        profile=profile,
        custom_args=custom_args,
    )
    return payload["xml"], payload.get("summary", "nmap (host runner)"), payload.get("command", "")
