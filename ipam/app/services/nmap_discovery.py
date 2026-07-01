"""Ejecución de nmap y parseo de salida XML."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Sequence

from app.config import settings
from app.services.rfc1918 import parse_cidr, parse_ip


@dataclass(frozen=True, slots=True)
class NmapHost:
    ip: str
    hostname: str | None = None
    mac: str | None = None


class NmapNotAvailableError(RuntimeError):
    pass


class NmapScanError(RuntimeError):
    pass


from app.config import settings
from app.services.nmap_runner_client import NmapRunnerError, run_nmap_via_runner


def is_nmap_runner_configured() -> bool:
    return bool((settings.nmap_runner_url or "").strip())


def is_nmap_available() -> bool:
    if is_nmap_runner_configured():
        return True
    return shutil.which("nmap") is not None


def normalize_mac(raw: str | None) -> str | None:
    if not raw:
        return None
    cleaned = raw.strip().lower().replace("-", ":")
    if cleaned in {"(unknown)", "unknown", ""}:
        return None
    parts = cleaned.split(":")
    if len(parts) != 6:
        return None
    if not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        return None
    return cleaned


def parse_nmap_xml(xml_text: str) -> list[NmapHost]:
    """Extrae hosts con status up del XML de nmap."""
    if not xml_text.strip():
        return []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapScanError("Salida XML de nmap inválida") from exc

    hosts: list[NmapHost] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

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

        hosts.append(NmapHost(ip=ip, hostname=hostname, mac=mac))

    return hosts


def filter_hosts_in_subnet(hosts: list[NmapHost], cidr: str) -> list[NmapHost]:
    """Conserva solo IPs asignables dentro del bloque (excluye red/broadcast)."""
    network = parse_cidr(cidr)
    seen: set[str] = set()
    filtered: list[NmapHost] = []

    for host in hosts:
        if host.ip in seen:
            continue
        try:
            ip = parse_ip(host.ip)
        except ValueError:
            continue
        if ip not in network:
            continue
        if network.version == 4 and network.prefixlen <= 30:
            if ip == network.network_address or ip == network.broadcast_address:
                continue
        seen.add(host.ip)
        filtered.append(host)

    return filtered


def run_nmap_host_discovery(cidr: str) -> tuple[list[NmapHost], str]:
    """
    Escaneo de descubrimiento (-sn) con resolución DNS inversa.
    Devuelve hosts activos y versión/resumen de nmap.

    Si NMAP_RUNNER_URL está definido, nmap se ejecuta en el host (acceso a LAN 192.168.x.x).
    """
    if is_nmap_runner_configured():
        try:
            xml_text, summary = run_nmap_via_runner(cidr)
        except NmapRunnerError as exc:
            raise NmapScanError(str(exc)) from exc
        hosts = filter_hosts_in_subnet(parse_nmap_xml(xml_text), cidr)
        return hosts, summary

    if not is_nmap_available():
        raise NmapNotAvailableError(
            "nmap no está instalado en el contenedor IPAM. Reconstruya: docker compose build ipam",
        )

    cmd: Sequence[str] = [
        "nmap",
        "-sn",
        "-R",
        "-oX",
        "-",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{settings.nmap_host_timeout_sec}s",
        cidr,
    ]

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
            f"Tiempo de espera agotado ({settings.nmap_timeout_sec}s) escaneando {cidr}",
        ) from exc

    if proc.returncode not in (0, 1):
        stderr = (proc.stderr or "").strip()
        raise NmapScanError(stderr or f"nmap terminó con código {proc.returncode}")

    hosts = filter_hosts_in_subnet(parse_nmap_xml(proc.stdout or ""), cidr)
    summary = (proc.stderr or "").splitlines()[0] if proc.stderr else "nmap"
    return hosts, summary
