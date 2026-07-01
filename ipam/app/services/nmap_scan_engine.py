"""Motor nmap completo: perfiles, ejecución (contenedor o host runner) y parseo XML."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.config import settings
from app.services.nmap_discovery import NmapNotAvailableError, NmapScanError, normalize_mac
from app.services.nmap_runner_client import NmapRunnerError, run_nmap_via_runner

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SEVERITY_RE = re.compile(r"\b(critical|high|medium|low|info)\b", re.IGNORECASE)
CVSS_RE = re.compile(r"(?:CVSS[:\s]+|score[:\s]+)?(\d+\.\d+)", re.IGNORECASE)
SCRIPT_CVE_RE = re.compile(r"cve(\d{4})-(\d+)", re.IGNORECASE)

VULN_SCRIPT_ARGS = ["--script", "vuln", "--script-timeout", "120s"]

SCAN_PROFILES: dict[str, list[str]] = {
    "discovery": ["-sn", "-R"],
    "quick": ["-T4", "-F"],
    "standard": ["-T4", "-sV", "-sC", "--version-light"],
    "full": ["-T4", "-sV", "-sC", "-p-"],
    "stealth": ["-T2", "-sS", "-F"],
    "vulnerabilities": ["-T4", "-sV", "--version-light", *VULN_SCRIPT_ARGS],
}

PROFILE_LABELS: dict[str, str] = {
    "discovery": "Descubrimiento de hosts (-sn)",
    "quick": "Rápido — 100 puertos top (-F)",
    "standard": "Estándar — servicios + scripts (-sV -sC)",
    "full": "Completo — todos los puertos (-p-)",
    "stealth": "Sigiloso SYN (-sS -F)",
    "vulnerabilities": "CVE / vulnerabilidades (--script vuln)",
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
class ParsedVulnerability:
    cve_id: str
    severity: str | None = None
    cvss_score: float | None = None
    title: str | None = None
    port: int | None = None
    protocol: str | None = None
    script_id: str | None = None
    details: str | None = None


@dataclass(slots=True)
class ParsedHost:
    ip: str
    status: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    ports: list[ParsedPort] = field(default_factory=list)
    vulnerabilities: list[ParsedVulnerability] = field(default_factory=list)


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


def resolve_scan_profile(profile: str, scan_cves: bool) -> str:
    if scan_cves and profile == "discovery":
        return "vulnerabilities"
    if scan_cves and profile not in ("vulnerabilities", "custom"):
        return profile
    return profile


def _profile_args(profile: str, scan_cves: bool) -> list[str]:
    effective = resolve_scan_profile(profile, scan_cves)
    if effective == "custom":
        return []
    args = list(SCAN_PROFILES.get(effective, SCAN_PROFILES["discovery"]))
    if scan_cves and effective not in ("vulnerabilities", "discovery"):
        args = [*args, *VULN_SCRIPT_ARGS]
    return args


def build_nmap_command(
    targets: str,
    profile: str,
    custom_args: str | None = None,
    *,
    scan_cves: bool = False,
) -> list[str]:
    nmap_bin = shutil.which("nmap") or "nmap"
    effective = resolve_scan_profile(profile, scan_cves)
    if effective == "custom":
        args = parse_custom_args(custom_args)
        if not args:
            raise ValueError("Perfil custom requiere custom_args")
        if scan_cves:
            args = [*args, *VULN_SCRIPT_ARGS]
    else:
        args = _profile_args(profile, scan_cves)

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


def _normalize_cve(raw: str) -> str:
    return raw.upper()


def _cve_from_script_id(script_id: str) -> str | None:
    m = SCRIPT_CVE_RE.search(script_id)
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def _guess_severity(text: str) -> str | None:
    m = SEVERITY_RE.search(text)
    return m.group(1).lower() if m else None


def _guess_cvss(text: str) -> float | None:
    m = CVSS_RE.search(text)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _extract_cves_from_text(text: str) -> list[str]:
    return [_normalize_cve(c) for c in CVE_RE.findall(text or "")]


def _parse_script_vulns(
    script_el: ET.Element,
    *,
    port: int | None = None,
    protocol: str | None = None,
) -> list[ParsedVulnerability]:
    script_id = script_el.get("id", "") or ""
    output = script_el.get("output", "") or ""
    table_text = " ".join(elem.text or "" for elem in script_el.iter("elem"))
    combined = f"{output}\n{table_text}".strip()
    if not combined and not script_id:
        return []

    cve_ids: set[str] = set(_extract_cves_from_text(combined))
    script_cve = _cve_from_script_id(script_id)
    if script_cve:
        cve_ids.add(script_cve)

    if not cve_ids:
        if "VULNERABLE" in combined.upper() and script_cve:
            cve_ids.add(script_cve)
        elif "vuln" in script_id.lower() and combined:
            cve_ids.add(f"NMAP-{script_id.upper()}")

    severity = _guess_severity(combined)
    cvss = _guess_cvss(combined)
    title = output.splitlines()[0][:500] if output else script_id or None

    vulns: list[ParsedVulnerability] = []
    for cve_id in sorted(cve_ids):
        if cve_id.startswith("NMAP-"):
            continue
        vulns.append(
            ParsedVulnerability(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss,
                title=title,
                port=port,
                protocol=protocol,
                script_id=script_id or None,
                details=combined[:4000] if combined else None,
            ),
        )
    return vulns


def _dedupe_vulns(vulns: list[ParsedVulnerability]) -> list[ParsedVulnerability]:
    seen: set[tuple[str, int | None, str | None]] = set()
    out: list[ParsedVulnerability] = []
    for v in vulns:
        key = (v.cve_id, v.port, v.script_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


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
        host_vulns: list[ParsedVulnerability] = []
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
                port_num = int(port_id)
                ports.append(
                    ParsedPort(
                        port=port_num,
                        protocol=protocol,
                        state=state,
                        service=service,
                        product=product,
                        version=version,
                        extra_info=extra,
                    ),
                )
                for script_el in port_el.findall("script"):
                    host_vulns.extend(
                        _parse_script_vulns(script_el, port=port_num, protocol=protocol),
                    )

        for script_el in host_el.findall("hostscript/script"):
            host_vulns.extend(_parse_script_vulns(script_el))

        hosts.append(
            ParsedHost(
                ip=ip,
                status=status,
                hostname=hostname,
                mac=mac,
                os_guess=os_guess,
                ports=ports,
                vulnerabilities=_dedupe_vulns(host_vulns),
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
    *,
    scan_cves: bool = False,
) -> tuple[list[ParsedHost], str, str, str]:
    """
    Ejecuta nmap y devuelve (hosts, summary, command, raw_xml).
    """
    normalized = validate_targets(targets)
    from app.services.nmap_discovery import is_nmap_runner_configured

    if is_nmap_runner_configured():
        custom_list = parse_custom_args(custom_args) if profile == "custom" else None
        try:
            xml_text, summary, command = _run_via_runner(
                normalized,
                profile,
                custom_list,
                scan_cves=scan_cves,
            )
        except NmapRunnerError as exc:
            raise NmapScanError(str(exc)) from exc
    else:
        if not shutil.which("nmap"):
            raise NmapNotAvailableError("nmap no disponible")
        cmd = build_nmap_command(normalized, profile, custom_args, scan_cves=scan_cves)
        xml_text, summary, command = _run_local(cmd)

    hosts = parse_nmap_full_xml(xml_text)
    return hosts, summary, command, xml_text


def _run_via_runner(
    targets: str,
    profile: str,
    custom_args: list[str] | None,
    *,
    scan_cves: bool = False,
) -> tuple[str, str, str]:
    from app.services.nmap_runner_client import run_nmap_scan_via_runner

    payload = run_nmap_scan_via_runner(
        targets=targets,
        profile=profile,
        custom_args=custom_args,
        scan_cves=scan_cves,
    )
    return payload["xml"], payload.get("summary", "nmap (host runner)"), payload.get("command", "")
