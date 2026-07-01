"""Persistencia, ejecución async, estadísticas y exportación del módulo descubrimiento."""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import threading
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, text
from sqlalchemy.orm import Session, joinedload

from app.database import SessionLocal
from app.models.discovery import (
    NetworkDiscoveryHost,
    NetworkDiscoveryJob,
    NetworkDiscoveryPort,
    NetworkDiscoveryRun,
    NetworkDiscoveryVulnerability,
)
from app.models.ipam import IPAMSubnet
from app.services.asset_integration import post_discovery_ipam_pipeline
from app.services.nmap_discovery import NmapHost, NmapScanError
from app.services.nmap_scan_engine import ParsedHost, run_network_scan

logger = logging.getLogger("ipam.discovery")


def list_jobs(db: Session) -> list[NetworkDiscoveryJob]:
    return db.query(NetworkDiscoveryJob).order_by(NetworkDiscoveryJob.name).all()


def get_job(db: Session, job_id: int) -> NetworkDiscoveryJob | None:
    return db.get(NetworkDiscoveryJob, job_id)


def create_job(db: Session, data: dict, actor: str) -> NetworkDiscoveryJob:
    job = NetworkDiscoveryJob(**data, created_by=actor)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def update_job(db: Session, job: NetworkDiscoveryJob, data: dict) -> NetworkDiscoveryJob:
    for key, val in data.items():
        setattr(job, key, val)
    job.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(job)
    return job


def delete_job(db: Session, job: NetworkDiscoveryJob) -> None:
    db.delete(job)
    db.commit()


def list_runs(db: Session, limit: int = 50, job_id: int | None = None) -> list[NetworkDiscoveryRun]:
    q = db.query(NetworkDiscoveryRun).order_by(NetworkDiscoveryRun.created_at.desc())
    if job_id:
        q = q.filter(NetworkDiscoveryRun.job_id == job_id)
    return q.limit(limit).all()


def get_run(db: Session, run_id: int) -> NetworkDiscoveryRun | None:
    return db.get(NetworkDiscoveryRun, run_id)


def create_run_record(
    db: Session,
    *,
    targets: str,
    scan_profile: str,
    triggered_by: str,
    job_id: int | None = None,
    name: str | None = None,
    scan_cves: bool = False,
) -> NetworkDiscoveryRun:
    run = NetworkDiscoveryRun(
        job_id=job_id,
        name=name,
        targets=targets,
        scan_profile=scan_profile,
        scan_cves=scan_cves,
        status="pending",
        triggered_by=triggered_by,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _compute_stats(hosts: list[ParsedHost]) -> dict[str, Any]:
    up = [h for h in hosts if h.status == "up"]
    services: Counter[str] = Counter()
    ports: Counter[int] = Counter()
    oses: Counter[str] = Counter()
    cves: Counter[str] = Counter()
    hosts_with_cves = 0
    open_ports = 0
    cves_total = 0
    for h in up:
        if h.os_guess:
            oses[h.os_guess] += 1
        if h.vulnerabilities:
            hosts_with_cves += 1
            cves_total += len(h.vulnerabilities)
            for v in h.vulnerabilities:
                cves[v.cve_id] += 1
        for p in h.ports:
            if p.state == "open":
                open_ports += 1
                if p.service:
                    services[p.service] += 1
                ports[p.port] += 1
    return {
        "hosts_up": len(up),
        "hosts_total": len(hosts),
        "ports_open": open_ports,
        "cves_total": cves_total,
        "hosts_with_cves": hosts_with_cves,
        "by_cve": [{"cve_id": k, "count": v} for k, v in cves.most_common(20)],
        "by_service": [{"service": k, "count": v} for k, v in services.most_common(20)],
        "by_port": [{"port": k, "count": v} for k, v in ports.most_common(20)],
        "by_os": [{"os": k, "count": v} for k, v in oses.most_common(10)],
        "by_status": dict(Counter(h.status for h in hosts)),
    }


def _persist_hosts(db: Session, run_id: int, hosts: list[ParsedHost]) -> None:
    for h in hosts:
        row = NetworkDiscoveryHost(
            run_id=run_id,
            ip_address=h.ip,
            hostname=h.hostname,
            mac_address=h.mac,
            status=h.status,
            os_guess=h.os_guess,
        )
        db.add(row)
        db.flush()
        for p in h.ports:
            if p.state not in ("open", "open|filtered"):
                continue
            db.add(
                NetworkDiscoveryPort(
                    host_id=row.id,
                    port=p.port,
                    protocol=p.protocol,
                    state=p.state,
                    service=p.service,
                    product=p.product,
                    version=p.version,
                    extra_info=p.extra_info,
                ),
            )
        for v in h.vulnerabilities:
            db.add(
                NetworkDiscoveryVulnerability(
                    host_id=row.id,
                    cve_id=v.cve_id,
                    severity=v.severity,
                    cvss_score=v.cvss_score,
                    title=v.title,
                    port=v.port,
                    protocol=v.protocol,
                    script_id=v.script_id,
                    details=v.details,
                ),
            )


def _sync_to_ipam(db: Session, subnet_id: int, hosts: list[ParsedHost]) -> int:
    from app.services.ipam_nmap_sync import sync_nmap_discovery

    subnet = db.get(IPAMSubnet, subnet_id)
    if not subnet or subnet.deleted_at:
        return 0
    nmap_hosts = [
        NmapHost(ip=h.ip, hostname=h.hostname, mac=h.mac)
        for h in hosts
        if h.status == "up"
    ]
    result = sync_nmap_discovery(db, subnet, nmap_hosts)
    return result.get("created", 0) + result.get("updated", 0)


def execute_run(
    run_id: int,
    *,
    custom_args: str | None = None,
    auto_sync_ipam: bool = False,
    ipam_subnet_id: int | None = None,
    scan_cves: bool = False,
) -> None:
    db = SessionLocal()
    started = datetime.now(UTC)
    try:
        run = db.get(NetworkDiscoveryRun, run_id)
        if not run:
            return
        run.status = "running"
        run.started_at = started
        db.commit()

        effective_scan_cves = scan_cves or bool(run.scan_cves)
        hosts, summary, command, raw_xml = run_network_scan(
            run.targets,
            run.scan_profile,
            custom_args=custom_args,
            scan_cves=effective_scan_cves,
        )
        stats = _compute_stats(hosts)
        _persist_hosts(db, run.id, hosts)

        integration: dict[str, int] = {}
        if auto_sync_ipam and ipam_subnet_id:
            _sync_to_ipam(db, ipam_subnet_id, hosts)
            integration = post_discovery_ipam_pipeline(db, ipam_subnet_id, hosts, run_id=run.id)
        else:
            from app.services.nmap_discovery import NmapHost

            nmap_hosts = [
                NmapHost(ip=h.ip, hostname=h.hostname, mac=h.mac)
                for h in hosts
                if h.status == "up"
            ]
            parsed_by_ip = {h.ip: h for h in hosts}
            from app.services.asset_integration import (
                ensure_noc_stubs_from_nmap_hosts,
                enrich_noc_from_parsed_hosts,
                sync_asset_registry_from_noc,
            )

            integration = {
                "noc_stubs_created": ensure_noc_stubs_from_nmap_hosts(
                    db, nmap_hosts, parsed_by_ip=parsed_by_ip,
                ),
                "noc_enriched": enrich_noc_from_parsed_hosts(db, hosts, run_id=run.id),
                "noc_linked": 0,
                "registry_synced": sync_asset_registry_from_noc(
                    db, ip_addresses=[h.ip for h in nmap_hosts],
                ),
            }

        finished = datetime.now(UTC)
        run.status = "completed"
        run.finished_at = finished
        run.duration_ms = int((finished - started).total_seconds() * 1000)
        run.hosts_up = stats["hosts_up"]
        run.hosts_total = stats["hosts_total"]
        run.ports_open = stats["ports_open"]
        run.nmap_summary = summary
        run.nmap_command = command
        run.raw_xml = raw_xml
        run.stats_json = {**stats, "integration": integration}

        if run.job_id:
            job = db.get(NetworkDiscoveryJob, run.job_id)
            if job:
                job.last_run_at = finished
                job.last_run_id = run.id
                job.updated_at = finished

        db.commit()
        logger.info("discovery_run_done id=%s hosts_up=%s", run_id, stats["hosts_up"])
    except (NmapScanError, ValueError) as exc:
        db.rollback()
        run = db.get(NetworkDiscoveryRun, run_id)
        if run:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            run.error_message = str(exc)
            run.duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
            db.commit()
        logger.warning("discovery_run_failed id=%s err=%s", run_id, exc)
    except Exception:
        db.rollback()
        run = db.get(NetworkDiscoveryRun, run_id)
        if run:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            run.error_message = "Error interno al ejecutar escaneo"
            db.commit()
        logger.exception("discovery_run_error id=%s", run_id)
    finally:
        db.close()


def enqueue_run(
    run_id: int,
    *,
    custom_args: str | None = None,
    auto_sync_ipam: bool = False,
    ipam_subnet_id: int | None = None,
    scan_cves: bool = False,
) -> None:
    thread = threading.Thread(
        target=execute_run,
        args=(run_id,),
        kwargs={
            "custom_args": custom_args,
            "auto_sync_ipam": auto_sync_ipam,
            "ipam_subnet_id": ipam_subnet_id,
            "scan_cves": scan_cves,
        },
        daemon=True,
    )
    thread.start()


def list_hosts(
    db: Session,
    run_id: int,
    *,
    limit: int = 100,
    offset: int = 0,
    documented_only: bool | None = None,
) -> tuple[list[NetworkDiscoveryHost], int]:
    q = (
        db.query(NetworkDiscoveryHost)
        .options(
            joinedload(NetworkDiscoveryHost.ports),
            joinedload(NetworkDiscoveryHost.vulnerabilities),
        )
        .filter(NetworkDiscoveryHost.run_id == run_id)
    )
    if documented_only is True:
        q = q.filter(NetworkDiscoveryHost.documented.is_(True))
    elif documented_only is False:
        q = q.filter(NetworkDiscoveryHost.documented.is_(False))
    total = q.count()
    rows = q.order_by(NetworkDiscoveryHost.ip_address).offset(offset).limit(limit).all()
    return rows, total


def update_host(db: Session, host: NetworkDiscoveryHost, data: dict, actor: str) -> NetworkDiscoveryHost:
    if "notes" in data:
        host.notes = data["notes"]
    if "tags" in data:
        host.tags = data["tags"]
    if "os_guess" in data:
        host.os_guess = data["os_guess"]
    if "documented" in data and data["documented"] is not None:
        host.documented = data["documented"]
        if data["documented"]:
            host.documented_at = datetime.now(UTC)
            host.documented_by = actor
            db.execute(
                text(
                    """
                    UPDATE noc_devices
                       SET inventory_ack = TRUE,
                           inventory_ack_at = NOW(),
                           inventory_ack_by = :actor,
                           inventory_ack_notes = COALESCE(inventory_ack_notes, 'Reconocido vía descubrimiento')
                     WHERE ip_address = :ip
                       AND inventory_ack IS FALSE
                    """,
                ),
                {"actor": actor, "ip": str(host.ip_address)},
            )
            db.execute(
                text(
                    """
                    UPDATE incidents_queue
                       SET status = 'suppressed', processed_at = NOW(),
                           error_message = 'Activo documentado en descubrimiento'
                     WHERE incident_type IN ('unknown_asset', 'undocumented_host')
                       AND status = 'pending'
                       AND node_id IN (
                         SELECT id FROM noc_devices WHERE ip_address = :ip
                       )
                    """,
                ),
                {"ip": str(host.ip_address)},
            )
        else:
            host.documented_at = None
            host.documented_by = None
    db.commit()
    db.refresh(host)
    return host


def get_stats(db: Session, run_id: int) -> dict[str, Any]:
    run = db.get(NetworkDiscoveryRun, run_id)
    if not run:
        raise ValueError("Run no encontrado")
    documented = (
        db.query(func.count(NetworkDiscoveryHost.id))
        .filter(NetworkDiscoveryHost.run_id == run_id, NetworkDiscoveryHost.documented.is_(True))
        .scalar()
        or 0
    )
    base = run.stats_json or {}
    return {
        "run_id": run_id,
        "hosts_up": run.hosts_up,
        "hosts_total": run.hosts_total,
        "ports_open": run.ports_open,
        "documented": documented,
        "cves_total": base.get("cves_total", 0),
        "hosts_with_cves": base.get("hosts_with_cves", 0),
        "by_cve": base.get("by_cve", []),
        "by_service": base.get("by_service", []),
        "by_port": base.get("by_port", []),
        "by_os": base.get("by_os", []),
        "by_status": base.get("by_status", {}),
    }


def list_vulnerabilities(
    db: Session,
    run_id: int,
    *,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[NetworkDiscoveryVulnerability], int]:
    q = (
        db.query(NetworkDiscoveryVulnerability)
        .join(NetworkDiscoveryHost, NetworkDiscoveryVulnerability.host_id == NetworkDiscoveryHost.id)
        .filter(NetworkDiscoveryHost.run_id == run_id)
    )
    total = q.count()
    rows = (
        q.order_by(NetworkDiscoveryVulnerability.cve_id, NetworkDiscoveryVulnerability.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


CRITICAL_PORTS = frozenset({21, 23, 135, 139, 161, 445, 3389, 5900, 6379, 27017})
SUMMARY_HOST_THRESHOLD = 80
TOPOLOGY_HOST_LIMIT = 2000


def _parse_targets_cidr(targets: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    raw = (targets or "").strip().split(",")[0].strip()
    if not raw:
        return None
    try:
        if "/" in raw:
            return ipaddress.ip_network(raw, strict=False)
        return ipaddress.ip_network(f"{raw}/24", strict=False)
    except ValueError:
        return None


def _host_subnet_key(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    default_net: ipaddress.IPv4Network | ipaddress.IPv6Network | None,
) -> str:
    if default_net and ip in default_net:
        return str(default_net)
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _noc_lookup(db: Session, ips: list[str]) -> dict[str, dict[str, Any]]:
    if not ips:
        return {}
    rows = db.execute(
        text(
            """
            SELECT d.id::text AS noc_device_id,
                   host(d.ip_address)::text AS ip,
                   d.status AS noc_status,
                   COALESCE(al.open_alerts, 0)::int AS noc_open_alerts
              FROM noc_devices d
              LEFT JOIN LATERAL (
                SELECT COUNT(*)::int AS open_alerts
                  FROM noc_alerts a
                 WHERE a.device_id = d.id AND a.status IN ('open', 'ack')
              ) al ON true
             WHERE d.ip_address IS NOT NULL
               AND host(d.ip_address)::text = ANY(:ips)
            """,
        ),
        {"ips": ips},
    ).mappings().all()
    return {str(r["ip"]): dict(r) for r in rows}


def _previous_run_id(db: Session, run: NetworkDiscoveryRun) -> int | None:
    if not run.job_id:
        return None
    prev = (
        db.query(NetworkDiscoveryRun.id)
        .filter(
            NetworkDiscoveryRun.job_id == run.job_id,
            NetworkDiscoveryRun.status == "completed",
            NetworkDiscoveryRun.id < run.id,
        )
        .order_by(NetworkDiscoveryRun.id.desc())
        .first()
    )
    return int(prev[0]) if prev else None


def _ips_from_run(db: Session, run_id: int) -> set[str]:
    rows = db.execute(
        text(
            """
            SELECT host(ip_address)::text AS ip
              FROM network_discovery_hosts
             WHERE run_id = :rid AND status = 'up'
            """,
        ),
        {"rid": run_id},
    ).mappings().all()
    return {str(r["ip"]) for r in rows}


def build_topology(
    db: Session,
    run_id: int,
    *,
    mode: str = "auto",
    compare: bool = True,
    compare_run_id: int | None = None,
) -> dict[str, Any]:
    run = (
        db.query(NetworkDiscoveryRun)
        .options(joinedload(NetworkDiscoveryRun.job))
        .filter(NetworkDiscoveryRun.id == run_id)
        .first()
    )
    if not run:
        raise ValueError("Run no encontrado")

    ipam_cidr: str | None = None
    region_name: str | None = None
    if run.job and run.job.ipam_subnet_id:
        row = db.execute(
            text(
                """
                SELECT s.cidr_block::text AS cidr, r.name AS region_name
                  FROM ipam_subnets s
                  LEFT JOIN ipam_regions r ON r.id = s.region_id
                 WHERE s.id = :sid AND s.deleted_at IS NULL
                """,
            ),
            {"sid": run.job.ipam_subnet_id},
        ).mappings().first()
        if row:
            ipam_cidr = row["cidr"]
            region_name = row["region_name"]

    default_net = _parse_targets_cidr(ipam_cidr or run.targets)

    hosts, total = list_hosts(db, run_id, limit=TOPOLOGY_HOST_LIMIT, offset=0)
    up_hosts = [h for h in hosts if h.status == "up"]

    effective_mode = mode
    if mode == "auto":
        effective_mode = "summary" if len(up_hosts) > SUMMARY_HOST_THRESHOLD else "detail"

    cmp_id: int | None = None
    prev_ips: set[str] = set()
    if compare:
        cmp_id = compare_run_id if compare_run_id is not None else _previous_run_id(db, run)
        if cmp_id:
            prev_ips = _ips_from_run(db, cmp_id)

    subnets: dict[str, list[NetworkDiscoveryHost]] = {}
    for h in up_hosts:
        ip = ipaddress.ip_address(str(h.ip_address))
        key = _host_subnet_key(ip, default_net)
        subnets.setdefault(key, []).append(h)

    ips = [str(h.ip_address) for h in up_hosts]
    noc_map = _noc_lookup(db, ips)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    clusters: list[dict[str, Any]] = []
    subnet_keys = sorted(subnets.keys())

    if effective_mode == "summary":
        for si, subnet in enumerate(subnet_keys):
            group = subnets[subnet]
            gx = (si % 4) * 320 + 160
            gy = (si // 4) * 260 + 140
            port_total = sum(len([p for p in h.ports if p.state == "open"]) for h in group)
            doc = sum(1 for h in group if h.documented)
            node_id = f"subnet-{subnet}"
            nodes.append(
                {
                    "id": node_id,
                    "label": subnet,
                    "ip": subnet,
                    "hostname": f"{len(group)} hosts",
                    "status": "up",
                    "port_count": port_total,
                    "documented": doc == len(group),
                    "subnet": subnet,
                    "x": gx,
                    "y": gy,
                    "node_type": "subnet",
                    "gateway_inferred": None,
                    "host_id": None,
                    "mac_address": None,
                    "os_guess": None,
                    "open_ports": [],
                    "has_critical_ports": False,
                    "noc_device_id": None,
                    "noc_status": None,
                    "noc_open_alerts": 0,
                    "delta": None,
                    "region_name": region_name,
                },
            )
            clusters.append(
                {
                    "id": f"cluster-{subnet}",
                    "subnet": subnet,
                    "label": subnet,
                    "host_count": len(group),
                    "documented": doc,
                    "ports_open": port_total,
                    "x": gx - 100,
                    "y": gy - 70,
                    "width": 200,
                    "height": 140,
                },
            )
        return {
            "run_id": run_id,
            "compare_run_id": cmp_id,
            "mode": effective_mode,
            "nodes": nodes,
            "edges": edges,
            "subnets": subnet_keys,
            "clusters": clusters,
            "meta": {
                "total_hosts": total,
                "shown_hosts": len(up_hosts),
                "ipam_cidr": ipam_cidr,
                "region_name": region_name,
            },
        }

    mac_groups: dict[str, list[str]] = {}
    for si, subnet in enumerate(subnet_keys):
        group_hosts = subnets[subnet]
        gx = (si % 4) * 300 + 120
        gy = (si // 4) * 280 + 120
        min_x, max_x = gx - 110, gx + 110
        min_y, max_y = gy - 60, gy + 100

        net_obj = ipaddress.ip_network(subnet, strict=False)
        gw_ip = str(net_obj.network_address + 1)
        gw_host = next((h for h in group_hosts if str(h.ip_address) == gw_ip), None)
        gateway_id = f"gw-{subnet}"
        gw_inferred = gw_host is None

        if gw_host:
            gw_ports = [p.port for p in gw_host.ports if p.state == "open"]
            gw_noc = noc_map.get(gw_ip, {})
            nodes.append(
                {
                    "id": gateway_id,
                    "label": gw_host.hostname or "gateway",
                    "ip": gw_ip,
                    "hostname": gw_host.hostname,
                    "status": "up",
                    "port_count": len(gw_ports),
                    "documented": gw_host.documented,
                    "subnet": subnet,
                    "x": gx,
                    "y": gy - 55,
                    "node_type": "gateway",
                    "gateway_inferred": False,
                    "host_id": gw_host.id,
                    "mac_address": str(gw_host.mac_address) if gw_host.mac_address else None,
                    "os_guess": gw_host.os_guess,
                    "open_ports": gw_ports[:20],
                    "has_critical_ports": bool(set(gw_ports) & CRITICAL_PORTS),
                    "noc_device_id": gw_noc.get("noc_device_id"),
                    "noc_status": gw_noc.get("noc_status"),
                    "noc_open_alerts": gw_noc.get("noc_open_alerts", 0),
                    "delta": _delta_for_ip(gw_ip, prev_ips),
                    "region_name": region_name,
                },
            )
        else:
            nodes.append(
                {
                    "id": gateway_id,
                    "label": f"GW {subnet}",
                    "ip": gw_ip,
                    "hostname": "gateway (inferido)",
                    "status": "unknown",
                    "port_count": 0,
                    "documented": True,
                    "subnet": subnet,
                    "x": gx,
                    "y": gy - 55,
                    "node_type": "gateway",
                    "gateway_inferred": True,
                    "host_id": None,
                    "mac_address": None,
                    "os_guess": None,
                    "open_ports": [],
                    "has_critical_ports": False,
                    "noc_device_id": noc_map.get(gw_ip, {}).get("noc_device_id"),
                    "noc_status": noc_map.get(gw_ip, {}).get("noc_status"),
                    "noc_open_alerts": noc_map.get(gw_ip, {}).get("noc_open_alerts", 0),
                    "delta": None,
                    "region_name": region_name,
                },
            )

        host_nodes = [h for h in group_hosts if not gw_host or h.id != gw_host.id]
        for hi, h in enumerate(host_nodes):
            node_id = f"host-{h.id}"
            ip_str = str(h.ip_address)
            open_ports = [p.port for p in h.ports if p.state == "open"]
            px = gx + (hi % 8) * 38 - 133
            py = gy + (hi // 8) * 38
            min_x, max_x = min(min_x, px - 12), max(max_x, px + 12)
            min_y, max_y = min(min_y, py - 12), max(max_y, py + 12)
            noc = noc_map.get(ip_str, {})
            mac_s = str(h.mac_address) if h.mac_address else None
            if mac_s:
                mac_key = mac_s.lower().replace(":", "")
                mac_groups.setdefault(mac_key, []).append(node_id)

            nodes.append(
                {
                    "id": node_id,
                    "label": h.hostname or ip_str,
                    "ip": ip_str,
                    "hostname": h.hostname,
                    "status": h.status,
                    "port_count": len(open_ports),
                    "documented": h.documented,
                    "subnet": subnet,
                    "x": px,
                    "y": py,
                    "node_type": "host",
                    "gateway_inferred": None,
                    "host_id": h.id,
                    "mac_address": mac_s,
                    "os_guess": h.os_guess,
                    "open_ports": open_ports[:30],
                    "has_critical_ports": bool(set(open_ports) & CRITICAL_PORTS),
                    "noc_device_id": noc.get("noc_device_id"),
                    "noc_status": noc.get("noc_status"),
                    "noc_open_alerts": noc.get("noc_open_alerts", 0),
                    "delta": _delta_for_ip(ip_str, prev_ips),
                    "region_name": region_name,
                },
            )
            edges.append(
                {
                    "source": gateway_id,
                    "target": node_id,
                    "label": subnet,
                    "edge_type": "inferred_gateway" if gw_inferred else "gateway",
                },
            )

        clusters.append(
            {
                "id": f"cluster-{subnet}",
                "subnet": subnet,
                "label": subnet,
                "host_count": len(group_hosts),
                "documented": sum(1 for h in group_hosts if h.documented),
                "ports_open": sum(len([p for p in h.ports if p.state == "open"]) for h in group_hosts),
                "x": min_x - 16,
                "y": min_y - 36,
                "width": max_x - min_x + 32,
                "height": max_y - min_y + 48,
            },
        )

    if cmp_id and prev_ips:
        current_ips = {str(h.ip_address) for h in up_hosts}
        removed = prev_ips - current_ips
        for ri, ip_str in enumerate(sorted(removed)[:40]):
            node_id = f"removed-{ip_str}"
            nodes.append(
                {
                    "id": node_id,
                    "label": ip_str,
                    "ip": ip_str,
                    "hostname": "desaparecido",
                    "status": "removed",
                    "port_count": 0,
                    "documented": False,
                    "subnet": _host_subnet_key(ipaddress.ip_address(ip_str), default_net),
                    "x": 40 + (ri % 6) * 50,
                    "y": 40 + (ri // 6) * 50,
                    "node_type": "host",
                    "gateway_inferred": None,
                    "host_id": None,
                    "mac_address": None,
                    "os_guess": None,
                    "open_ports": [],
                    "has_critical_ports": False,
                    "noc_device_id": None,
                    "noc_status": None,
                    "noc_open_alerts": 0,
                    "delta": "removed",
                    "region_name": region_name,
                },
            )

    for _mac, node_ids in mac_groups.items():
        if len(node_ids) < 2:
            continue
        for i in range(1, len(node_ids)):
            edges.append(
                {
                    "source": node_ids[0],
                    "target": node_ids[i],
                    "label": "misma MAC",
                    "edge_type": "same_mac",
                },
            )

    return {
        "run_id": run_id,
        "compare_run_id": cmp_id,
        "mode": effective_mode,
        "nodes": nodes,
        "edges": edges,
        "subnets": subnet_keys,
        "clusters": clusters,
        "meta": {
            "total_hosts": total,
            "shown_hosts": len(up_hosts),
            "ipam_cidr": ipam_cidr,
            "region_name": region_name,
            "critical_ports": sorted(CRITICAL_PORTS),
        },
    }


def _delta_for_ip(ip: str, prev_ips: set[str]) -> str | None:
    if not prev_ips:
        return None
    return "new" if ip not in prev_ips else "unchanged"


def export_run_json(db: Session, run_id: int) -> dict:
    run = db.get(NetworkDiscoveryRun, run_id)
    if not run:
        raise ValueError("Run no encontrado")
    hosts, _ = list_hosts(db, run_id, limit=5000, offset=0)
    return {
        "run": {
            "id": run.id,
            "targets": run.targets,
            "scan_profile": run.scan_profile,
            "status": run.status,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "hosts_up": run.hosts_up,
            "ports_open": run.ports_open,
            "nmap_summary": run.nmap_summary,
        },
        "hosts": [
            {
                "ip": str(h.ip_address),
                "hostname": h.hostname,
                "mac": str(h.mac_address) if h.mac_address else None,
                "status": h.status,
                "os_guess": h.os_guess,
                "notes": h.notes,
                "documented": h.documented,
                "tags": h.tags,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                    }
                    for p in h.ports
                ],
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "severity": v.severity,
                        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                        "title": v.title,
                        "port": v.port,
                        "protocol": v.protocol,
                        "script_id": v.script_id,
                    }
                    for v in h.vulnerabilities
                ],
            }
            for h in hosts
        ],
    }


def export_run_csv(db: Session, run_id: int) -> str:
    data = export_run_json(db, run_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "ip", "hostname", "mac", "status", "os_guess", "port", "protocol", "service",
        "product", "version", "documented", "notes", "cve_id", "severity", "cvss",
    ])
    for h in data["hosts"]:
        vulns = h.get("vulnerabilities") or []
        if not h["ports"] and not vulns:
            writer.writerow([
                h["ip"], h["hostname"], h["mac"], h["status"], h["os_guess"],
                "", "", "", "", "", h["documented"], h["notes"], "", "", "",
            ])
        elif not h["ports"]:
            for v in vulns:
                writer.writerow([
                    h["ip"], h["hostname"], h["mac"], h["status"], h["os_guess"],
                    v.get("port") or "", v.get("protocol") or "", "", "", "",
                    h["documented"], h["notes"], v.get("cve_id"), v.get("severity"), v.get("cvss_score"),
                ])
        else:
            for p in h["ports"]:
                port_vulns = [v for v in vulns if v.get("port") == p["port"]] or [None]
                for v in port_vulns:
                    writer.writerow([
                        h["ip"], h["hostname"], h["mac"], h["status"], h["os_guess"],
                        p["port"], p["protocol"], p["service"], p["product"], p["version"],
                        h["documented"], h["notes"],
                        v.get("cve_id") if v else "",
                        v.get("severity") if v else "",
                        v.get("cvss_score") if v else "",
                    ])
    return buf.getvalue()
