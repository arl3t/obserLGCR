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

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.database import SessionLocal
from app.models.discovery import (
    NetworkDiscoveryHost,
    NetworkDiscoveryJob,
    NetworkDiscoveryPort,
    NetworkDiscoveryRun,
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
) -> NetworkDiscoveryRun:
    run = NetworkDiscoveryRun(
        job_id=job_id,
        name=name,
        targets=targets,
        scan_profile=scan_profile,
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
    open_ports = 0
    for h in up:
        if h.os_guess:
            oses[h.os_guess] += 1
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


def execute_run(run_id: int, *, custom_args: str | None = None, auto_sync_ipam: bool = False, ipam_subnet_id: int | None = None) -> None:
    db = SessionLocal()
    started = datetime.now(UTC)
    try:
        run = db.get(NetworkDiscoveryRun, run_id)
        if not run:
            return
        run.status = "running"
        run.started_at = started
        db.commit()

        hosts, summary, command, raw_xml = run_network_scan(
            run.targets,
            run.scan_profile,
            custom_args=custom_args,
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
) -> None:
    thread = threading.Thread(
        target=execute_run,
        args=(run_id,),
        kwargs={
            "custom_args": custom_args,
            "auto_sync_ipam": auto_sync_ipam,
            "ipam_subnet_id": ipam_subnet_id,
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
        .options(joinedload(NetworkDiscoveryHost.ports))
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
        "by_service": base.get("by_service", []),
        "by_port": base.get("by_port", []),
        "by_os": base.get("by_os", []),
        "by_status": base.get("by_status", {}),
    }


def build_topology(db: Session, run_id: int) -> dict[str, Any]:
    hosts, _ = list_hosts(db, run_id, limit=500, offset=0)
    subnets: dict[str, list[NetworkDiscoveryHost]] = {}
    for h in hosts:
        if h.status != "up":
            continue
        ip = ipaddress.ip_address(str(h.ip_address))
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        key = str(net)
        subnets.setdefault(key, []).append(h)

    nodes: list[dict] = []
    edges: list[dict] = []
    subnet_keys = sorted(subnets.keys())
    for si, subnet in enumerate(subnet_keys):
        group_hosts = subnets[subnet]
        gx = (si % 4) * 280 + 80
        gy = (si // 4) * 220 + 80
        gateway_id = f"gw-{subnet}"
        nodes.append(
            {
                "id": gateway_id,
                "label": f"GW {subnet}",
                "ip": subnet.replace("/24", ".1"),
                "hostname": "gateway",
                "status": "up",
                "port_count": 0,
                "documented": True,
                "subnet": subnet,
                "x": gx,
                "y": gy - 50,
            },
        )
        for hi, h in enumerate(group_hosts):
            node_id = f"host-{h.id}"
            px = gx + (hi % 6) * 42 - 105
            py = gy + (hi // 6) * 42
            port_count = len([p for p in h.ports if p.state == "open"])
            nodes.append(
                {
                    "id": node_id,
                    "label": h.hostname or str(h.ip_address),
                    "ip": str(h.ip_address),
                    "hostname": h.hostname,
                    "status": h.status,
                    "port_count": port_count,
                    "documented": h.documented,
                    "subnet": subnet,
                    "x": px,
                    "y": py,
                },
            )
            edges.append({"source": gateway_id, "target": node_id, "label": subnet})

    return {"run_id": run_id, "nodes": nodes, "edges": edges, "subnets": subnet_keys}


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
            }
            for h in hosts
        ],
    }


def export_run_csv(db: Session, run_id: int) -> str:
    data = export_run_json(db, run_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "hostname", "mac", "status", "os_guess", "port", "protocol", "service", "product", "version", "documented", "notes"])
    for h in data["hosts"]:
        if not h["ports"]:
            writer.writerow([h["ip"], h["hostname"], h["mac"], h["status"], h["os_guess"], "", "", "", "", "", h["documented"], h["notes"]])
        else:
            for p in h["ports"]:
                writer.writerow([
                    h["ip"], h["hostname"], h["mac"], h["status"], h["os_guess"],
                    p["port"], p["protocol"], p["service"], p["product"], p["version"],
                    h["documented"], h["notes"],
                ])
    return buf.getvalue()
