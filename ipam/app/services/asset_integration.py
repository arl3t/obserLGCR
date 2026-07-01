"""
Integración post-descubrimiento: NOC stubs, enriquecimiento, link IPAM↔NOC (IP+MAC), asset_registry.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.services.nmap_discovery import NmapHost
from app.services.nmap_scan_engine import ParsedHost, ParsedPort
from app.services.noc_link import auto_link_subnet

logger = logging.getLogger("ipam.asset_integration")

_NETWORK_DEVICE_TYPES = frozenset({"router", "switch", "firewall", "network", "gateway"})


def _normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = mac.strip().lower().replace("-", ":")
    if cleaned in {"", "unknown", "(unknown)"}:
        return None
    return cleaned


def _stub_hostname(host: NmapHost) -> str:
    if host.hostname and host.hostname.strip():
        base = host.hostname.strip()[:200]
    else:
        base = f"discovered-{host.ip.replace('.', '-')}"
    return base


def _infer_device_type(host: NmapHost, parsed: ParsedHost | None = None) -> str:
    if parsed and parsed.ports:
        services = {((p.service or "").lower()) for p in parsed.ports if p.state == "open"}
        if services & {"http", "https", "ssh", "microsoft-ds", "ms-wbt-server"}:
            return "server"
        if services & {"snmp", "telnet"} and len(services) <= 3:
            return "router"
    return "server"


def _port_dict(p: ParsedPort) -> dict[str, Any]:
    return {
        "port": p.port,
        "protocol": p.protocol,
        "service": p.service,
        "product": p.product,
        "version": p.version,
    }


def ensure_noc_stubs_from_nmap_hosts(
    db: Session,
    hosts: list[NmapHost],
    *,
    parsed_by_ip: dict[str, ParsedHost] | None = None,
) -> int:
    """Crea noc_devices mínimos para hosts descubiertos que aún no existen."""
    created = 0
    parsed_by_ip = parsed_by_ip or {}
    new_device_ids: list[str] = []

    for host in hosts:
        parsed = parsed_by_ip.get(host.ip)
        hostname = _stub_hostname(host)
        mac = _normalize_mac(host.mac)
        device_type = _infer_device_type(host, parsed)

        exists = db.execute(
            text(
                """
                SELECT 1 FROM noc_devices
                 WHERE ip_address = CAST(:ip AS inet)
                    OR lower(hostname) = lower(:hostname)
                 LIMIT 1
                """,
            ),
            {"ip": host.ip, "hostname": hostname},
        ).first()
        if exists:
            continue

        for attempt, hn in enumerate((hostname, f"{hostname}-{host.ip.split('.')[-1]}")):
            try:
                row = db.execute(
                    text(
                        """
                        INSERT INTO noc_devices
                          (hostname, ip_address, mac_address, device_type, description, status, discovered_via, inventory_ack)
                        VALUES
                          (:hostname, CAST(:ip AS inet), :mac, :device_type,
                           'Auto-descubierto vía nmap', 'unknown', 'nmap', FALSE)
                        RETURNING id::text
                        """,
                    ),
                    {
                        "hostname": hn[:255],
                        "ip": host.ip,
                        "mac": mac,
                        "device_type": device_type,
                    },
                ).first()
                if row:
                    new_device_ids.append(row[0])
                created += 1
                break
            except IntegrityError:
                db.rollback()
                if attempt == 1:
                    logger.warning("noc_stub_skip ip=%s hostname=%s", host.ip, hostname)
                continue

    if created:
        db.commit()
        enqueue_unknown_asset_incidents(db, device_ids=new_device_ids, source="nmap")
    return created


def enqueue_unknown_asset_incidents(
    db: Session,
    *,
    device_ids: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    source: str = "nmap",
) -> int:
    """Encola incidentes de activo desconocido para dispositivos NOC sin ACK."""
    if device_ids:
        rows = db.execute(
            text(
                """
                SELECT id::text, hostname, ip_address::text AS ip
                  FROM noc_devices
                 WHERE id = ANY(CAST(:ids AS uuid[]))
                   AND inventory_ack IS FALSE
                """,
            ),
            {"ids": device_ids},
        ).fetchall()
    elif ip_addresses:
        rows = db.execute(
            text(
                """
                SELECT id::text, hostname, ip_address::text AS ip
                  FROM noc_devices
                 WHERE ip_address = ANY(CAST(:ips AS inet[]))
                   AND inventory_ack IS FALSE
                """,
            ),
            {"ips": ip_addresses},
        ).fetchall()
    else:
        return 0

    enqueued = 0
    for row in rows:
        dedup = hashlib.sha256(f"{row[0]}|unknown_asset".encode()).hexdigest()
        payload = json.dumps(
            {
                "noc_device_id": row[0],
                "ip_address": row[2],
                "hostname": row[1],
                "discovered_via": source,
                "policy": "inventory_ack_required",
            },
        )
        ins = db.execute(
            text(
                """
                INSERT INTO incidents_queue (
                  incident_type, severity, node_id, hostname, dedup_key, payload, status
                ) VALUES (
                  'unknown_asset', 'HIGH', CAST(:id AS uuid), :hostname, :dedup,
                  CAST(:payload AS jsonb), 'pending'
                )
                ON CONFLICT (dedup_key) WHERE (status = 'pending') DO NOTHING
                RETURNING id
                """,
            ),
            {"id": row[0], "hostname": row[1], "dedup": dedup, "payload": payload},
        ).first()
        if ins:
            enqueued += 1

    if enqueued:
        db.commit()
        logger.info("unknown_asset_enqueued count=%s source=%s", enqueued, source)
    return enqueued


def enrich_noc_from_parsed_hosts(
    db: Session,
    hosts: list[ParsedHost],
    *,
    run_id: int | None = None,
) -> int:
    """Actualiza discovery_meta en noc_devices con puertos/OS del escaneo."""
    updated = 0
    now = datetime.now(UTC).isoformat()

    for host in hosts:
        if host.status != "up":
            continue
        open_ports = [_port_dict(p) for p in host.ports if p.state in ("open", "open|filtered")]
        meta = {
            "source": "nmap",
            "updated_at": now,
            "os_guess": host.os_guess,
            "open_ports": open_ports[:64],
            "open_port_count": len(open_ports),
        }
        if run_id is not None:
            meta["last_run_id"] = run_id

        mac = _normalize_mac(host.mac)
        result = db.execute(
            text(
                """
                UPDATE noc_devices d
                   SET discovery_meta = COALESCE(d.discovery_meta, '{}'::jsonb) || CAST(:meta AS jsonb),
                       mac_address = COALESCE(d.mac_address, :mac),
                       description = CASE
                         WHEN d.description IS NULL OR d.description = '' THEN 'Enriquecido vía nmap'
                         ELSE d.description
                       END,
                       updated_at = NOW()
                 WHERE d.ip_address = CAST(:ip AS inet)
                    OR (
                      :mac IS NOT NULL AND d.mac_address IS NOT NULL
                      AND lower(replace(d.mac_address, ':', '')) = lower(replace(:mac, ':', ''))
                    )
                    OR (
                      :hostname IS NOT NULL AND lower(d.hostname) = lower(:hostname)
                    )
                """,
            ),
            {
                "meta": json.dumps(meta),
                "ip": host.ip,
                "mac": mac,
                "hostname": host.hostname,
            },
        )
        updated += result.rowcount or 0

    if updated:
        db.commit()
    return updated


def enrich_noc_from_nmap_hosts(db: Session, hosts: list[NmapHost], *, run_id: int | None = None) -> int:
    parsed = [
        ParsedHost(
            ip=h.ip,
            status="up",
            hostname=h.hostname,
            mac=h.mac,
            ports=[],
        )
        for h in hosts
    ]
    return enrich_noc_from_parsed_hosts(db, parsed, run_id=run_id)


def sync_asset_registry_from_noc(db: Session, *, ip_addresses: list[str] | None = None) -> int:
    """
    Upsert asset_registry desde noc_devices (criticidad por device_type/site).
    """
    ip_filter = ""
    params: dict[str, Any] = {}
    if ip_addresses:
        ip_filter = "AND d.ip_address = ANY(CAST(:ips AS inet[]))"
        params["ips"] = ip_addresses

    result = db.execute(
        text(
            f"""
            INSERT INTO asset_registry (
              sensor_key, hostname, ip_address, asset_type, criticality,
              location, os_platform, description, updated_by
            )
            SELECT
              COALESCE(NULLIF(trim(d.hostname), ''), host(d.ip_address)::text) AS sensor_key,
              d.hostname,
              d.ip_address,
              CASE
                WHEN lower(d.device_type) IN ('router','switch','firewall','network','gateway')
                  THEN 'network-device'
                WHEN lower(d.device_type) IN ('printer') THEN 'printer'
                WHEN lower(d.device_type) IN ('iot','sensor') THEN 'iot'
                ELSE 'server'
              END AS asset_type,
              CASE
                WHEN lower(d.device_type) IN ('router','switch','firewall','network','gateway') THEN 'tier1'
                WHEN lower(d.device_type) = 'server' THEN 'tier2'
                WHEN d.site ILIKE '%dc%' OR d.site ILIKE '%datacenter%' THEN 'tier1'
                ELSE 'tier3'
              END AS criticality,
              d.site,
              NULLIF(d.discovery_meta->>'os_guess', ''),
              COALESCE(NULLIF(trim(d.description), ''), 'Sincronizado desde NOC/IPAM'),
              'asset-integration'
            FROM noc_devices d
            WHERE d.ip_address IS NOT NULL
              {ip_filter}
            ON CONFLICT (sensor_key) DO UPDATE SET
              hostname = EXCLUDED.hostname,
              ip_address = EXCLUDED.ip_address,
              asset_type = EXCLUDED.asset_type,
              criticality = EXCLUDED.criticality,
              location = COALESCE(EXCLUDED.location, asset_registry.location),
              os_platform = COALESCE(EXCLUDED.os_platform, asset_registry.os_platform),
              description = CASE
                WHEN asset_registry.description LIKE 'Sincronizado%' THEN EXCLUDED.description
                ELSE asset_registry.description
              END,
              is_active = true,
              updated_at = NOW(),
              updated_by = 'asset-integration'
            """,
        ),
        params,
    )
    db.commit()
    return result.rowcount or 0


def post_subnet_nmap_pipeline(
    db: Session,
    subnet_id: int,
    hosts: list[NmapHost],
    *,
    run_id: int | None = None,
    parsed_hosts: list[ParsedHost] | None = None,
) -> dict[str, int]:
    """
    Pipeline unificado tras nmap en subred IPAM:
    stubs NOC → enriquecer → link IPAM↔NOC (IP+MAC) → asset_registry.
    """
    parsed_by_ip = {h.ip: h for h in (parsed_hosts or [])}
    stubs = ensure_noc_stubs_from_nmap_hosts(db, hosts, parsed_by_ip=parsed_by_ip)

    if parsed_hosts:
        enriched = enrich_noc_from_parsed_hosts(db, parsed_hosts, run_id=run_id)
    else:
        enriched = enrich_noc_from_nmap_hosts(db, hosts, run_id=run_id)

    linked = auto_link_subnet(db, subnet_id)
    ips = [h.ip for h in hosts]
    registry = sync_asset_registry_from_noc(db, ip_addresses=ips) if ips else 0
    incidents = enqueue_unknown_asset_incidents(db, ip_addresses=ips, source="nmap") if ips else 0

    return {
        "noc_stubs_created": stubs,
        "noc_enriched": enriched,
        "noc_linked": linked,
        "registry_synced": registry,
        "unknown_asset_incidents": incidents,
    }


def post_discovery_ipam_pipeline(
    db: Session,
    subnet_id: int,
    hosts: list[ParsedHost],
    *,
    run_id: int,
) -> dict[str, int]:
    """Tras discovery→IPAM: mismo pipeline que subnet nmap."""
    nmap_hosts = [
        NmapHost(ip=h.ip, hostname=h.hostname, mac=h.mac)
        for h in hosts
        if h.status == "up"
    ]
    return post_subnet_nmap_pipeline(
        db,
        subnet_id,
        nmap_hosts,
        run_id=run_id,
        parsed_hosts=hosts,
    )
