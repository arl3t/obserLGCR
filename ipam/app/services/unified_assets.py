"""Vista unificada de activos: NOC + IPAM + último descubrimiento + asset_registry."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

_LATEST_DISCOVERY = """
            latest_discovery AS (
              SELECT DISTINCT ON (h.ip_address)
                h.ip_address, h.os_guess, h.documented,
                (SELECT COUNT(*)::int FROM network_discovery_ports p
                 WHERE p.host_id = h.id AND p.state = 'open') AS open_ports
              FROM network_discovery_hosts h
              ORDER BY h.ip_address, h.run_id DESC
            )
"""

_UNIFIED_BODY = """
            noc_rows AS (
              SELECT
                d.id::text AS unified_id,
                d.id::text AS noc_device_id,
                a.id AS ipam_address_id,
                COALESCE(d.hostname, a.hostname) AS hostname,
                COALESCE(d.ip_address, a.ip_address)::text AS ip_address,
                COALESCE(d.mac_address, a.mac_address::text) AS mac_address,
                d.device_type,
                d.site,
                d.status AS noc_status,
                a.status::text AS ipam_status,
                r.name AS region_name,
                s.cidr_block,
                ld.os_guess,
                ld.documented AS discovery_documented,
                COALESCE(ld.open_ports, 0) AS discovery_open_ports,
                d.discovery_meta,
                d.inventory_ack,
                d.inventory_ack_at::text AS inventory_ack_at,
                d.discovered_via,
                ar.criticality,
                ar.asset_type AS registry_type,
                ar.sensor_key AS registry_sensor_key,
                (a.noc_device_id IS NOT NULL) AS ipam_linked,
                d.last_seen_at::text AS last_seen_at
              FROM noc_devices d
              LEFT JOIN ipam_addresses a
                ON a.noc_device_id = d.id
                OR (a.noc_device_id IS NULL AND d.ip_address IS NOT NULL AND a.ip_address = d.ip_address)
              LEFT JOIN ipam_subnets s ON s.id = a.subnet_id AND s.deleted_at IS NULL
              LEFT JOIN ipam_regions r ON r.id = s.region_id
              LEFT JOIN latest_discovery ld ON ld.ip_address = COALESCE(d.ip_address, a.ip_address)
              LEFT JOIN asset_registry ar
                ON ar.is_active = true
               AND (
                 (d.ip_address IS NOT NULL AND ar.ip_address = d.ip_address)
                 OR lower(ar.sensor_key) = lower(d.hostname)
               )
            ),
            ipam_only AS (
              SELECT
                'ipam-' || a.id::text AS unified_id,
                NULL::text AS noc_device_id,
                a.id AS ipam_address_id,
                a.hostname,
                a.ip_address::text AS ip_address,
                a.mac_address::text AS mac_address,
                NULL::varchar AS device_type,
                NULL::varchar AS site,
                NULL::varchar AS noc_status,
                a.status::text AS ipam_status,
                r.name AS region_name,
                s.cidr_block,
                ld.os_guess,
                ld.documented AS discovery_documented,
                COALESCE(ld.open_ports, 0) AS discovery_open_ports,
                NULL::jsonb AS discovery_meta,
                NULL::boolean AS inventory_ack,
                NULL::text AS inventory_ack_at,
                NULL::varchar AS discovered_via,
                ar.criticality,
                ar.asset_type AS registry_type,
                ar.sensor_key AS registry_sensor_key,
                false AS ipam_linked,
                NULL::text AS last_seen_at
              FROM ipam_addresses a
              LEFT JOIN ipam_subnets s ON s.id = a.subnet_id AND s.deleted_at IS NULL
              LEFT JOIN ipam_regions r ON r.id = s.region_id
              LEFT JOIN latest_discovery ld ON ld.ip_address = a.ip_address
              LEFT JOIN asset_registry ar ON ar.is_active = true AND ar.ip_address = a.ip_address
              WHERE a.noc_device_id IS NULL
                AND NOT EXISTS (
                  SELECT 1 FROM noc_devices d WHERE d.ip_address = a.ip_address
                )
            ),
            unified AS (
              SELECT * FROM noc_rows
              UNION ALL
              SELECT * FROM ipam_only
            )
"""

_SEARCH_FILTER = """
              AND (
                lower(COALESCE(u.hostname, '')) LIKE :q
                OR lower(COALESCE(u.ip_address, '')) LIKE :q
                OR lower(COALESCE(u.mac_address, '')) LIKE :q
              )
            """


def list_unified_assets(
    db: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    search: str | None = None,
    linked_only: bool = False,
) -> tuple[list[dict], int]:
    params: dict = {"limit": limit, "offset": offset}
    if search and search.strip():
        params["q"] = f"%{search.strip().lower()}%"

    search_sql = _SEARCH_FILTER if search and search.strip() else ""
    linked_sql = " AND u.ipam_linked = true" if linked_only else ""

    cte = f"WITH {_LATEST_DISCOVERY.strip()}, {_UNIFIED_BODY.strip()}"

    total = db.execute(
        text(
            cte
            + """
            SELECT COUNT(*) FROM unified u
            WHERE 1=1
            """
            + search_sql
            + linked_sql,
        ),
        params,
    ).scalar() or 0

    rows = db.execute(
        text(
            cte
            + """
            SELECT * FROM unified u
            WHERE 1=1
            """
            + search_sql
            + linked_sql
            + """
            ORDER BY u.ip_address NULLS LAST, u.hostname NULLS LAST
            LIMIT :limit OFFSET :offset
            """,
        ),
        params,
    ).mappings().all()

    return [dict(r) for r in rows], int(total)
