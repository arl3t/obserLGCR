"""Sincroniza resultados nmap con ipam_addresses."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.ipam import IPAMAddress, IPAMAddressStatus, IPAMSubnet
from app.services.nmap_discovery import NmapHost
from app.services.rfc1918 import host_capacity, parse_cidr


MAX_SCAN_HOSTS = 512


def assert_scan_size(cidr: str) -> int:
    network = parse_cidr(cidr)
    capacity = host_capacity(network)
    if capacity > MAX_SCAN_HOSTS:
        raise ValueError(
            f"Subred demasiado grande ({capacity} hosts). Máximo {MAX_SCAN_HOSTS} por escaneo nmap.",
        )
    return capacity


def sync_nmap_discovery(
    db: Session,
    subnet: IPAMSubnet,
    hosts: list[NmapHost],
    *,
    mark_offline: bool = True,
    preserve_reserved: bool = True,
) -> dict[str, int]:
    now = datetime.now(UTC)
    seen_ips = {h.ip for h in hosts}

    existing_rows = db.query(IPAMAddress).filter(IPAMAddress.subnet_id == subnet.id).all()
    by_ip = {str(row.ip_address): row for row in existing_rows}

    created = 0
    updated = 0
    marked_offline = 0

    for host in hosts:
        row = by_ip.get(host.ip)
        if row is None:
            row = IPAMAddress(
                subnet_id=subnet.id,
                ip_address=host.ip,
                status=IPAMAddressStatus.ONLINE,
                hostname=host.hostname,
                mac_address=host.mac,
                last_seen=now,
                is_discovered_by_nmap=True,
                description="Descubierto vía nmap",
            )
            db.add(row)
            by_ip[host.ip] = row
            created += 1
            continue

        if preserve_reserved and row.status == IPAMAddressStatus.RESERVED:
            row.last_seen = now
            continue

        row.status = IPAMAddressStatus.ONLINE
        row.is_discovered_by_nmap = True
        row.last_seen = now
        if host.hostname:
            row.hostname = host.hostname
        if host.mac:
            row.mac_address = host.mac
        if not row.description:
            row.description = "Descubierto vía nmap"
        updated += 1

    if mark_offline:
        for ip, row in by_ip.items():
            if ip in seen_ips:
                continue
            if not row.is_discovered_by_nmap:
                continue
            if preserve_reserved and row.status == IPAMAddressStatus.RESERVED:
                continue
            if row.status in (IPAMAddressStatus.ONLINE, IPAMAddressStatus.DHCP):
                row.status = IPAMAddressStatus.OFFLINE
                row.last_seen = now
                marked_offline += 1

    db.commit()
    return {
        "created": created,
        "updated": updated,
        "marked_offline": marked_offline,
    }
