from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.ipam import IPAMAddress, IPAMAddressStatus, IPAMRegion, IPAMSubnet
from app.services.address_serial import to_address_response
from app.services.audit import audit_log
from app.services.rfc1918 import ip_in_network, iter_ips_in_range, parse_ip


def export_inventory(db: Session, *, region_id: int | None = None) -> list[dict[str, Any]]:
    q = (
        db.query(IPAMAddress, IPAMSubnet, IPAMRegion)
        .join(IPAMSubnet, IPAMSubnet.id == IPAMAddress.subnet_id)
        .join(IPAMRegion, IPAMRegion.id == IPAMSubnet.region_id)
        .filter(IPAMSubnet.deleted_at.is_(None))
    )
    if region_id is not None:
        q = q.filter(IPAMRegion.id == region_id)

    rows = []
    for addr, subnet, region in q.order_by(IPAMRegion.name, IPAMSubnet.cidr_block, IPAMAddress.ip_address):
        rows.append(
            {
                "region": region.name,
                "cidr_block": str(subnet.cidr_block),
                "ip_address": str(addr.ip_address),
                "status": addr.status.value if hasattr(addr.status, "value") else str(addr.status),
                "hostname": addr.hostname,
                "mac_address": str(addr.mac_address) if addr.mac_address else None,
                "description": addr.description,
                "expires_at": addr.expires_at.isoformat() if addr.expires_at else None,
                "noc_device_id": addr.noc_device_id,
            },
        )
    return rows


def export_csv(rows: list[dict]) -> str:
    if not rows:
        return "region,cidr_block,ip_address,status,hostname,mac_address,description,expires_at,noc_device_id\n"
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def import_addresses(
    db: Session,
    subnet_id: int,
    items: list[dict],
    *,
    actor: str | None,
) -> dict[str, int]:
    subnet = db.get(IPAMSubnet, subnet_id)
    if not subnet or subnet.deleted_at:
        raise ValueError("Subred no encontrada")

    cidr = str(subnet.cidr_block)
    created = updated = skipped = 0

    for raw in items:
        ip_raw = raw.get("ip_address") or raw.get("ip")
        if not ip_raw:
            skipped += 1
            continue
        ip_str = str(parse_ip(str(ip_raw)))
        if not ip_in_network(ip_str, cidr):
            skipped += 1
            continue

        status_raw = raw.get("status", "Free")
        try:
            status = IPAMAddressStatus(status_raw)
        except ValueError:
            status = IPAMAddressStatus.FREE

        row = (
            db.query(IPAMAddress)
            .filter(IPAMAddress.subnet_id == subnet_id, IPAMAddress.ip_address == ip_str)
            .first()
        )
        if row:
            row.status = status
            row.hostname = raw.get("hostname") or row.hostname
            row.description = raw.get("description") or row.description
            updated += 1
        else:
            db.add(
                IPAMAddress(
                    subnet_id=subnet_id,
                    ip_address=ip_str,
                    status=status,
                    hostname=raw.get("hostname"),
                    mac_address=raw.get("mac_address"),
                    description=raw.get("description"),
                    is_discovered_by_nmap=False,
                ),
            )
            created += 1

    audit_log(db, entity_type="subnet", entity_id=subnet_id, action="import", actor=actor, changes={"created": created, "updated": updated})
    db.commit()
    return {"created": created, "updated": updated, "skipped": skipped}


def bulk_reserve(
    db: Session,
    subnet_id: int,
    *,
    start_ip: str,
    end_ip: str,
    status: IPAMAddressStatus,
    description: str | None,
    expires_at: datetime | None,
    actor: str | None,
) -> dict[str, int]:
    subnet = db.get(IPAMSubnet, subnet_id)
    if not subnet or subnet.deleted_at:
        raise ValueError("Subred no encontrada")

    cidr = str(subnet.cidr_block)
    created = updated = 0

    for ip_str in iter_ips_in_range(start_ip, end_ip):
        if not ip_in_network(ip_str, cidr):
            continue
        row = (
            db.query(IPAMAddress)
            .filter(IPAMAddress.subnet_id == subnet_id, IPAMAddress.ip_address == ip_str)
            .first()
        )
        if row:
            row.status = status
            row.description = description or row.description
            row.expires_at = expires_at or row.expires_at
            updated += 1
        else:
            db.add(
                IPAMAddress(
                    subnet_id=subnet_id,
                    ip_address=ip_str,
                    status=status,
                    description=description,
                    expires_at=expires_at,
                    is_discovered_by_nmap=False,
                ),
            )
            created += 1

    audit_log(
        db,
        entity_type="subnet",
        entity_id=subnet_id,
        action="bulk_reserve",
        actor=actor,
        changes={"start_ip": start_ip, "end_ip": end_ip, "status": status.value, "created": created, "updated": updated},
    )
    db.commit()
    return {"created": created, "updated": updated}


def sync_dhcp_leases(db: Session, subnet_id: int, leases: list[dict], *, actor: str | None) -> dict[str, int]:
    subnet = db.get(IPAMSubnet, subnet_id)
    if not subnet or subnet.deleted_at:
        raise ValueError("Subred no encontrada")

    cidr = str(subnet.cidr_block)
    synced = 0

    for lease in leases:
        ip_str = str(parse_ip(str(lease.get("ip_address") or lease.get("ip"))))
        if not ip_in_network(ip_str, cidr):
            continue

        exp = lease.get("expires_at")
        expires = datetime.fromisoformat(exp.replace("Z", "+00:00")) if isinstance(exp, str) else None

        row = (
            db.query(IPAMAddress)
            .filter(IPAMAddress.subnet_id == subnet_id, IPAMAddress.ip_address == ip_str)
            .first()
        )
        if row:
            row.status = IPAMAddressStatus.DHCP
            row.mac_address = lease.get("mac_address") or row.mac_address
            row.hostname = lease.get("hostname") or row.hostname
            row.dhcp_lease_expires = expires
        else:
            row = IPAMAddress(
                subnet_id=subnet_id,
                ip_address=ip_str,
                status=IPAMAddressStatus.DHCP,
                mac_address=lease.get("mac_address"),
                hostname=lease.get("hostname"),
                dhcp_lease_expires=expires,
                is_discovered_by_nmap=False,
            )
            db.add(row)
        synced += 1

    audit_log(db, entity_type="subnet", entity_id=subnet_id, action="dhcp_sync", actor=actor, changes={"synced": synced})
    db.commit()
    return {"synced": synced}


def build_heatmap(db: Session, subnet_id: int) -> dict:
    subnet = db.get(IPAMSubnet, subnet_id)
    if not subnet or subnet.deleted_at:
        raise ValueError("Subred no encontrada")

    cidr = str(subnet.cidr_block)
    from app.services.rfc1918 import parse_cidr

    network = parse_cidr(cidr)
    if network.prefixlen > 28 or network.version != 4:
        raise ValueError("Heatmap solo disponible para IPv4 /16–/28")

    addr_map = {
        str(a.ip_address): a.status.value if hasattr(a.status, "value") else str(a.status)
        for a in db.query(IPAMAddress).filter(IPAMAddress.subnet_id == subnet_id).all()
    }

    cells = []
    if network.prefixlen <= 24:
        for host in network.hosts():
            ip = str(host)
            cells.append({"ip": ip, "status": addr_map.get(ip, "untracked"), "last_octet": int(ip.split(".")[-1])})
    else:
        for host in network.hosts():
            ip = str(host)
            cells.append({"ip": ip, "status": addr_map.get(ip, "untracked"), "last_octet": int(ip.split(".")[-1])})

    return {"subnet_id": subnet_id, "cidr_block": cidr, "cells": cells, "prefixlen": network.prefixlen}
