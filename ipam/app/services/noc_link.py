from sqlalchemy import text
from sqlalchemy.orm import Session


def _mac_match_clause(alias_a: str = "a", alias_d: str = "d") -> str:
    return f"""(
              {alias_a}.ip_address IS NOT NULL
              AND {alias_d}.ip_address IS NOT NULL
              AND {alias_a}.ip_address = {alias_d}.ip_address
            )
            OR (
              {alias_a}.mac_address IS NOT NULL
              AND {alias_d}.mac_address IS NOT NULL
              AND lower(replace({alias_a}.mac_address::text, ':', ''))
                = lower(replace({alias_d}.mac_address, ':', ''))
            )"""


def link_address_to_noc(db: Session, address_id: int) -> dict | None:
    match = _mac_match_clause("a", "d")
    row = db.execute(
        text(
            f"""
            UPDATE ipam_addresses a
               SET noc_device_id = d.id
              FROM noc_devices d
             WHERE a.id = :aid
               AND a.noc_device_id IS NULL
               AND ({match})
             RETURNING d.id::text AS noc_device_id, d.hostname AS noc_hostname, d.status AS noc_status
            """,
        ),
        {"aid": address_id},
    ).mappings().first()
    if row:
        db.commit()
        return dict(row)
    return None


def auto_link_subnet(db: Session, subnet_id: int) -> int:
    match = _mac_match_clause("a", "d")
    result = db.execute(
        text(
            f"""
            UPDATE ipam_addresses a
               SET noc_device_id = d.id
              FROM noc_devices d
             WHERE a.subnet_id = :sid
               AND a.noc_device_id IS NULL
               AND ({match})
            """,
        ),
        {"sid": subnet_id},
    )
    db.commit()
    return result.rowcount or 0
