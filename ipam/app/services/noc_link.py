from sqlalchemy import text
from sqlalchemy.orm import Session


def link_address_to_noc(db: Session, address_id: int) -> dict | None:
    row = db.execute(
        text(
            """
            UPDATE ipam_addresses a
               SET noc_device_id = d.id
              FROM noc_devices d
             WHERE a.id = :aid
               AND a.ip_address IS NOT NULL
               AND d.ip_address IS NOT NULL
               AND a.ip_address = d.ip_address
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
    result = db.execute(
        text(
            """
            UPDATE ipam_addresses a
               SET noc_device_id = d.id
              FROM noc_devices d
             WHERE a.subnet_id = :sid
               AND a.noc_device_id IS NULL
               AND a.ip_address = d.ip_address
            """,
        ),
        {"sid": subnet_id},
    )
    db.commit()
    return result.rowcount or 0
