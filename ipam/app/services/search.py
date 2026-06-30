from datetime import UTC, datetime

from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from app.models.ipam import IPAMAddress, IPAMAuditLog, IPAMSubnet
from app.schemas.subnet import IPAddressResponse
from app.services.address_serial import to_address_response


def address_response_enriched(db: Session, addr: IPAMAddress) -> IPAddressResponse:
    base = to_address_response(addr)
    noc_hostname = None
    if addr.noc_device_id:
        row = db.execute(
            text("SELECT hostname FROM noc_devices WHERE id = :id::uuid"),
            {"id": addr.noc_device_id},
        ).first()
        noc_hostname = row[0] if row else None

    expired = bool(addr.expires_at and addr.expires_at.replace(tzinfo=UTC) < datetime.now(UTC))
    return base.model_copy(update={"noc_hostname": noc_hostname, "reservation_expired": expired})


def search_addresses(db: Session, q: str, *, limit: int = 50, offset: int = 0) -> tuple[list[IPAddressResponse], int]:
    pattern = f"%{q.strip()}%"
    base_q = (
        db.query(IPAMAddress)
        .join(IPAMSubnet, IPAMSubnet.id == IPAMAddress.subnet_id)
        .filter(IPAMSubnet.deleted_at.is_(None))
        .filter(
            or_(
                IPAMAddress.hostname.ilike(pattern),
                text("host(ipam_addresses.ip_address) ILIKE :p").bindparams(p=pattern),
                text("CAST(ipam_addresses.mac_address AS text) ILIKE :p").bindparams(p=pattern),
                IPAMAddress.description.ilike(pattern),
            ),
        )
    )
    total = base_q.count()
    rows = base_q.order_by(IPAMAddress.ip_address).offset(offset).limit(limit).all()
    return [address_response_enriched(db, r) for r in rows], total
