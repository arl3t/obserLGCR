from fastapi import APIRouter, Depends, HTTPException, Query, status
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user, require_write
from app.database import get_db
from app.models.ipam import IPAMAddress, IPAMSubnet
from app.schemas.subnet import IPAddressCreate, IPAddressResponse
from app.services.address_serial import to_address_response
from app.services.audit import audit_log
from app.services.rfc1918 import ip_in_network, parse_ip
from app.services.search import address_response_enriched

router = APIRouter(tags=["inventory"])


@router.get("/subnets/{subnet_id}/addresses")
def list_subnet_addresses(
    subnet_id: int,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
):
    subnet = db.get(IPAMSubnet, subnet_id)
    if not subnet or subnet.deleted_at:
        raise HTTPException(status_code=404, detail="Subred no encontrada")

    q = db.query(IPAMAddress).filter(IPAMAddress.subnet_id == subnet_id)
    total = q.count()
    rows = q.order_by(IPAMAddress.ip_address).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "data": [address_response_enriched(db, r) for r in rows],
    }


@router.post("/subnets/{subnet_id}/addresses", response_model=IPAddressResponse, status_code=status.HTTP_201_CREATED)
def create_subnet_address(
    subnet_id: int,
    payload: IPAddressCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
) -> IPAddressResponse:
    subnet = db.get(IPAMSubnet, subnet_id)
    if not subnet or subnet.deleted_at:
        raise HTTPException(status_code=404, detail="Subred no encontrada")

    cidr = str(subnet.cidr_block)
    ip_str = str(parse_ip(payload.ip_address))
    if not ip_in_network(ip_str, cidr):
        raise HTTPException(status_code=400, detail=f"IP {ip_str} fuera de {cidr}")

    address = IPAMAddress(
        subnet_id=subnet_id,
        ip_address=ip_str,
        status=payload.status,
        hostname=payload.hostname,
        mac_address=payload.mac_address,
        description=payload.description,
        expires_at=payload.expires_at,
        is_discovered_by_nmap=False,
    )
    db.add(address)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if isinstance(exc.orig, UniqueViolation):
            raise HTTPException(status_code=409, detail="IP duplicada en subred") from exc
        raise HTTPException(status_code=400, detail="Error al crear dirección") from exc

    db.refresh(address)
    audit_log(db, entity_type="address", entity_id=address.id, action="create", actor=user.email, changes={"ip": ip_str})
    db.commit()
    return address_response_enriched(db, address)
