from fastapi import APIRouter, Depends, HTTPException, status
from psycopg2.errors import UniqueViolation
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user, require_admin, require_write
from app.database import get_db
from app.models.ipam import IPAMAddress, IPAMRegion, IPAMSubnet
from app.schemas.subnet import RegionCreate, RegionDetailResponse, RegionUpdate
from app.services.audit import audit_log

router = APIRouter(prefix="/regions", tags=["regions"])


def _region_detail(db: Session, region: IPAMRegion) -> RegionDetailResponse:
    subnet_count = (
        db.query(func.count(IPAMSubnet.id))
        .filter(IPAMSubnet.region_id == region.id, IPAMSubnet.deleted_at.is_(None))
        .scalar()
        or 0
    )
    address_count = (
        db.query(func.count(IPAMAddress.id))
        .join(IPAMSubnet, IPAMSubnet.id == IPAMAddress.subnet_id)
        .filter(IPAMSubnet.region_id == region.id, IPAMSubnet.deleted_at.is_(None))
        .scalar()
        or 0
    )
    return RegionDetailResponse(
        id=region.id,
        name=region.name,
        description=region.description,
        contact_name=region.contact_name,
        contact_email=region.contact_email,
        rack_notes=region.rack_notes,
        internal_asn=region.internal_asn,
        subnet_count=subnet_count,
        address_count=address_count,
    )


@router.get("", response_model=list[RegionDetailResponse])
def list_regions(
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> list[RegionDetailResponse]:
    regions = db.query(IPAMRegion).order_by(IPAMRegion.name).all()
    return [_region_detail(db, r) for r in regions]


@router.post("", response_model=RegionDetailResponse, status_code=status.HTTP_201_CREATED)
def create_region(
    payload: RegionCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
) -> RegionDetailResponse:
    region = IPAMRegion(**payload.model_dump())
    region.name = region.name.strip()
    db.add(region)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if isinstance(exc.orig, UniqueViolation):
            raise HTTPException(status_code=409, detail=f"Ya existe la región '{payload.name}'") from exc
        raise HTTPException(status_code=400, detail="Error al crear región") from exc
    db.refresh(region)
    audit_log(db, entity_type="region", entity_id=region.id, action="create", actor=user.email, changes=payload.model_dump())
    db.commit()
    return _region_detail(db, region)


@router.patch("/{region_id}", response_model=RegionDetailResponse)
def update_region(
    region_id: int,
    payload: RegionUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
) -> RegionDetailResponse:
    region = db.get(IPAMRegion, region_id)
    if not region:
        raise HTTPException(status_code=404, detail=f"Región {region_id} no encontrada")

    data = payload.model_dump(exclude_unset=True)
    if "name" in data and data["name"] is not None:
        region.name = data["name"].strip()
    for field in ("description", "contact_name", "contact_email", "rack_notes", "internal_asn"):
        if field in data:
            setattr(region, field, data[field])

    try:
        audit_log(db, entity_type="region", entity_id=region_id, action="update", actor=user.email, changes=data)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Nombre de región duplicado") from exc

    db.refresh(region)
    return _region_detail(db, region)


@router.delete("/{region_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_region(
    region_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
) -> None:
    region = db.get(IPAMRegion, region_id)
    if not region:
        raise HTTPException(status_code=404, detail=f"Región {region_id} no encontrada")

    subnet_count = (
        db.query(func.count(IPAMSubnet.id))
        .filter(IPAMSubnet.region_id == region_id, IPAMSubnet.deleted_at.is_(None))
        .scalar()
        or 0
    )
    if subnet_count > 0:
        raise HTTPException(status_code=409, detail=f"Región tiene {subnet_count} subred(es) activas")

    audit_log(db, entity_type="region", entity_id=region_id, action="delete", actor=user.email)
    db.delete(region)
    db.commit()
