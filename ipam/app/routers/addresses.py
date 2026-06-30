from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import CurrentUser, require_admin, require_write
from app.database import get_db
from app.models.ipam import IPAMAddress
from app.schemas.subnet import IPAddressResponse, IPAddressUpdate
from app.services.audit import audit_log
from app.services.search import address_response_enriched

router = APIRouter(prefix="/addresses", tags=["addresses"])


@router.patch("/{address_id}", response_model=IPAddressResponse)
def update_address(
    address_id: int,
    payload: IPAddressUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
) -> IPAddressResponse:
    address = db.get(IPAMAddress, address_id)
    if not address:
        raise HTTPException(status_code=404, detail="Dirección no encontrada")

    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(address, key, value)

    audit_log(db, entity_type="address", entity_id=address_id, action="update", actor=user.email, changes=data)
    db.commit()
    db.refresh(address)
    return address_response_enriched(db, address)


@router.delete("/{address_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_address(
    address_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
) -> None:
    address = db.get(IPAMAddress, address_id)
    if not address:
        raise HTTPException(status_code=404, detail="Dirección no encontrada")
    audit_log(db, entity_type="address", entity_id=address_id, action="delete", actor=user.email)
    db.delete(address)
    db.commit()
