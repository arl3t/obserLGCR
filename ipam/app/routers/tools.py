from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user, require_admin, require_write
from app.database import get_db
from app.models.ipam import IPAMAuditLog, IPAMSubnet
from app.schemas.subnet import (
    AuditLogResponse,
    BulkReserveRequest,
    HeatmapResponse,
    SearchResponse,
)
from app.services.export_import import build_heatmap, bulk_reserve, export_csv, export_inventory, import_addresses, sync_dhcp_leases
from app.services.noc_link import auto_link_subnet, link_address_to_noc
from app.services.scheduler import refresh_scan_jobs
from app.services.search import search_addresses

router = APIRouter(tags=["tools"])


@router.get("/search", response_model=SearchResponse)
def global_search(
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> SearchResponse:
    data, total = search_addresses(db, q, limit=limit, offset=offset)
    return SearchResponse(total=total, limit=limit, offset=offset, data=data)


@router.get("/export")
def export_data(
    format: str = Query("json", pattern="^(json|csv)$"),
    region_id: int | None = None,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
):
    rows = export_inventory(db, region_id=region_id)
    if format == "csv":
        return PlainTextResponse(export_csv(rows), media_type="text/csv")
    return rows


@router.post("/subnets/{subnet_id}/import")
def import_subnet_data(
    subnet_id: int,
    body: list[dict],
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    try:
        return import_addresses(db, subnet_id, body, actor=user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/subnets/{subnet_id}/addresses/bulk")
def bulk_reserve_addresses(
    subnet_id: int,
    body: BulkReserveRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    try:
        return bulk_reserve(
            db,
            subnet_id,
            start_ip=body.start_ip,
            end_ip=body.end_ip,
            status=body.status,
            description=body.description,
            expires_at=body.expires_at,
            actor=user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/subnets/{subnet_id}/dhcp/sync")
def dhcp_sync(
    subnet_id: int,
    body: list[dict],
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    try:
        result = sync_dhcp_leases(db, subnet_id, body, actor=user.email)
        auto_link_subnet(db, subnet_id)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/subnets/{subnet_id}/heatmap", response_model=HeatmapResponse)
def subnet_heatmap(
    subnet_id: int,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> HeatmapResponse:
    try:
        data = build_heatmap(db, subnet_id)
        return HeatmapResponse(**data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/audit", response_model=list[AuditLogResponse])
def list_audit(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> list[AuditLogResponse]:
    rows = db.query(IPAMAuditLog).order_by(IPAMAuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return rows


@router.post("/addresses/{address_id}/link-noc")
def link_noc(
    address_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    result = link_address_to_noc(db, address_id)
    if not result:
        raise HTTPException(status_code=404, detail="Sin dispositivo NOC con la misma IP")
    return result


@router.post("/subnets/{subnet_id}/link-noc-all")
def link_noc_subnet(
    subnet_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    count = auto_link_subnet(db, subnet_id)
    refresh_scan_jobs()
    return {"linked": count}


@router.post("/scheduler/refresh")
def scheduler_refresh(_user: CurrentUser = Depends(require_admin)):
    refresh_scan_jobs()
    return {"ok": True}
