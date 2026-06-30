import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.auth import CurrentUser, get_current_user, require_admin, require_write
from app.database import get_db
from app.models.ipam import IPAMRegion, IPAMSubnet
from app.schemas.subnet import (
    NmapDiscoverRequest,
    NmapDiscoverResponse,
    SubnetCreate,
    SubnetResponse,
    SubnetStatisticsResponse,
    SubnetUpdate,
)
from app.services.alerts import maybe_fire_utilization_webhook
from app.services.audit import audit_log
from app.services.ipam_nmap_sync import assert_scan_size, sync_nmap_discovery
from app.services.nmap_discovery import NmapNotAvailableError, NmapScanError, is_nmap_available, run_nmap_host_discovery
from app.services.noc_link import auto_link_subnet
from app.services.overlap import check_cidr_overlap, vlan_cross_region_warnings
from app.services.rfc1918 import parse_cidr
from app.services.scheduler import refresh_scan_jobs
from app.services.subnet_stats import compute_subnet_statistics

router = APIRouter(prefix="/subnets", tags=["subnets"])


def _subnet_to_response(db: Session, subnet: IPAMSubnet, *, include_warnings: bool = False) -> SubnetResponse:
    overlap_warnings = []
    vlan_warnings = []
    if include_warnings:
        overlap_warnings = check_cidr_overlap(db, subnet.region_id, str(subnet.cidr_block), subnet.id)
        if subnet.vlan_id:
            vlan_warnings = vlan_cross_region_warnings(db, subnet.vlan_id, subnet.region_id)

    return SubnetResponse(
        id=subnet.id,
        region_id=subnet.region_id,
        region_name=subnet.region.name if subnet.region else None,
        vlan_id=subnet.vlan_id,
        vlan_name=subnet.vlan_name,
        cidr_block=str(subnet.cidr_block),
        broadcast_domain=subnet.broadcast_domain,
        description=subnet.description,
        created_at=subnet.created_at,
        deleted_at=subnet.deleted_at,
        scan_enabled=bool(subnet.scan_enabled),
        scan_cron=subnet.scan_cron,
        utilization_alert_pct=float(subnet.utilization_alert_pct or 85),
        utilization_webhook_url=subnet.utilization_webhook_url,
        overlap_warnings=overlap_warnings,
        vlan_warnings=vlan_warnings,
    )


def _active_subnet(db: Session, subnet_id: int) -> IPAMSubnet | None:
    return (
        db.query(IPAMSubnet)
        .options(joinedload(IPAMSubnet.region))
        .filter(IPAMSubnet.id == subnet_id, IPAMSubnet.deleted_at.is_(None))
        .first()
    )


@router.get("", response_model=list[SubnetResponse])
def list_subnets(
    region_id: int | None = None,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> list[SubnetResponse]:
    q = db.query(IPAMSubnet).options(joinedload(IPAMSubnet.region)).filter(IPAMSubnet.deleted_at.is_(None))
    if region_id is not None:
        q = q.filter(IPAMSubnet.region_id == region_id)
    return [_subnet_to_response(db, s) for s in q.order_by(IPAMSubnet.id).all()]


@router.post("", response_model=SubnetResponse, status_code=status.HTTP_201_CREATED)
def create_subnet(
    payload: SubnetCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
) -> SubnetResponse:
    region = db.get(IPAMRegion, payload.region_id)
    if not region:
        raise HTTPException(status_code=404, detail=f"Región {payload.region_id} no encontrada")

    normalized_cidr = str(parse_cidr(payload.cidr_block))
    overlaps = check_cidr_overlap(db, payload.region_id, normalized_cidr)
    if overlaps:
        raise HTTPException(status_code=409, detail={"message": "CIDR solapa con subred existente", "overlaps": overlaps})

    subnet = IPAMSubnet(
        region_id=payload.region_id,
        vlan_id=payload.vlan_id,
        vlan_name=payload.vlan_name,
        cidr_block=normalized_cidr,
        broadcast_domain=payload.broadcast_domain,
        description=payload.description,
        scan_enabled=payload.scan_enabled,
        scan_cron=payload.scan_cron,
        utilization_alert_pct=payload.utilization_alert_pct,
        utilization_webhook_url=payload.utilization_webhook_url,
    )

    db.add(subnet)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if isinstance(exc.orig, UniqueViolation):
            raise HTTPException(status_code=409, detail="Ya existe ese CIDR en la región") from exc
        raise HTTPException(status_code=400, detail="Error de integridad") from exc

    db.refresh(subnet)
    subnet.region = region
    audit_log(db, entity_type="subnet", entity_id=subnet.id, action="create", actor=user.email, changes={"cidr": normalized_cidr})
    db.commit()
    refresh_scan_jobs()
    return _subnet_to_response(db, subnet, include_warnings=True)


@router.get("/{subnet_id}", response_model=SubnetResponse)
def get_subnet(
    subnet_id: int,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> SubnetResponse:
    subnet = _active_subnet(db, subnet_id)
    if not subnet:
        raise HTTPException(status_code=404, detail="Subred no encontrada")
    return _subnet_to_response(db, subnet, include_warnings=True)


@router.patch("/{subnet_id}", response_model=SubnetResponse)
def update_subnet(
    subnet_id: int,
    payload: SubnetUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
) -> SubnetResponse:
    subnet = _active_subnet(db, subnet_id)
    if not subnet:
        raise HTTPException(status_code=404, detail="Subred no encontrada")

    data = payload.model_dump(exclude_unset=True)
    if "region_id" in data and data["region_id"] is not None:
        region = db.get(IPAMRegion, data["region_id"])
        if not region:
            raise HTTPException(status_code=404, detail="Región no encontrada")
        subnet.region_id = data["region_id"]
        subnet.region = region

    for field in (
        "vlan_id",
        "vlan_name",
        "broadcast_domain",
        "description",
        "scan_enabled",
        "scan_cron",
        "utilization_alert_pct",
        "utilization_webhook_url",
    ):
        if field in data:
            setattr(subnet, field, data[field])

    audit_log(db, entity_type="subnet", entity_id=subnet_id, action="update", actor=user.email, changes=data)
    db.commit()
    db.refresh(subnet)
    refresh_scan_jobs()
    return _subnet_to_response(db, subnet, include_warnings=True)


@router.delete("/{subnet_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_subnet(
    subnet_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_admin),
) -> None:
    subnet = _active_subnet(db, subnet_id)
    if not subnet:
        raise HTTPException(status_code=404, detail="Subred no encontrada")
    subnet.deleted_at = datetime.now(UTC)
    audit_log(db, entity_type="subnet", entity_id=subnet_id, action="soft_delete", actor=user.email)
    db.commit()
    refresh_scan_jobs()


@router.get("/{subnet_id}/statistics", response_model=SubnetStatisticsResponse)
def subnet_statistics(
    subnet_id: int,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> SubnetStatisticsResponse:
    subnet = _active_subnet(db, subnet_id)
    if not subnet:
        raise HTTPException(status_code=404, detail="Subred no encontrada")
    return compute_subnet_statistics(db, subnet)


@router.post("/{subnet_id}/discover", response_model=NmapDiscoverResponse)
async def discover_subnet_nmap(
    subnet_id: int,
    payload: NmapDiscoverRequest | None = None,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
) -> NmapDiscoverResponse:
    subnet = _active_subnet(db, subnet_id)
    if not subnet:
        raise HTTPException(status_code=404, detail="Subred no encontrada")

    if not is_nmap_available():
        raise HTTPException(status_code=503, detail="nmap no disponible en el contenedor IPAM")

    cidr = str(subnet.cidr_block)
    opts = payload or NmapDiscoverRequest()

    try:
        capacity = assert_scan_size(cidr)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    started = time.perf_counter()
    try:
        hosts, summary = run_nmap_host_discovery(cidr)
    except (NmapNotAvailableError, NmapScanError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    counts = sync_nmap_discovery(db, subnet, hosts, mark_offline=opts.mark_offline, preserve_reserved=opts.preserve_reserved)
    noc_linked = auto_link_subnet(db, subnet_id)
    audit_log(db, entity_type="subnet", entity_id=subnet_id, action="nmap_discover", actor=user.email, changes=counts)
    db.commit()

    await maybe_fire_utilization_webhook(db, subnet)

    return NmapDiscoverResponse(
        subnet_id=subnet.id,
        cidr_block=cidr,
        hosts_capacity=capacity,
        hosts_up=len(hosts),
        created=counts["created"],
        updated=counts["updated"],
        marked_offline=counts["marked_offline"],
        duration_ms=int((time.perf_counter() - started) * 1000),
        nmap_summary=summary,
        noc_linked=noc_linked,
    )
