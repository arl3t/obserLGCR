from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session, joinedload

from app.auth import CurrentUser, get_current_user, require_admin, require_write
from app.database import get_db
from app.models.discovery import NetworkDiscoveryHost, NetworkDiscoveryJob
from app.schemas.discovery import (
    DiscoveryAdHocRunRequest,
    DiscoveryHostPage,
    DiscoveryHostResponse,
    DiscoveryHostUpdate,
    DiscoveryJobCreate,
    DiscoveryJobResponse,
    DiscoveryJobUpdate,
    DiscoveryPortResponse,
    DiscoveryRunResponse,
    DiscoveryStatsResponse,
    DiscoveryTopologyResponse,
    DiscoveryVulnerabilityPage,
    DiscoveryVulnerabilityResponse,
)
from app.services import discovery_service as svc
from app.services.nmap_scan_engine import PROFILE_LABELS, is_scan_available, validate_targets
from app.services.scheduler import refresh_discovery_jobs

router = APIRouter(prefix="/discovery", tags=["discovery"])


def _vuln_response(v) -> DiscoveryVulnerabilityResponse:
    return DiscoveryVulnerabilityResponse(
        id=v.id,
        cve_id=v.cve_id,
        severity=v.severity,
        cvss_score=float(v.cvss_score) if v.cvss_score is not None else None,
        title=v.title,
        port=v.port,
        protocol=v.protocol,
        script_id=v.script_id,
        details=v.details,
    )


def _host_response(h: NetworkDiscoveryHost) -> DiscoveryHostResponse:
    return DiscoveryHostResponse(
        id=h.id,
        run_id=h.run_id,
        ip_address=str(h.ip_address),
        hostname=h.hostname,
        mac_address=str(h.mac_address) if h.mac_address else None,
        status=h.status,
        os_guess=h.os_guess,
        notes=h.notes,
        documented=h.documented,
        documented_at=h.documented_at,
        documented_by=h.documented_by,
        tags=h.tags,
        ports=[
            DiscoveryPortResponse(
                id=p.id,
                port=p.port,
                protocol=p.protocol,
                state=p.state,
                service=p.service,
                product=p.product,
                version=p.version,
                extra_info=p.extra_info,
            )
            for p in h.ports
        ],
        vulnerabilities=[_vuln_response(v) for v in (h.vulnerabilities or [])],
        cve_count=len(h.vulnerabilities or []),
    )


@router.get("/profiles")
def list_profiles(_user: CurrentUser = Depends(get_current_user)):
    return [{"id": k, "label": v} for k, v in PROFILE_LABELS.items()]


@router.get("/status")
def discovery_status(_user: CurrentUser = Depends(get_current_user)):
    from app.services.nmap_discovery import is_nmap_runner_configured
    from app.services.nmap_runner_client import check_nmap_runner_health

    runner = is_nmap_runner_configured()
    return {
        "scan_available": is_scan_available(),
        "runner_configured": runner,
        "runner_ok": check_nmap_runner_health() if runner else None,
    }


@router.get("/jobs", response_model=list[DiscoveryJobResponse])
def get_jobs(db: Session = Depends(get_db), _user: CurrentUser = Depends(get_current_user)):
    return svc.list_jobs(db)


@router.post("/jobs", response_model=DiscoveryJobResponse, status_code=201)
def post_job(
    payload: DiscoveryJobCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    try:
        validate_targets(payload.targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job = svc.create_job(db, payload.model_dump(), user.email)
    refresh_discovery_jobs()
    return job


@router.patch("/jobs/{job_id}", response_model=DiscoveryJobResponse)
def patch_job(
    job_id: int,
    payload: DiscoveryJobUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    job = svc.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job no encontrado")
    data = payload.model_dump(exclude_unset=True)
    if "targets" in data:
        try:
            validate_targets(data["targets"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    job = svc.update_job(db, job, data)
    refresh_discovery_jobs()
    return job


@router.delete("/jobs/{job_id}", status_code=204)
def remove_job(
    job_id: int,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(require_admin),
):
    job = svc.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job no encontrado")
    svc.delete_job(db, job)
    refresh_discovery_jobs()


@router.post("/jobs/{job_id}/run", response_model=DiscoveryRunResponse, status_code=202)
def run_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    if not is_scan_available():
        raise HTTPException(status_code=503, detail="nmap no disponible")
    job = svc.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job no encontrado")
    run = svc.create_run_record(
        db,
        targets=job.targets,
        scan_profile=job.scan_profile,
        triggered_by=user.email,
        job_id=job.id,
        name=job.name,
        scan_cves=job.scan_cves,
    )
    svc.enqueue_run(
        run.id,
        custom_args=job.custom_args,
        auto_sync_ipam=job.auto_sync_ipam,
        ipam_subnet_id=job.ipam_subnet_id,
        scan_cves=job.scan_cves,
    )
    return run


@router.post("/runs", response_model=DiscoveryRunResponse, status_code=202)
def run_ad_hoc(
    payload: DiscoveryAdHocRunRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    if not is_scan_available():
        raise HTTPException(status_code=503, detail="nmap no disponible")
    try:
        validate_targets(payload.targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    run = svc.create_run_record(
        db,
        targets=payload.targets,
        scan_profile=payload.scan_profile,
        triggered_by=user.email,
        name=payload.name or f"Ad-hoc {payload.scan_profile}",
        scan_cves=payload.scan_cves,
    )
    svc.enqueue_run(
        run.id,
        custom_args=payload.custom_args,
        auto_sync_ipam=payload.auto_sync_ipam,
        ipam_subnet_id=payload.ipam_subnet_id,
        scan_cves=payload.scan_cves,
    )
    return run


@router.get("/runs", response_model=list[DiscoveryRunResponse])
def get_runs(
    job_id: int | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
):
    return svc.list_runs(db, limit=limit, job_id=job_id)


@router.get("/runs/{run_id}", response_model=DiscoveryRunResponse)
def get_run(run_id: int, db: Session = Depends(get_db), _user: CurrentUser = Depends(get_current_user)):
    run = svc.get_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run no encontrado")
    return run


@router.get("/runs/{run_id}/hosts", response_model=DiscoveryHostPage)
def get_run_hosts(
    run_id: int,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    documented: bool | None = None,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
):
    if not svc.get_run(db, run_id):
        raise HTTPException(status_code=404, detail="Run no encontrado")
    rows, total = svc.list_hosts(db, run_id, limit=limit, offset=offset, documented_only=documented)
    return DiscoveryHostPage(total=total, limit=limit, offset=offset, data=[_host_response(h) for h in rows])


@router.patch("/hosts/{host_id}", response_model=DiscoveryHostResponse)
def patch_host(
    host_id: int,
    payload: DiscoveryHostUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_write),
):
    host = (
        db.query(NetworkDiscoveryHost)
        .options(
            joinedload(NetworkDiscoveryHost.ports),
            joinedload(NetworkDiscoveryHost.vulnerabilities),
        )
        .filter(NetworkDiscoveryHost.id == host_id)
        .first()
    )
    if not host:
        raise HTTPException(status_code=404, detail="Host no encontrado")
    host = svc.update_host(db, host, payload.model_dump(exclude_unset=True), user.email)
    db.refresh(host)
    return _host_response(host)


@router.get("/runs/{run_id}/vulnerabilities", response_model=DiscoveryVulnerabilityPage)
def get_run_vulnerabilities(
    run_id: int,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
):
    if not svc.get_run(db, run_id):
        raise HTTPException(status_code=404, detail="Run no encontrado")
    rows, total = svc.list_vulnerabilities(db, run_id, limit=limit, offset=offset)
    return DiscoveryVulnerabilityPage(
        total=total,
        limit=limit,
        offset=offset,
        data=[_vuln_response(v) for v in rows],
    )


@router.get("/runs/{run_id}/stats", response_model=DiscoveryStatsResponse)
def get_run_stats(run_id: int, db: Session = Depends(get_db), _user: CurrentUser = Depends(get_current_user)):
    try:
        return svc.get_stats(db, run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/runs/{run_id}/topology", response_model=DiscoveryTopologyResponse)
def get_run_topology(
    run_id: int,
    mode: str = Query("auto", pattern="^(auto|detail|summary)$"),
    compare: bool = Query(True),
    compare_run_id: int | None = Query(None),
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
):
    if not svc.get_run(db, run_id):
        raise HTTPException(status_code=404, detail="Run no encontrado")
    try:
        return svc.build_topology(
            db,
            run_id,
            mode=mode,
            compare=compare,
            compare_run_id=compare_run_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/runs/{run_id}/export")
def export_run(
    run_id: int,
    format: str = Query("json", pattern="^(json|csv|xml)$"),
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
):
    run = svc.get_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run no encontrado")
    if format == "xml":
        if not run.raw_xml:
            raise HTTPException(status_code=404, detail="XML no disponible para este run")
        return Response(content=run.raw_xml, media_type="application/xml")
    if format == "csv":
        return PlainTextResponse(svc.export_run_csv(db, run_id), media_type="text/csv")
    return svc.export_run_json(db, run_id)


@router.post("/scheduler/refresh")
def refresh_scheduler(_user: CurrentUser = Depends(require_admin)):
    refresh_discovery_jobs()
    return {"ok": True}
