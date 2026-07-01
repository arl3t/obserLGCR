from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.discovery import NetworkDiscoveryJob
from app.models.ipam import IPAMSubnet
from app.services import discovery_service as discovery_svc
from app.services.asset_integration import post_subnet_nmap_pipeline
from app.services.ipam_nmap_sync import sync_nmap_discovery
from app.services.nmap_discovery import is_nmap_available, run_nmap_host_discovery

logger = logging.getLogger("ipam.scheduler")
_scheduler: BackgroundScheduler | None = None


def _run_subnet_scan(subnet_id: int) -> None:
    if not is_nmap_available():
        return
    db: Session = SessionLocal()
    try:
        subnet = db.get(IPAMSubnet, subnet_id)
        if not subnet or subnet.deleted_at or not subnet.scan_enabled:
            return
        cidr = str(subnet.cidr_block)
        hosts, _ = run_nmap_host_discovery(cidr)
        sync_nmap_discovery(db, subnet, hosts)
        post_subnet_nmap_pipeline(db, subnet_id, hosts)
        logger.info("cron_nmap_done subnet=%s hosts=%s", subnet_id, len(hosts))
    except Exception:
        logger.exception("cron_nmap_failed subnet=%s", subnet_id)
    finally:
        db.close()


def _run_discovery_job(job_id: int) -> None:
    if not is_nmap_available():
        return
    db: Session = SessionLocal()
    try:
        job = db.get(NetworkDiscoveryJob, job_id)
        if not job or not job.schedule_enabled:
            return
        run = discovery_svc.create_run_record(
            db,
            targets=job.targets,
            scan_profile=job.scan_profile,
            triggered_by="scheduler",
            job_id=job.id,
            name=job.name,
        )
        discovery_svc.execute_run(
            run.id,
            custom_args=job.custom_args,
            auto_sync_ipam=job.auto_sync_ipam,
            ipam_subnet_id=job.ipam_subnet_id,
        )
        logger.info("cron_discovery_done job=%s run=%s", job_id, run.id)
    except Exception:
        logger.exception("cron_discovery_failed job=%s", job_id)
    finally:
        db.close()


def refresh_discovery_jobs() -> None:
    global _scheduler
    if _scheduler is None:
        return
    db = SessionLocal()
    try:
        for job in _scheduler.get_jobs():
            if job.id.startswith("discovery-"):
                _scheduler.remove_job(job.id)
        rows = (
            db.query(NetworkDiscoveryJob)
            .filter(NetworkDiscoveryJob.schedule_enabled.is_(True), NetworkDiscoveryJob.schedule_cron.isnot(None))
            .all()
        )
        for job in rows:
            cron = (job.schedule_cron or "").strip()
            if not cron:
                continue
            parts = cron.split()
            if len(parts) != 5:
                continue
            try:
                trigger = CronTrigger(minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4])
                _scheduler.add_job(
                    _run_discovery_job,
                    trigger=trigger,
                    id=f"discovery-{job.id}",
                    args=[job.id],
                    replace_existing=True,
                )
            except Exception:
                logger.exception("invalid_discovery_cron job=%s cron=%s", job.id, cron)
    finally:
        db.close()


def refresh_scan_jobs() -> None:
    global _scheduler
    if _scheduler is None:
        return
    db = SessionLocal()
    try:
        for job in _scheduler.get_jobs():
            if job.id.startswith("nmap-"):
                _scheduler.remove_job(job.id)
        rows = (
            db.query(IPAMSubnet)
            .filter(IPAMSubnet.deleted_at.is_(None), IPAMSubnet.scan_enabled.is_(True), IPAMSubnet.scan_cron.isnot(None))
            .all()
        )
        for subnet in rows:
            cron = (subnet.scan_cron or "").strip()
            if not cron:
                continue
            parts = cron.split()
            if len(parts) != 5:
                continue
            try:
                trigger = CronTrigger(minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4])
                _scheduler.add_job(_run_subnet_scan, trigger=trigger, id=f"nmap-{subnet.id}", args=[subnet.id], replace_existing=True)
            except Exception:
                logger.exception("invalid_cron subnet=%s cron=%s", subnet.id, cron)
    finally:
        db.close()
    refresh_discovery_jobs()


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    _scheduler = BackgroundScheduler()
    _scheduler.start()
    refresh_scan_jobs()
    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
