from __future__ import annotations

import httpx
from sqlalchemy.orm import Session

from app.services.subnet_stats import compute_subnet_statistics


async def maybe_fire_utilization_webhook(db: Session, subnet) -> dict | None:
    url = (subnet.utilization_webhook_url or "").strip()
    if not url:
        return None

    stats = compute_subnet_statistics(db, subnet)
    threshold = float(subnet.utilization_alert_pct or 85)
    if stats.utilization_percent < threshold:
        return None

    payload = {
        "event": "ipam.utilization_high",
        "subnet_id": subnet.id,
        "cidr_block": str(subnet.cidr_block),
        "utilization_percent": stats.utilization_percent,
        "threshold": threshold,
        "occupied": stats.occupied,
        "total_host_capacity": stats.total_host_capacity,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            return {"status_code": resp.status_code, "sent": True}
    except Exception as exc:
        return {"sent": False, "error": str(exc)}
