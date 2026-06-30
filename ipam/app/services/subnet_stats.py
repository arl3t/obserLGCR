from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.ipam import IPAMAddress, IPAMSubnet
from app.schemas.subnet import SubnetStatisticsResponse
from app.services.rfc1918 import OCCUPIED_STATUSES, host_capacity, parse_cidr


def compute_subnet_statistics(db: Session, subnet: IPAMSubnet) -> SubnetStatisticsResponse:
    network = parse_cidr(str(subnet.cidr_block))
    total_capacity = host_capacity(network)

    status_rows = db.execute(
        select(IPAMAddress.status, func.count())
        .where(IPAMAddress.subnet_id == subnet.id)
        .group_by(IPAMAddress.status)
    ).all()

    by_status = {str(row[0].value if hasattr(row[0], "value") else row[0]): row[1] for row in status_rows}

    occupied = sum(by_status.get(s, 0) for s in OCCUPIED_STATUSES)
    free_tracked = by_status.get("Free", 0) + by_status.get("Offline", 0)
    free_remaining = max(total_capacity - occupied, 0)
    utilization = round((occupied / total_capacity) * 100, 2) if total_capacity > 0 else 0.0
    threshold = float(subnet.utilization_alert_pct or 85)

    return SubnetStatisticsResponse(
        subnet_id=subnet.id,
        cidr_block=str(subnet.cidr_block),
        region_id=subnet.region_id,
        vlan_id=subnet.vlan_id,
        total_host_capacity=total_capacity,
        occupied=occupied,
        free_tracked=free_tracked,
        free_remaining=free_remaining,
        utilization_percent=utilization,
        by_status=by_status,
        alert_threshold=threshold,
        alert_triggered=utilization >= threshold,
    )
