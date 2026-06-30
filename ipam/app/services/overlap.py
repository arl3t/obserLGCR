from sqlalchemy import text
from sqlalchemy.orm import Session


def check_cidr_overlap(db: Session, region_id: int, cidr: str, exclude_subnet_id: int | None = None) -> list[dict]:
    """Devuelve subredes que se solapan con cidr en la misma región (operador &&)."""
    sql = text(
        """
        SELECT id, cidr_block::text AS cidr_block
          FROM ipam_subnets
         WHERE region_id = :region_id
           AND deleted_at IS NULL
           AND cidr_block && CAST(:cidr AS cidr)
           AND (:exclude_id IS NULL OR id != :exclude_id)
        """,
    )
    rows = db.execute(sql, {"region_id": region_id, "cidr": cidr, "exclude_id": exclude_subnet_id}).mappings()
    return [dict(r) for r in rows]


def vlan_cross_region_warnings(db: Session, vlan_id: int, region_id: int) -> list[dict]:
    if vlan_id is None:
        return []
    sql = text(
        """
        SELECT s.id, s.cidr_block::text AS cidr_block, r.id AS region_id, r.name AS region_name
          FROM ipam_subnets s
          JOIN ipam_regions r ON r.id = s.region_id
         WHERE s.vlan_id = :vlan_id
           AND s.region_id != :region_id
           AND s.deleted_at IS NULL
        """,
    )
    rows = db.execute(sql, {"vlan_id": vlan_id, "region_id": region_id}).mappings()
    return [dict(r) for r in rows]
