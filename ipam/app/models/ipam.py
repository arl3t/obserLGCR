import enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import CIDR, ENUM, INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class IPAMAddressStatus(str, enum.Enum):
    OFFLINE = "Offline"
    ONLINE = "Online"
    RESERVED = "Reserved"
    FREE = "Free"
    DHCP = "DHCP"


ipam_status_pg = ENUM(
    IPAMAddressStatus,
    name="ipam_address_status",
    create_type=False,
    values_callable=lambda obj: [e.value for e in obj],
)


class IPAMRegion(Base):
    __tablename__ = "ipam_regions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    contact_name: Mapped[str | None] = mapped_column(String(128))
    contact_email: Mapped[str | None] = mapped_column(String(255))
    rack_notes: Mapped[str | None] = mapped_column(Text)
    internal_asn: Mapped[str | None] = mapped_column(String(32))

    subnets: Mapped[list["IPAMSubnet"]] = relationship(back_populates="region")


class IPAMSubnet(Base):
    __tablename__ = "ipam_subnets"
    __table_args__ = (
        CheckConstraint(
            "vlan_id IS NULL OR (vlan_id >= 1 AND vlan_id <= 4094)",
            name="ipam_subnets_vlan_id_check",
        ),
        UniqueConstraint("region_id", "cidr_block", name="unique_cidr_per_region"),
        Index("idx_ipam_subnets_cidr_gist", "cidr_block", postgresql_using="gist"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    region_id: Mapped[int] = mapped_column(ForeignKey("ipam_regions.id", ondelete="RESTRICT"), nullable=False)
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    vlan_name: Mapped[str | None] = mapped_column(String(64))
    cidr_block: Mapped[str] = mapped_column(CIDR, nullable=False)
    broadcast_domain: Mapped[str | None] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    deleted_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    scan_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scan_cron: Mapped[str | None] = mapped_column(String(64))
    utilization_alert_pct: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False, default=85)
    utilization_webhook_url: Mapped[str | None] = mapped_column(Text)

    region: Mapped[IPAMRegion] = relationship(back_populates="subnets")
    addresses: Mapped[list["IPAMAddress"]] = relationship(back_populates="subnet", cascade="all, delete-orphan")


class IPAMAddress(Base):
    __tablename__ = "ipam_addresses"
    __table_args__ = (UniqueConstraint("subnet_id", "ip_address", name="unique_ip_per_subnet"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subnet_id: Mapped[int] = mapped_column(ForeignKey("ipam_subnets.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    status: Mapped[IPAMAddressStatus] = mapped_column(ipam_status_pg, nullable=False, default=IPAMAddressStatus.FREE)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(MACADDR)
    description: Mapped[str | None] = mapped_column(Text)
    last_seen: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    is_discovered_by_nmap: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    noc_device_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    dhcp_lease_expires: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    subnet: Mapped[IPAMSubnet] = relationship(back_populates="addresses")


class IPAMAuditLog(Base):
    __tablename__ = "ipam_audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255))
    changes: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IPAMDHCPLease(Base):
    __tablename__ = "ipam_dhcp_leases"
    __table_args__ = (UniqueConstraint("subnet_id", "ip_address", name="ipam_dhcp_leases_subnet_ip_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subnet_id: Mapped[int | None] = mapped_column(ForeignKey("ipam_subnets.id", ondelete="CASCADE"))
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    mac_address: Mapped[str | None] = mapped_column(MACADDR)
    hostname: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
