from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class NetworkDiscoveryJob(Base):
    __tablename__ = "network_discovery_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    targets: Mapped[str] = mapped_column(Text, nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(32), nullable=False, default="discovery")
    custom_args: Mapped[str | None] = mapped_column(Text)
    schedule_cron: Mapped[str | None] = mapped_column(String(64))
    schedule_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auto_sync_ipam: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scan_cves: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ipam_subnet_id: Mapped[int | None] = mapped_column(ForeignKey("ipam_subnets.id", ondelete="SET NULL"))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_id: Mapped[int | None] = mapped_column(BigInteger)
    created_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    runs: Mapped[list["NetworkDiscoveryRun"]] = relationship(back_populates="job")


class NetworkDiscoveryRun(Base):
    __tablename__ = "network_discovery_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("network_discovery_jobs.id", ondelete="SET NULL"))
    name: Mapped[str | None] = mapped_column(String(128))
    targets: Mapped[str] = mapped_column(Text, nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(32), nullable=False)
    nmap_command: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    hosts_up: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ports_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scan_cves: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    nmap_summary: Mapped[str | None] = mapped_column(Text)
    raw_xml: Mapped[str | None] = mapped_column(Text)
    stats_json: Mapped[dict | None] = mapped_column(JSONB)
    error_message: Mapped[str | None] = mapped_column(Text)
    triggered_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    job: Mapped[NetworkDiscoveryJob | None] = relationship(back_populates="runs")
    hosts: Mapped[list["NetworkDiscoveryHost"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class NetworkDiscoveryHost(Base):
    __tablename__ = "network_discovery_hosts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("network_discovery_runs.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(MACADDR)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="up")
    os_guess: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    documented_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    documented_by: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    run: Mapped[NetworkDiscoveryRun] = relationship(back_populates="hosts")
    ports: Mapped[list["NetworkDiscoveryPort"]] = relationship(back_populates="host", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["NetworkDiscoveryVulnerability"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )


class NetworkDiscoveryPort(Base):
    __tablename__ = "network_discovery_ports"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("network_discovery_hosts.id", ondelete="CASCADE"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    service: Mapped[str | None] = mapped_column(String(64))
    product: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(128))
    extra_info: Mapped[str | None] = mapped_column(Text)

    host: Mapped[NetworkDiscoveryHost] = relationship(back_populates="ports")


class NetworkDiscoveryVulnerability(Base):
    __tablename__ = "network_discovery_vulnerabilities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("network_discovery_hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(16))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(4, 1))
    title: Mapped[str | None] = mapped_column(Text)
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(8))
    script_id: Mapped[str | None] = mapped_column(String(128))
    details: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    host: Mapped[NetworkDiscoveryHost] = relationship(back_populates="vulnerabilities")
