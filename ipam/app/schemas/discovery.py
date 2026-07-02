from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ScanProfile = Literal["discovery", "quick", "standard", "full", "stealth", "vulnerabilities", "custom"]
RunStatus = Literal["pending", "running", "completed", "failed"]

VALID_PROFILES = {"discovery", "quick", "standard", "full", "stealth", "vulnerabilities", "custom"}


class DiscoveryJobCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = None
    targets: str = Field(..., min_length=1, max_length=2000)
    scan_profile: ScanProfile = "discovery"
    custom_args: str | None = None
    schedule_cron: str | None = Field(default=None, max_length=64)
    schedule_interval_minutes: int | None = Field(default=None, ge=15, le=10080)
    schedule_enabled: bool = False
    detect_new_assets: bool = True
    open_incidents_on_unacked: bool = True
    auto_sync_ipam: bool = False
    scan_cves: bool = False
    ipam_subnet_id: int | None = None

    @field_validator("scan_profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        if v not in VALID_PROFILES:
            raise ValueError(f"Perfil inválido. Use: {', '.join(sorted(VALID_PROFILES))}")
        return v


class DiscoveryJobUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    targets: str | None = Field(default=None, min_length=1, max_length=2000)
    scan_profile: ScanProfile | None = None
    custom_args: str | None = None
    schedule_cron: str | None = None
    schedule_enabled: bool | None = None
    auto_sync_ipam: bool | None = None
    scan_cves: bool | None = None
    ipam_subnet_id: int | None = None


class DiscoveryJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    targets: str
    scan_profile: str
    custom_args: str | None
    schedule_cron: str | None
    schedule_interval_minutes: int | None = None
    schedule_enabled: bool
    detect_new_assets: bool = True
    open_incidents_on_unacked: bool = True
    auto_sync_ipam: bool
    scan_cves: bool
    ipam_subnet_id: int | None
    last_run_at: datetime | None
    last_run_id: int | None
    created_by: str | None
    created_at: datetime | None
    updated_at: datetime | None


class DiscoveryRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_id: int | None
    name: str | None
    targets: str
    scan_profile: str
    nmap_command: str | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    hosts_up: int
    hosts_total: int
    ports_open: int
    scan_cves: bool = False
    nmap_summary: str | None
    error_message: str | None
    triggered_by: str | None
    created_at: datetime | None


class DiscoveryPortResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None


class DiscoveryVulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    severity: str | None
    cvss_score: float | None
    title: str | None
    port: int | None
    protocol: str | None
    script_id: str | None
    details: str | None


class DiscoveryHostResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int
    ip_address: str
    hostname: str | None
    mac_address: str | None
    status: str
    os_guess: str | None
    notes: str | None
    documented: bool
    documented_at: datetime | None
    documented_by: str | None
    tags: list[str] | None
    ports: list[DiscoveryPortResponse] = []
    vulnerabilities: list[DiscoveryVulnerabilityResponse] = []
    cve_count: int = 0


class DiscoveryHostUpdate(BaseModel):
    notes: str | None = None
    documented: bool | None = None
    tags: list[str] | None = None
    os_guess: str | None = None


class DiscoveryHostPage(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[DiscoveryHostResponse]


class DiscoveryStatsResponse(BaseModel):
    run_id: int
    hosts_up: int
    hosts_total: int
    ports_open: int
    documented: int
    cves_total: int = 0
    hosts_with_cves: int = 0
    by_cve: list[dict[str, int | str]] = []
    by_service: list[dict[str, int | str]]
    by_port: list[dict[str, int | str]]
    by_os: list[dict[str, int | str]]
    by_status: dict[str, int]


class DiscoveryTopologyNode(BaseModel):
    id: str
    label: str
    ip: str
    hostname: str | None = None
    status: str
    port_count: int
    documented: bool
    subnet: str
    x: float | None = None
    y: float | None = None
    node_type: str = "host"
    gateway_inferred: bool | None = None
    host_id: int | None = None
    mac_address: str | None = None
    os_guess: str | None = None
    open_ports: list[int] = []
    has_critical_ports: bool = False
    noc_device_id: str | None = None
    noc_status: str | None = None
    noc_open_alerts: int = 0
    delta: str | None = None
    region_name: str | None = None


class DiscoveryTopologyEdge(BaseModel):
    source: str
    target: str
    label: str
    edge_type: str = "gateway"


class DiscoveryTopologyCluster(BaseModel):
    id: str
    subnet: str
    label: str
    host_count: int
    documented: int
    ports_open: int
    x: float
    y: float
    width: float
    height: float


class DiscoveryTopologyResponse(BaseModel):
    run_id: int
    compare_run_id: int | None = None
    mode: str = "detail"
    nodes: list[DiscoveryTopologyNode]
    edges: list[DiscoveryTopologyEdge]
    subnets: list[str]
    clusters: list[DiscoveryTopologyCluster] = []
    meta: dict[str, Any] = {}


class DiscoveryVulnerabilityPage(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[DiscoveryVulnerabilityResponse]


class DiscoveryAdHocRunRequest(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    targets: str = Field(..., min_length=1, max_length=2000)
    scan_profile: ScanProfile = "discovery"
    custom_args: str | None = None
    scan_cves: bool = False
    auto_sync_ipam: bool = False
    ipam_subnet_id: int | None = None
