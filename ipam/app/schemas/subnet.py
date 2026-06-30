from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.ipam import IPAMAddressStatus
from app.services.rfc1918 import is_private_network, parse_cidr


class RegionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None
    contact_name: str | None = None
    contact_email: str | None = None
    rack_notes: str | None = None
    internal_asn: str | None = None


class RegionDetailResponse(RegionResponse):
    subnet_count: int = 0
    address_count: int = 0


class RegionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    contact_name: str | None = None
    contact_email: str | None = None
    rack_notes: str | None = None
    internal_asn: str | None = None


class RegionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = None
    contact_name: str | None = None
    contact_email: str | None = None
    rack_notes: str | None = None
    internal_asn: str | None = None


class SubnetCreate(BaseModel):
    region_id: int = Field(..., ge=1)
    cidr_block: str = Field(..., min_length=3, max_length=43)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    vlan_name: str | None = Field(default=None, max_length=64)
    broadcast_domain: str | None = Field(default=None, max_length=128)
    description: str | None = None
    scan_enabled: bool = False
    scan_cron: str | None = None
    utilization_alert_pct: float = Field(default=85, ge=1, le=100)
    utilization_webhook_url: str | None = None

    @field_validator("cidr_block")
    @classmethod
    def validate_cidr_private(cls, value: str) -> str:
        network = parse_cidr(value)
        if not is_private_network(network):
            raise ValueError("cidr_block debe ser RFC 1918 (IPv4) o ULA fc00::/7 (IPv6)")
        return str(network)


class SubnetUpdate(BaseModel):
    region_id: int | None = Field(default=None, ge=1)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    vlan_name: str | None = Field(default=None, max_length=64)
    broadcast_domain: str | None = Field(default=None, max_length=128)
    description: str | None = None
    scan_enabled: bool | None = None
    scan_cron: str | None = None
    utilization_alert_pct: float | None = Field(default=None, ge=1, le=100)
    utilization_webhook_url: str | None = None


class SubnetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    region_id: int
    region_name: str | None = None
    vlan_id: int | None = None
    vlan_name: str | None = None
    cidr_block: str
    broadcast_domain: str | None = None
    description: str | None = None
    created_at: datetime | None = None
    deleted_at: datetime | None = None
    scan_enabled: bool = False
    scan_cron: str | None = None
    utilization_alert_pct: float = 85
    utilization_webhook_url: str | None = None
    rfc1918_scope: str = "private"
    overlap_warnings: list[dict] = Field(default_factory=list)
    vlan_warnings: list[dict] = Field(default_factory=list)


class SubnetStatisticsResponse(BaseModel):
    subnet_id: int
    cidr_block: str
    region_id: int
    vlan_id: int | None = None
    total_host_capacity: int
    occupied: int
    free_tracked: int
    free_remaining: int
    utilization_percent: float
    by_status: dict[str, int]
    alert_threshold: float = 85
    alert_triggered: bool = False


class IPAddressUpdate(BaseModel):
    status: IPAMAddressStatus | None = None
    hostname: str | None = Field(default=None, max_length=255)
    description: str | None = None
    mac_address: str | None = Field(default=None, max_length=17)
    last_seen: datetime | None = None
    is_discovered_by_nmap: bool | None = None
    expires_at: datetime | None = None

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower().replace("-", ":")
        parts = cleaned.split(":")
        if len(parts) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
            raise ValueError("mac_address inválida")
        return cleaned


class IPAddressCreate(BaseModel):
    ip_address: str
    status: IPAMAddressStatus = IPAMAddressStatus.FREE
    hostname: str | None = None
    mac_address: str | None = None
    description: str | None = None
    expires_at: datetime | None = None

    @field_validator("mac_address")
    @classmethod
    def validate_mac_create(cls, value: str | None) -> str | None:
        return IPAddressUpdate.validate_mac(value)


class IPAddressResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    subnet_id: int
    ip_address: str
    status: IPAMAddressStatus
    hostname: str | None = None
    mac_address: str | None = None
    description: str | None = None
    last_seen: datetime | None = None
    is_discovered_by_nmap: bool
    expires_at: datetime | None = None
    noc_device_id: str | None = None
    noc_hostname: str | None = None
    dhcp_lease_expires: datetime | None = None
    updated_at: datetime | None = None
    reservation_expired: bool = False


class NmapDiscoverRequest(BaseModel):
    mark_offline: bool = True
    preserve_reserved: bool = True


class NmapDiscoverResponse(BaseModel):
    subnet_id: int
    cidr_block: str
    hosts_capacity: int
    hosts_up: int
    created: int
    updated: int
    marked_offline: int
    duration_ms: int
    nmap_summary: str | None = None
    noc_linked: int = 0


class BulkReserveRequest(BaseModel):
    start_ip: str
    end_ip: str
    status: IPAMAddressStatus = IPAMAddressStatus.RESERVED
    description: str | None = None
    expires_at: datetime | None = None


class SearchResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[IPAddressResponse]


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    entity_type: str
    entity_id: str
    action: str
    actor: str | None
    changes: dict | None
    created_at: datetime


class HeatmapResponse(BaseModel):
    subnet_id: int
    cidr_block: str
    prefixlen: int
    cells: list[dict]
