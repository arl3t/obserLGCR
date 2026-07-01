from pydantic import BaseModel, ConfigDict


class UnifiedAssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    unified_id: str
    noc_device_id: str | None = None
    ipam_address_id: int | None = None
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    device_type: str | None = None
    site: str | None = None
    noc_status: str | None = None
    ipam_status: str | None = None
    region_name: str | None = None
    cidr_block: str | None = None
    os_guess: str | None = None
    discovery_documented: bool | None = None
    discovery_open_ports: int = 0
    discovery_meta: dict | None = None
    criticality: str | None = None
    registry_type: str | None = None
    registry_sensor_key: str | None = None
    ipam_linked: bool = False
    last_seen_at: str | None = None


class UnifiedAssetPage(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[UnifiedAssetResponse]
