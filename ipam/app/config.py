from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql://obserlgcr:obserlgcr@postgres:5432/obserlgcr"
    app_name: str = "obserLGCR IPAM"
    debug: bool = False
    nmap_timeout_sec: int = 600
    nmap_host_timeout_sec: int = 5
    # Runner en el host: escanea LAN real (192.168.x.x) fuera del bridge Docker.
    nmap_runner_url: str = Field(default="", validation_alias="NMAP_RUNNER_URL")
    nmap_runner_token: str = Field(default="", validation_alias="NMAP_RUNNER_TOKEN")
    jwt_secret: str = Field(default="obserlgcr-agent-dev-secret-change-in-production", validation_alias="AGENT_JWT_SECRET")
    platform_auth_enabled: bool = Field(default=True, validation_alias="PLATFORM_AUTH_ENABLED")
    default_utilization_alert_pct: float = 85.0


settings = Settings()
