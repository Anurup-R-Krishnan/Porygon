from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PORYGON_",
        case_sensitive=False,
        extra="ignore",
    )

    service_name: str = "responder"
    responder_instance_id: str = "local-responder-01"
    api_base_url: str = "http://backend:8000"
    internal_api_token: SecretStr = Field(min_length=32)
    heartbeat_interval_seconds: int = Field(default=10, ge=2, le=300)
    poll_seconds: float = Field(default=1.0, ge=0.2, le=30.0)
    lease_seconds: int = Field(default=30, ge=10, le=300)
    docker_base_url: str = "unix:///var/run/docker.sock"
    docker_timeout_seconds: int = Field(default=15, ge=2, le=120)
    stop_timeout_seconds: int = Field(default=10, ge=1, le=120)
    protected_label: str = "com.porygon.protected"
    environment: str = "development"
    log_level: str = "INFO"
    version: str = "0.7.0"


@lru_cache
def get_settings() -> Settings:
    return Settings()
