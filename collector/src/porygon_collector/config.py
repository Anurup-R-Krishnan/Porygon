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

    service_name: str = "collector"
    collector_instance_id: str = "local-collector-01"
    api_base_url: str = "http://backend:8000"
    internal_api_token: SecretStr = Field(min_length=32)
    heartbeat_interval_seconds: int = Field(default=10, ge=2, le=300)
    environment: str = "development"
    log_level: str = "INFO"
    version: str = "0.3.0"

    docker_base_url: str = "unix:///var/run/docker.sock"
    docker_host_id: str = "auto"
    docker_timeout_seconds: int = Field(default=10, ge=2, le=120)
    docker_event_window_seconds: int = Field(default=15, ge=5, le=120)
    docker_event_overlap_seconds: int = Field(default=2, ge=0, le=30)
    docker_reconnect_max_seconds: int = Field(default=30, ge=2, le=300)

    spool_path: str = "/var/lib/porygon/outbox.db"
    spool_max_events: int = Field(default=100_000, ge=100, le=10_000_000)
    delivery_batch_size: int = Field(default=100, ge=1, le=250)
    delivery_poll_seconds: float = Field(default=1.0, ge=0.2, le=30.0)
    delivery_retry_max_seconds: int = Field(default=60, ge=2, le=3600)


@lru_cache
def get_settings() -> Settings:
    return Settings()
