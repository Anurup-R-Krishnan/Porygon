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

    service_name: str = "telemetry"
    telemetry_instance_id: str = "local-falco-adapter-01"
    api_base_url: str = "http://backend:8000"
    internal_api_token: SecretStr = Field(min_length=32)
    heartbeat_interval_seconds: int = Field(default=10, ge=2, le=300)
    environment: str = "development"
    log_level: str = "INFO"
    version: str = "0.3.0"

    falco_log_path: str = "/var/log/porygon/falco-events.jsonl"
    falco_poll_seconds: float = Field(default=0.25, ge=0.05, le=10.0)
    falco_max_line_bytes: int = Field(default=1_048_576, ge=4096, le=16_777_216)
    falco_expected_rule: str = "Porygon Container Process Execution"
    docker_host_id: str | None = None

    spool_path: str = "/var/lib/porygon/process-outbox.db"
    spool_max_events: int = Field(default=250_000, ge=100, le=10_000_000)
    delivery_batch_size: int = Field(default=100, ge=1, le=250)
    delivery_poll_seconds: float = Field(default=1.0, ge=0.2, le=30.0)
    delivery_retry_max_seconds: int = Field(default=60, ge=2, le=3600)
    dead_letter_max_records: int = Field(default=1000, ge=1, le=1_000_000)
    dead_letter_max_total_bytes: int = Field(
        default=1_048_576,
        ge=1024,
        le=1_073_741_824,
    )
    dead_letter_excerpt_bytes: int = Field(default=512, ge=64, le=16_384)
    dead_letter_retention_seconds: int = Field(default=604_800, ge=60, le=31_536_000)

    @property
    def reported_docker_host_id(self) -> str | None:
        if not self.docker_host_id or self.docker_host_id.lower() == "auto":
            return None
        return self.docker_host_id


@lru_cache
def get_settings() -> Settings:
    return Settings()
