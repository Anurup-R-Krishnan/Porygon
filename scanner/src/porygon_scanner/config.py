from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PORYGON_", case_sensitive=False, extra="ignore")

    version: str = "0.8.0"
    environment: str = "development"
    log_level: str = "INFO"
    service_name: str = "scanner"
    scanner_instance_id: str = "local-trivy-scanner-01"
    api_base_url: str = "http://backend:8000"
    internal_api_token: SecretStr = Field(min_length=32)
    heartbeat_interval_seconds: float = Field(default=10, ge=1, le=300)
    poll_seconds: float = Field(default=2, ge=0.2, le=300)
    lease_seconds: int = Field(default=1800, ge=60, le=7200)
    docker_base_url: str = "unix:///var/run/docker.sock"
    docker_timeout_seconds: int = Field(default=30, ge=1, le=300)
    trivy_binary: str = "/usr/local/bin/trivy"
    trivy_version: str = "0.72.0"
    trivy_cache_dir: str = "/var/lib/trivy"
    trivy_timeout_seconds: int = Field(default=900, ge=30, le=7200)
    epss_url: str = "https://api.first.org/data/v1/epss"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    intel_timeout_seconds: int = Field(default=30, ge=3, le=300)
    intel_batch_size: int = Field(default=100, ge=1, le=500)


@lru_cache
def get_settings() -> Settings:
    return Settings()
