from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PORYGON_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Porygon API"
    app_version: str = "0.8.0"
    environment: str = "development"
    log_level: str = "INFO"

    db_host: str = "postgres"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "porygon"
    db_user: str = "porygon"
    db_password: SecretStr

    internal_api_token: SecretStr = Field(min_length=32)
    operator_api_token: SecretStr = Field(min_length=32)
    response_execution_mode: Literal["disabled", "live"] = "disabled"
    calibrated_enabled: bool = False
    response_approval_max_age_seconds: int = Field(default=3600, ge=60, le=86400)
    baseline_max_events: int = Field(default=250000, ge=100, le=2000000)
    baseline_max_windows: int = Field(default=50000, ge=10, le=500000)
    anomaly_max_events: int = Field(default=100000, ge=10, le=1000000)
    anomaly_min_process_events: int = Field(default=1, ge=1, le=10000)
    parent_correlation_lookback_seconds: int = Field(default=600, ge=1, le=86400)
    vulnerability_max_findings: int = Field(default=50000, ge=1, le=500000)
    vulnerability_runtime_event_limit: int = Field(default=10000, ge=0, le=100000)
    sbom_max_components: int = Field(default=500000, ge=1, le=2000000)

    @property
    def database_url(self) -> URL:
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.db_user,
            password=self.db_password.get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
