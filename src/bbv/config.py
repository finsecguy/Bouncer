"""Configuration via pydantic-settings. Secrets come from .env only."""
from __future__ import annotations

import json
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="BBV_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_path: str = "data/bbv.db"

    # Rate limiting (conservative defaults).
    rate_per_host: float = 2.0
    rate_per_host_burst: int = 4
    rate_global: float = 5.0
    rate_global_burst: int = 10

    # HTTP
    http_timeout: float = 15.0
    user_agent: str = "bbv-validator/0.1"

    # IDOR sessions: JSON header dicts. Empty => IDOR validator cannot run.
    idor_session_a: dict[str, str] = Field(default_factory=dict)
    idor_session_b: dict[str, str] = Field(default_factory=dict)

    @field_validator("idor_session_a", "idor_session_b", mode="before")
    @classmethod
    def _parse_json_dict(cls, v: Any) -> Any:
        if v is None or v == "":
            return {}
        if isinstance(v, str):
            return json.loads(v)
        return v


def load_settings() -> Settings:
    return Settings()
