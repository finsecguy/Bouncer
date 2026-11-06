"""Configuration via pydantic-settings. Secrets come from .env only."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Backward-compat: the env prefix was renamed BBV_ -> BOUNCER_. Legacy BBV_*
# names keep working for this version, with a one-time deprecation notice, so an
# existing .env does not silently stop working after the rename.
_LEGACY_PREFIX = "BBV_"
_NEW_PREFIX = "BOUNCER_"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="BOUNCER_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_path: str = "data/bouncer.db"

    # Rate limiting (conservative defaults).
    rate_per_host: float = 2.0
    rate_per_host_burst: int = 4
    rate_global: float = 5.0
    rate_global_burst: int = 10

    # HTTP
    http_timeout: float = 15.0
    user_agent: str = "bouncer-validator/0.1"

    # IDOR sessions: JSON header dicts. Empty => IDOR validator cannot run.
    idor_session_a: dict[str, str] = Field(default_factory=dict)
    idor_session_b: dict[str, str] = Field(default_factory=dict)

    # --- Recon (milestone 2) ---
    # External tool binaries (wrapped via subprocess, not reimplemented).
    # Paths are configurable so the PD 'httpx' tool is never confused with the
    # Python httpx library's 'httpx' CLI of the same name.
    subfinder_bin: str = "subfinder"
    httpx_bin: str = "httpx"
    katana_bin: str = "katana"
    recon_timeout: int = 120          # per-tool subprocess timeout (seconds)
    katana_max_depth: int = 2

    candidates_dir: str = "candidates"
    reports_dir: str = "reports"

    # --- LLM provider for candidate-generation reasoning (reasoning steps ONLY) ---
    # The chosen endpoint is reasoning infrastructure, NOT a program target, so it
    # is deliberately NOT routed through ScopedHttpClient. Keys are never logged.
    # provider: anthropic | openai | self_hosted (self_hosted is OpenAI-compatible,
    # e.g. Ollama/vLLM/LM Studio, selected via a non-default openai_base_url).
    llm_provider: str = "anthropic"

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5"
    anthropic_max_tokens: int = 2048

    openai_api_key: str = ""
    openai_model: str = "gpt-4.1-mini"
    openai_base_url: str = ""          # blank => OpenAI's real endpoint; required for self_hosted
    openai_max_tokens: int = 2048
    openai_timeout: float = 60.0       # self-hosted models can be slow; make it configurable
    openai_max_retries: int = 2        # retry transient 429/5xx/timeouts with backoff

    @field_validator("idor_session_a", "idor_session_b", mode="before")
    @classmethod
    def _parse_json_dict(cls, v: Any) -> Any:
        if v is None or v == "":
            return {}
        if isinstance(v, str):
            return json.loads(v)
        return v


def _migrate_legacy_env(env_path: str = ".env") -> None:
    """Map any legacy BBV_* variable (from the environment or .env) onto its
    BOUNCER_* equivalent when the new name is not already set, printing a
    one-time deprecation notice to stderr. Never overwrites a value the user has
    already provided under the new name."""
    legacy: dict[str, str] = {}
    for k, v in os.environ.items():
        if k.startswith(_LEGACY_PREFIX):
            legacy[k] = v
    p = Path(env_path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith(_LEGACY_PREFIX) and "=" in s and not s.startswith("#"):
                k, _, v = s.partition("=")
                legacy.setdefault(k.strip(), v.strip())

    def _env_file_has(key: str) -> bool:
        if not p.exists():
            return False
        for line in p.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith(f"{key}=") and not s.startswith("#"):
                return True
        return False

    for old, val in legacy.items():
        new = _NEW_PREFIX + old[len(_LEGACY_PREFIX):]
        if new in os.environ or _env_file_has(new):
            continue  # the new name wins; no migration, no notice
        os.environ[new] = val
        print(f"DEPRECATION: {old} is deprecated; rename it to {new} in your .env. "
              f"Honoring {old} for now.", file=sys.stderr)


def load_settings() -> Settings:
    _migrate_legacy_env()
    return Settings()
