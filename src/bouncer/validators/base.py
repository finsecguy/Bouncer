"""Validator contract and shared context."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..config import Settings
from ..http_client import ScopedHttpClient
from ..models import Finding, ValidationResult


@dataclass
class ValidatorContext:
    http: ScopedHttpClient
    settings: Settings


class Validator(ABC):
    """One per vuln class. Deterministic: proves exploitability with real
    request/response evidence, never by asking an LLM."""

    vuln_class: str = ""

    @abstractmethod
    def validate(self, finding: Finding, ctx: ValidatorContext) -> ValidationResult:
        ...
