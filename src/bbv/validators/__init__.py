"""Validator registry, keyed by vuln_class string."""
from __future__ import annotations

from .base import Validator, ValidatorContext
from .idor import IdorValidator
from .reflected_xss import ReflectedXssValidator
from .sqli_boolean import SqliBooleanValidator

_REGISTRY: dict[str, Validator] = {}


def register(validator: Validator) -> None:
    _REGISTRY[validator.vuln_class] = validator


def get_validator(vuln_class: str) -> Validator | None:
    return _REGISTRY.get(vuln_class)


def known_classes() -> list[str]:
    return sorted(_REGISTRY)


for _v in (ReflectedXssValidator(), IdorValidator(), SqliBooleanValidator()):
    register(_v)

__all__ = ["Validator", "ValidatorContext", "get_validator", "register", "known_classes"]
