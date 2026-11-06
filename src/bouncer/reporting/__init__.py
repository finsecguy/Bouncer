"""Reporter registry, keyed by platform string (mirrors the validator registry).
Add HackerOne/Bugcrowd formatters by registering a new Reporter — no
restructuring needed."""
from __future__ import annotations

from .base import Reporter, ReportFacts, build_facts
from .intigriti import IntigritiReporter

_REGISTRY: dict[str, Reporter] = {}


def register(reporter: Reporter) -> None:
    _REGISTRY[reporter.platform] = reporter


def get_reporter(platform: str) -> Reporter | None:
    return _REGISTRY.get(platform)


def known_platforms() -> list[str]:
    return sorted(_REGISTRY)


for _r in (IntigritiReporter(),):
    register(_r)

__all__ = [
    "Reporter", "ReportFacts", "build_facts",
    "get_reporter", "register", "known_platforms",
]
