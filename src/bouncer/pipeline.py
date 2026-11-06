"""Validation orchestration: run the registered validator for a finding and
drive the state machine. The pipeline HARD-STOPS at in_review. There is no
submission path anywhere in this repo."""
from __future__ import annotations

from . import models as m
from . import state_machine as sm
from .config import Settings
from .http_client import ScopedHttpClient
from .rate_limiter import RateLimiter
from .repository import Repository
from .scope import Scope
from .validators import ValidatorContext, get_validator


def build_rate_limiter(settings: Settings) -> RateLimiter:
    return RateLimiter(
        per_host_rate=settings.rate_per_host,
        per_host_burst=settings.rate_per_host_burst,
        global_rate=settings.rate_global,
        global_burst=settings.rate_global_burst,
    )


def validate_finding(
    repo: Repository, finding: m.Finding, scope: Scope, settings: Settings,
    rate_limiter: RateLimiter | None = None,
) -> m.Finding:
    """Run validation for a finding currently in state 'new'. Advances it to
    validated->in_review, or rejected. Returns the refreshed finding.

    Pass a shared ``rate_limiter`` when validating many findings in one run
    (batch / auto-chain) so per-host buckets and 429 backoff carry across
    findings instead of resetting per finding. When omitted, a fresh limiter is
    built (the single-`ingest` behavior)."""
    assert finding.id is not None

    # new -> validating
    repo.transition(finding.id, m.VALIDATING, finding.confidence,
                    "validation started")

    validator = get_validator(finding.vuln_class)
    rl = rate_limiter or build_rate_limiter(settings)

    if validator is None:
        repo.transition(finding.id, m.REJECTED, 0.0,
                        f"no validator registered for vuln_class={finding.vuln_class!r}")
        return repo.get_finding(finding.id)  # type: ignore[return-value]

    with ScopedHttpClient(
        scope, rl, timeout=settings.http_timeout, user_agent=settings.user_agent
    ) as http:
        ctx = ValidatorContext(http=http, settings=settings)
        try:
            result = validator.validate(finding, ctx)
        except Exception as e:  # validator crash must not strand the finding
            repo.transition(
                finding.id, m.REJECTED, finding.confidence,
                f"validator error: {type(e).__name__}: {e}",
                evidence=[m.Evidence(finding.id, "error", {"error": str(e)})],
            )
            return repo.get_finding(finding.id)  # type: ignore[return-value]

    new_conf = max(0.0, min(1.0, finding.confidence + result.confidence_delta))
    target = sm.classify_after_validation(new_conf)
    reason = f"[{result.verdict}] {result.reason} (conf {finding.confidence:.2f} -> {new_conf:.2f})"

    repo.transition(finding.id, target, new_conf, reason, evidence=result.evidence)

    # validated auto-advances to in_review — the pipeline stops there, always.
    if target == m.VALIDATED:
        repo.transition(finding.id, m.IN_REVIEW, new_conf,
                        "confidence >= threshold; awaiting human review")

    return repo.get_finding(finding.id)  # type: ignore[return-value]
