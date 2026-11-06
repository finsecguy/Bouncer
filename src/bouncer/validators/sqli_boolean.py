"""Boolean-based SQLi validator.

Sends a TRUE-condition and a FALSE-condition payload and confirms a stable
differential: the TRUE response matches the baseline, the FALSE response
differs, and this holds across repeats (ruling out jitter). The baseline is
fetched twice first; if the baseline is not stable against itself, we bail as
inconclusive rather than report noise.

Benign only: payloads must be boolean tautologies. Stacked queries, UNION, and
time-based payloads are refused — they are unnecessary for a differential and
risk altering or stressing the target.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Evidence, Finding, ValidationResult
from .base import Validator, ValidatorContext

_STABLE = 0.98   # baseline-vs-baseline must be at least this similar
_MATCH = 0.97    # TRUE vs baseline
_DIFFER = 0.95   # FALSE vs baseline must be below this

_FORBIDDEN = re.compile(
    r"(;|\bUNION\b|\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bPG_SLEEP\s*\(|\bWAITFOR\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    t = text or ""
    # Strip common dynamic tokens so "differs" is meaningful, not noise.
    t = re.sub(r'(?i)(csrf[_-]?token|authenticity_token)["\']?\s*[:=]\s*["\']?[\w\-+/=]+', "", t)
    t = re.sub(r"\b[0-9a-f]{16,}\b", "", t, flags=re.IGNORECASE)      # long hex nonces
    t = re.sub(r"\b\d{10,13}\b", "", t)                                # epoch timestamps
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _ratio(a: str, b: str) -> float:
    import difflib
    return difflib.SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()


def _inject(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit(parts._replace(query=urlencode(q)))


class SqliBooleanValidator(Validator):
    vuln_class = "sqli_boolean"

    def validate(self, finding: Finding, ctx: ValidatorContext) -> ValidationResult:
        req = finding.request
        param = req.get("inject_param")
        base_value = str(req.get("base_value", ""))
        true_payload = req.get("true_payload")
        false_payload = req.get("false_payload")
        repeats = int(req.get("repeats", 3))

        if not param or not true_payload or not false_payload:
            return ValidationResult(
                -0.1, ValidationResult.INCONCLUSIVE,
                "finding.request needs inject_param, true_payload, false_payload",
            )

        for label, payload in (("true", true_payload), ("false", false_payload)):
            if _FORBIDDEN.search(payload):
                return ValidationResult(
                    -0.3, ValidationResult.REFUTED,
                    f"refusing non-benign {label}_payload "
                    f"(stacked/UNION/time-based/DML not permitted): {payload!r}",
                )

        base_url = _inject(finding.target_url, param, base_value)
        true_url = _inject(finding.target_url, param, str(true_payload))
        false_url = _inject(finding.target_url, param, str(false_payload))

        # 1) baseline stability.
        b1 = ctx.http.get(base_url).text
        b2 = ctx.http.get(base_url).text
        base_stability = _ratio(b1, b2)
        if base_stability < _STABLE:
            return ValidationResult(
                0.0, ValidationResult.INCONCLUSIVE,
                f"baseline is not stable against itself ({base_stability:.3f} < "
                f"{_STABLE}); response jitter makes a differential unreliable",
                [Evidence(finding.id or 0, "sqli_differential",
                          {"base_stability": round(base_stability, 3)})],
            )

        # 2) repeated differential.
        true_sims, false_sims = [], []
        for _ in range(max(1, repeats)):
            t = ctx.http.get(true_url).text
            f = ctx.http.get(false_url).text
            true_sims.append(_ratio(b1, t))
            false_sims.append(_ratio(b1, f))

        true_ok = all(s >= _MATCH for s in true_sims)
        false_ok = all(s < _DIFFER for s in false_sims)

        evidence = [Evidence(finding.id or 0, "sqli_differential", {
            "base_stability": round(base_stability, 3),
            "true_sims": [round(s, 3) for s in true_sims],
            "false_sims": [round(s, 3) for s in false_sims],
            "thresholds": {"stable": _STABLE, "match": _MATCH, "differ": _DIFFER},
            "true_payload": true_payload, "false_payload": false_payload,
        })]

        if true_ok and false_ok:
            return ValidationResult(
                0.6, ValidationResult.CONFIRMED,
                "stable boolean differential: TRUE matches baseline, FALSE "
                "differs, across all repeats", evidence,
            )
        return ValidationResult(
            -0.15, ValidationResult.REFUTED,
            f"no stable boolean differential (true_ok={true_ok}, "
            f"false_ok={false_ok}); not a confirmed boolean SQLi", evidence,
        )
