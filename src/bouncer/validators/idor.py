"""IDOR validator.

Requires two authenticated sessions (A and B) from config, for the SAME
program. We replay A's request for B's object using A's session, and only call
it a real IDOR when THREE controls hold:

  1. A, using A's session, receives data that materially matches what B sees
     for B's object (A actually got B's data — not just a 200).
  2. That response materially DIFFERS from A's own object, proving the
     endpoint is object-specific (rules out an endpoint that returns the same
     thing for any id).
  3. An UNAUTHENTICATED request for B's object does NOT return B's data
     (rules out a public endpoint masquerading as IDOR).

Safe methods only (GET/HEAD): replay must never mutate target state.
"""
from __future__ import annotations

import difflib
import re
from typing import Any

from ..models import Evidence, Finding, ValidationResult
from .base import Validator, ValidatorContext

_SAFE = frozenset({"GET", "HEAD"})
_MATCH = 0.90      # >= => "materially matches"
_DIFFER = 0.90     # <  => "materially differs"


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def _build_url(template: str, object_id: str) -> str:
    if "{id}" in template:
        return template.replace("{id}", str(object_id))
    return template.rstrip("/") + "/" + str(object_id)


class IdorValidator(Validator):
    vuln_class = "idor"

    def validate(self, finding: Finding, ctx: ValidatorContext) -> ValidationResult:
        req = finding.request
        method = (req.get("method") or "GET").upper()
        if method not in _SAFE:
            return ValidationResult(
                -0.3, ValidationResult.REFUTED,
                f"refusing IDOR replay with unsafe method {method}; "
                "only GET/HEAD are permitted (no state changes)",
            )

        template = req.get("url_template") or finding.target_url
        id_a = req.get("object_id_a")
        id_b = req.get("object_id_b")
        if not id_a or not id_b:
            return ValidationResult(
                -0.1, ValidationResult.INCONCLUSIVE,
                "finding.request must provide object_id_a and object_id_b",
            )

        sess_a = ctx.settings.idor_session_a
        sess_b = ctx.settings.idor_session_b
        if not sess_a or not sess_b:
            return ValidationResult(
                0.0, ValidationResult.INCONCLUSIVE,
                "IDOR needs two configured sessions (BOUNCER_IDOR_SESSION_A/B); "
                "none provided, cannot validate",
            )

        url_a = _build_url(template, id_a)
        url_b = _build_url(template, id_b)

        r_a_self = ctx.http.request(method, url_a, headers=sess_a)      # A sees A
        r_a_on_b = ctx.http.request(method, url_b, headers=sess_a)      # A attacks B
        r_b_self = ctx.http.request(method, url_b, headers=sess_b)      # ground truth
        r_unauth = ctx.http.request(method, url_b)                       # public?

        match_ab = _ratio(r_a_on_b.text, r_b_self.text)
        diff_self = _ratio(r_a_on_b.text, r_a_self.text)
        public_leak = _ratio(r_unauth.text, r_b_self.text)

        evidence = [Evidence(finding.id or 0, "idor_match", {
            "url_a": url_a, "url_b": url_b,
            "status_a_self": r_a_self.status_code,
            "status_a_on_b": r_a_on_b.status_code,
            "status_b_self": r_b_self.status_code,
            "status_unauth": r_unauth.status_code,
            "match_a_on_b_vs_b_self": round(match_ab, 3),
            "diff_a_on_b_vs_a_self": round(diff_self, 3),
            "unauth_vs_b_self": round(public_leak, 3),
            "thresholds": {"match": _MATCH, "differ": _DIFFER},
        })]

        got_bs_data = r_a_on_b.status_code == 200 and match_ab >= _MATCH
        object_specific = diff_self < _DIFFER
        is_public = r_unauth.status_code == 200 and public_leak >= _MATCH

        if is_public:
            return ValidationResult(
                -0.2, ValidationResult.REFUTED,
                f"object is publicly accessible (unauth matched B's data "
                f"at {public_leak:.2f}); not an IDOR", evidence,
            )
        if not object_specific:
            return ValidationResult(
                -0.2, ValidationResult.REFUTED,
                f"endpoint returns the same content regardless of id "
                f"(A-on-B vs A-self similarity {diff_self:.2f}); not object-specific",
                evidence,
            )
        if not got_bs_data:
            return ValidationResult(
                -0.1, ValidationResult.REFUTED,
                f"A did not obtain B's object data (status {r_a_on_b.status_code}, "
                f"similarity {match_ab:.2f} < {_MATCH}); a bare 200 is not evidence",
                evidence,
            )

        return ValidationResult(
            0.6, ValidationResult.CONFIRMED,
            f"A retrieved B's object data (match {match_ab:.2f}), endpoint is "
            f"object-specific (self-diff {diff_self:.2f}), and it is not public",
            evidence,
        )
