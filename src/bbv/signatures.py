"""Deterministic false-positive signature extraction (ADVISORY ONLY).

A signature is a canonical fingerprint of WHY a finding was rejected, derived
purely from the structured evidence the validators already emit. No LLM, no
embeddings, no fuzzy similarity: same underlying cause -> same string, always.

This layer never gates, skips, or alters validation. It only makes repetition
visible for human triage. See README for the reasoning.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from . import models as m

SCOPE_GLOBAL = "global"
SCOPE_PROGRAM = "program"


@dataclass
class Signature:
    vuln_class: str
    feature_key: str
    scope: str                 # SCOPE_GLOBAL | SCOPE_PROGRAM
    example_evidence: dict[str, Any]
    # endpoint is filled by the caller (from the finding's target_url) when
    # scope == program; the extractor itself doesn't need the URL.


def _evidence_by_kind(evidence: list[m.Evidence]) -> dict[str, dict[str, Any]]:
    """Last-write-wins map of evidence kind -> data (validators may append
    several entries of the same kind; the later ones are the refined ones)."""
    out: dict[str, dict[str, Any]] = {}
    for ev in evidence:
        out[ev.kind] = ev.data
    return out


def extract(vuln_class: str, evidence: list[m.Evidence]) -> Signature | None:
    """Return a deterministic signature for a rejection, or None when no stable
    fingerprint can be derived (e.g. a validator crash, or operator-input errors
    with no structured evidence). None => no signature is recorded."""
    if vuln_class == "reflected_xss":
        return _extract_xss(evidence)
    if vuln_class == "idor":
        return _extract_idor(evidence)
    if vuln_class == "sqli_boolean":
        return _extract_sqli(evidence)
    return None


def _extract_xss(evidence: list[m.Evidence]) -> Signature | None:
    by = _evidence_by_kind(evidence)
    refl = by.get("canary_reflection", {})
    # The first reflection evidence carries {reflected: bool}; a later one carries
    # {context, raw_special_chars}. Merge what we have.
    reflected = None
    context = None
    raw = None
    for ev in evidence:
        if ev.kind == "canary_reflection":
            if "reflected" in ev.data:
                reflected = ev.data["reflected"]
            if "context" in ev.data:
                context = ev.data["context"]
            if "raw_special_chars" in ev.data:
                raw = ev.data["raw_special_chars"]

    if reflected is False:
        return Signature("reflected_xss", "xss|not_reflected", SCOPE_GLOBAL,
                         {"reflected": False})
    if context is not None:
        # Non-executable reflection is a general web-behavior pattern -> global.
        key = f"xss|reflected|context={context}|raw={_b(raw)}"
        # If a browser check ran and did not confirm, include that (distinct cause).
        bx = by.get("browser_exec", {})
        if bx.get("status") in {"not_executed"}:
            key += "|browser=not_executed"
        return Signature("reflected_xss", key, SCOPE_GLOBAL,
                         {"context": context, "raw_special_chars": raw,
                          **({"browser": bx.get("status")} if bx else {})})
    return None


def _extract_idor(evidence: list[m.Evidence]) -> Signature | None:
    by = _evidence_by_kind(evidence)
    d = by.get("idor_match")
    if not d:
        return None
    th = d.get("thresholds", {})
    match_th = th.get("match", 0.9)
    differ_th = th.get("differ", 0.9)

    match_ab = d.get("match_a_on_b_vs_b_self", 0.0)
    diff_self = d.get("diff_a_on_b_vs_a_self", 0.0)
    unauth = d.get("unauth_vs_b_self", 0.0)
    status_unauth = d.get("status_unauth")
    status_a_on_b = d.get("status_a_on_b")

    # Mirror the validator's own priority so the fingerprint names the real cause.
    if status_unauth == 200 and unauth >= match_th:
        return Signature("idor", "idor|public_endpoint", SCOPE_PROGRAM,
                         {"unauth_vs_b_self": unauth, "status_unauth": status_unauth})
    if diff_self >= differ_th:
        return Signature("idor", "idor|not_object_specific", SCOPE_PROGRAM,
                         {"diff_a_on_b_vs_a_self": diff_self})
    if status_a_on_b != 200 or match_ab < match_th:
        return Signature("idor", "idor|no_cross_user_data", SCOPE_GLOBAL,
                         {"match_a_on_b_vs_b_self": match_ab, "status_a_on_b": status_a_on_b})
    return None


def _extract_sqli(evidence: list[m.Evidence]) -> Signature | None:
    by = _evidence_by_kind(evidence)
    d = by.get("sqli_differential")
    if not d:
        return None
    th = d.get("thresholds", {})
    stable_th = th.get("stable", 0.98)
    base_stability = d.get("base_stability")

    # Baseline-unstable rejections never reach the differential stage, so their
    # evidence lacks true_sims and base_stability is below the threshold.
    if base_stability is not None and base_stability < stable_th:
        return Signature("sqli_boolean", "sqli|baseline_unstable", SCOPE_GLOBAL,
                         {"base_stability": base_stability})
    # Reached the repeated differential stage but it did not hold -> this endpoint
    # does not respond to the boolean condition. Program/endpoint specific.
    return Signature("sqli_boolean", "sqli|differential_unstable", SCOPE_PROGRAM,
                     {"true_sims": d.get("true_sims"), "false_sims": d.get("false_sims")})


def normalize_endpoint(url: str) -> str:
    """Canonical host+path for program-scoped signatures: lowercase host, drop
    query/fragment, and collapse trailing numeric path segments to {n} so
    /api/orders/1001 and /api/orders/1002 fingerprint as the same endpoint.
    Deterministic — no fuzzy matching."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.port:
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    path = re.sub(r"/\d+(?=/|$)", "/{n}", path)
    return f"{host}{path}"


def _b(v: Any) -> str:
    return "true" if v is True else "false" if v is False else str(v)
