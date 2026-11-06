"""Deterministic CVSS 3.1 / CWE assessment.

Severity is derived ONLY from the structured evidence a finding already carries
in SQLite — never from an LLM, never from "vibes". Each metric choice is
recorded in `metric_reasoning` so the whole assessment is auditable rather than
a black box. We deliberately score conservatively: where the evidence does not
establish something (e.g. the sensitivity of data exposed by an IDOR), we do
NOT inflate the metric, and we say so in the reasoning.

The CVSS 3.1 base-score formula and roundup are implemented here directly (no
third-party dependency) per the official specification.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from . import models as m

# --- CVSS 3.1 metric weights ---
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

_CWE_NAMES = {
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
}


@dataclass
class Assessment:
    cwe_id: str
    cwe_name: str
    cvss_vector: str
    cvss_score: float
    severity: str
    metrics: dict[str, str]
    metric_reasoning: dict[str, str] = field(default_factory=dict)


def _roundup(x: float) -> float:
    """Official CVSS 3.1 roundup (avoids binary float artefacts)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def _severity_rating(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def compute_base_score(mt: dict[str, str]) -> float:
    """CVSS 3.1 base score from a metrics dict with keys AV,AC,PR,UI,S,C,I,A."""
    scope_changed = mt["S"] == "C"
    c, i, a = _CIA[mt["C"]], _CIA[mt["I"]], _CIA[mt["A"]]
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[mt["PR"]]
    exploitability = 8.22 * _AV[mt["AV"]] * _AC[mt["AC"]] * pr * _UI[mt["UI"]]

    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def vector_string(mt: dict[str, str]) -> str:
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    return "CVSS:3.1/" + "/".join(f"{k}:{mt[k]}" for k in order)


def _evidence_by_kind(evidence: list[m.Evidence]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for ev in evidence:
        out[ev.kind] = ev.data
    return out


def assess(finding: m.Finding, evidence: list[m.Evidence]) -> Assessment:
    """Return a deterministic CVSS/CWE assessment for an approved finding."""
    vc = finding.vuln_class
    if vc == "reflected_xss":
        return _assess_xss(finding, evidence)
    if vc == "idor":
        return _assess_idor(finding, evidence)
    if vc == "sqli_boolean":
        return _assess_sqli(finding, evidence)
    # Unknown class: no inflation, minimal informational assessment.
    mt = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
    return _finish("CWE-0", mt, {"note": f"no mapping for vuln_class {vc!r}"})


def _finish(cwe: str, mt: dict[str, str], reasoning: dict[str, str]) -> Assessment:
    score = compute_base_score(mt)
    return Assessment(
        cwe_id=cwe, cwe_name=_CWE_NAMES.get(cwe, "Unmapped"),
        cvss_vector=vector_string(mt), cvss_score=score,
        severity=_severity_rating(score), metrics=mt, metric_reasoning=reasoning,
    )


def _assess_xss(finding: m.Finding, evidence: list[m.Evidence]) -> Assessment:
    by = _evidence_by_kind(evidence)
    confirmed = by.get("browser_exec", {}).get("status") == "confirmed"
    mt = {
        "AV": "N",  # delivered over the web
        "AC": "L",  # no special conditions to land the payload
        "PR": "N",  # attacker needs no account to craft the malicious URL
        "UI": "R",  # a victim must open the crafted URL
        "S": "C",   # script runs in the victim's browser authority (scope change)
        "C": "L" if confirmed else "N",
        "I": "L" if confirmed else "N",
        "A": "N",   # no availability impact demonstrated
    }
    reasoning = {
        "AV": "Reflected XSS is delivered via an HTTP(S) URL -> Network.",
        "AC": "The canary reflected and executed with no preconditions -> Low.",
        "PR": "Crafting the URL requires no account on the target -> None.",
        "UI": "Exploitation requires a victim to load the crafted URL -> Required.",
        "S": "JavaScript executes in the victim's browser security authority -> Changed.",
        "C/I": ("Confirmed browser execution (browser_exec.status=confirmed) can read/"
                "alter page content in the victim context -> Low/Low."
                if confirmed else
                "Execution was NOT confirmed by the browser evidence -> None/None."),
        "A": "No availability impact was demonstrated -> None.",
    }
    return _finish("CWE-79", mt, reasoning)


def _assess_idor(finding: m.Finding, evidence: list[m.Evidence]) -> Assessment:
    by = _evidence_by_kind(evidence)
    d = by.get("idor_match", {})
    status_unauth = d.get("status_unauth")
    # If unauthenticated access is denied, an account is required => PR:L.
    requires_account = status_unauth != 200
    mt = {
        "AV": "N",
        "AC": "L",
        "PR": "L" if requires_account else "N",
        "UI": "N",   # no victim interaction; attacker acts directly
        "S": "U",
        "C": "L",    # cross-user object read; see reasoning (deliberately not High)
        "I": "N",    # replay restricted to GET/HEAD; no modification demonstrated
        "A": "N",
    }
    reasoning = {
        "AV": "The endpoint is reached over the network -> Network.",
        "AC": "Substituting another user's object id is reliable -> Low.",
        "PR": (f"Unauthenticated access returned HTTP {status_unauth}, so a valid "
               "account is required to exploit -> Low." if requires_account else
               "Unauthenticated access returned the data -> None (note: the "
               "validator rejects truly public endpoints, so this should not occur)."),
        "UI": "The attacker performs the request directly; no victim action -> None.",
        "S": "Impact stays within the vulnerable application's authority -> Unchanged.",
        "C": ("Evidence shows account A read account B's object "
              f"(similarity {d.get('match_a_on_b_vs_b_self')}). The SENSITIVITY of "
              "that data is not quantified by the evidence, so Confidentiality is "
              "set to Low rather than High to avoid overclaiming. Raise manually if "
              "the exposed records are sensitive."),
        "I": "Replay is restricted to GET/HEAD; no data modification was attempted "
             "or shown -> None.",
        "A": "No availability impact was demonstrated -> None.",
    }
    return _finish("CWE-639", mt, reasoning)


def _assess_sqli(finding: m.Finding, evidence: list[m.Evidence]) -> Assessment:
    # PR is read from whether the validated request carried credentials, rather
    # than assumed. (Our request shape has no auth headers by default.)
    req = finding.request or {}
    headers = {k.lower() for k in (req.get("headers") or {})}
    carried_creds = bool(headers & {"cookie", "authorization"})
    mt = {
        "AV": "N",
        "AC": "L",
        "PR": "L" if carried_creds else "N",
        "UI": "N",
        "S": "U",
        "C": "H",    # a confirmed boolean oracle is a proven extraction primitive
        "I": "N",    # no write/UPDATE/DELETE demonstrated (benign tautologies only)
        "A": "N",    # no time-based/DoS payloads used
    }
    reasoning = {
        "AV": "The injection point is an HTTP parameter -> Network.",
        "AC": "The boolean differential held stably across repeats -> Low.",
        "PR": ("The validated request carried credentials (Cookie/Authorization) "
               "-> Low." if carried_creds else
               "The validated request carried no credentials -> None."),
        "UI": "The attacker injects directly; no victim action -> None.",
        "S": "Impact stays within the database/application authority -> Unchanged.",
        "C": ("A confirmed, stable boolean oracle (TRUE matches baseline, FALSE "
              "differs across repeats) is a proven bit-by-bit data-extraction "
              "primitive -> High."),
        "I": "Only benign boolean tautologies were sent; no write was demonstrated "
             "-> None.",
        "A": "No time-based or resource-exhausting payloads were used -> None.",
    }
    return _finish("CWE-89", mt, reasoning)
