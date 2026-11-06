"""Reporter contract + deterministic fact assembly shared by all formatters.

Every fact in a report is assembled HERE from the finding/evidence/transitions
rows in SQLite. Formatters only render these facts into a platform's layout;
they never introduce new technical claims. No LLM is involved in this path.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .. import models as m
from ..severity import Assessment, assess


@dataclass
class ReportFacts:
    finding: m.Finding
    assessment: Assessment
    evidence: list[m.Evidence]
    transitions: list[m.Transition]
    title: str
    summary: str
    steps: list[str]
    impact: str


def _by_kind(evidence: list[m.Evidence]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for ev in evidence:
        out[ev.kind] = ev.data
    return out


def build_facts(
    finding: m.Finding, evidence: list[m.Evidence], transitions: list[m.Transition]
) -> ReportFacts:
    assessment = assess(finding, evidence)
    title, summary, steps, impact = _narrative(finding, evidence)
    return ReportFacts(
        finding=finding, assessment=assessment, evidence=evidence,
        transitions=transitions, title=title, summary=summary, steps=steps,
        impact=impact,
    )


def _narrative(finding: m.Finding, evidence: list[m.Evidence]):
    vc = finding.vuln_class
    if vc == "reflected_xss":
        return _xss(finding, evidence)
    if vc == "idor":
        return _idor(finding, evidence)
    if vc == "sqli_boolean":
        return _sqli(finding, evidence)
    return (
        f"{vc} on {finding.target_url}",
        f"A {vc} finding was recorded for {finding.target_url}.",
        ["See the evidence appendix."],
        "See the evidence appendix; no class-specific impact template exists.",
    )


def _xss(finding, evidence):
    by = _by_kind(evidence)
    # The reflection evidence is split across two canary_reflection rows: the
    # first carries {url, marker, reflected}, the second {context, raw_special_chars}.
    # Collect each field from whichever row has it (do NOT rely on last-write-wins).
    ctx = None
    probe_url = finding.target_url
    marker = ""
    for ev in evidence:
        if ev.kind == "canary_reflection":
            if ev.data.get("url"):
                probe_url = ev.data["url"]
            if ev.data.get("marker"):
                marker = ev.data["marker"]
            if "context" in ev.data:
                ctx = ev.data["context"]
    bx = by.get("browser_exec", {})
    param = (finding.request or {}).get("inject_param", "the parameter")

    title = f"Reflected Cross-Site Scripting in `{param}` on {finding.target_url}"
    summary = (
        f"The `{param}` parameter at {finding.target_url} reflects attacker input "
        f"into a `{ctx}` context and executes it as JavaScript in the victim's "
        "browser. Execution was confirmed with a benign marker payload."
    )
    steps = [
        f"Send a GET request with a unique canary in `{param}`:\n   `{probe_url}`",
        f"Observe the canary `{marker}` reflected into a **{ctx}** context in the "
        "response (special characters are not encoded).",
    ]
    if bx.get("status") == "confirmed":
        steps.append(
            f"Load the proof URL in a browser:\n   `{bx.get('url')}`\n   "
            f"The benign payload `{bx.get('payload')}` runs and sets "
            f"`window.{bx.get('marker_attr')}`, confirming JavaScript execution "
            "(no alert/cookie access — a marker only)."
        )
    impact = (
        "An attacker who gets a victim to open the crafted URL can execute "
        "arbitrary JavaScript in the victim's session on this origin (confirmed "
        "execution via a benign window-marker payload). This enables actions in "
        "the victim's browser context such as reading page content or performing "
        "authenticated requests as the victim. Only confirmed execution is claimed; "
        "no data was exfiltrated during validation."
    )
    return title, summary, steps, impact


def _idor(finding, evidence):
    by = _by_kind(evidence)
    d = by.get("idor_match", {})
    req = finding.request or {}
    title = f"Insecure Direct Object Reference on {_endpoint(d, finding)}"
    summary = (
        f"The endpoint {_endpoint(d, finding)} exposes objects by a user-controlled "
        "identifier without enforcing ownership. Account A was able to read account "
        "B's object by substituting B's object id into A's own authenticated request."
    )
    steps = [
        f"As account A, request your own object:\n   `{d.get('url_a')}` "
        f"(HTTP {d.get('status_a_self')}).",
        f"As account A (A's session), request account B's object id:\n   "
        f"`{d.get('url_b')}` (HTTP {d.get('status_a_on_b')}). The response matches "
        f"what B sees for that object (similarity {d.get('match_a_on_b_vs_b_self')} "
        f">= {(_th(d)).get('match')}), and differs from A's own object "
        f"(similarity {d.get('diff_a_on_b_vs_a_self')}), confirming the endpoint is "
        "object-specific.",
        f"Confirm the object is not public: an unauthenticated request to "
        f"`{d.get('url_b')}` returns HTTP {d.get('status_unauth')} "
        f"(similarity to B's data {d.get('unauth_vs_b_self')}).",
    ]
    impact = (
        "An authenticated user can read other users' objects at this endpoint by "
        "changing the object identifier. Evidence demonstrates cross-user read of "
        f"the object data returned by {_endpoint(d, finding)}; unauthenticated "
        f"access is denied (HTTP {d.get('status_unauth')}), so this is an "
        "authorization flaw rather than public data. No modification was attempted "
        "(replay was restricted to GET/HEAD); impact beyond read is not claimed."
    )
    return title, summary, steps, impact


def _sqli(finding, evidence):
    by = _by_kind(evidence)
    d = by.get("sqli_differential", {})
    req = finding.request or {}
    param = req.get("inject_param", "the parameter")
    title = f"Boolean-based SQL Injection in `{param}` on {finding.target_url}"
    summary = (
        f"The `{param}` parameter at {finding.target_url} is injectable: a boolean "
        "TRUE condition and a boolean FALSE condition produce reliably different "
        "responses, giving an attacker a boolean oracle over the backing database."
    )
    steps = [
        f"Establish a baseline with `{param}={req.get('base_value')}` and confirm it "
        f"is stable across repeats (self-similarity {d.get('base_stability')}).",
        f"Send the TRUE condition `{param}={d.get('true_payload')}`: the response "
        f"matches the baseline across all repeats (similarities {d.get('true_sims')}).",
        f"Send the FALSE condition `{param}={d.get('false_payload')}`: the response "
        f"differs from the baseline across all repeats (similarities {d.get('false_sims')}).",
        "The stable TRUE/FALSE divergence confirms a boolean injection oracle.",
    ]
    impact = (
        "The confirmed boolean oracle lets an attacker extract database contents "
        "bit-by-bit by asking true/false questions through the injection point. "
        "Validation used only benign boolean tautologies; no data was exfiltrated "
        "and no write/time-based payloads were sent, so data modification and "
        "denial-of-service are not claimed here."
    )
    return title, summary, steps, impact


def _endpoint(d: dict, finding) -> str:
    return (finding.request or {}).get("url_template") or finding.target_url


def _th(d: dict) -> dict:
    return d.get("thresholds", {}) or {}


class Reporter(ABC):
    """One per platform. Renders assembled facts into a platform layout."""

    platform: str = ""

    @abstractmethod
    def render(self, facts: ReportFacts) -> str:
        ...
