"""Candidate generation: raw asset -> well-formed candidate finding JSON.

This module's ONLY job is to turn Claude's reasoning over already-fetched JS
into finding JSON in the EXACT milestone-1 schema. It does NOT call any
validator, does NOT touch finding state, and does NOT ingest anything. Handoff
to validation is the separate, manual `ingest` step — nothing reaches the gate
without the operator choosing to run it.

Every candidate is just that: a candidate. It seeds at confidence 0.3 like any
other (the lifecycle enforces that at ingest). AI-sourced candidates are tagged
in `notes` as useful signal, but get no trust bonus.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .candidate_schema import ExtractedEndpoint, ExtractionResult
from .claude_client import EndpointExtractor
from .scope import Scope

log = logging.getLogger("bbv.candidates")

AI_SOURCE_TAG = "ai-sourced:claude"


@dataclass
class JsInput:
    """A JS file to reason over, plus the base URL it was fetched from (used to
    resolve root-relative endpoints)."""

    source_url: str
    base_url: str
    text: str


def _set_query_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit(parts._replace(query=urlencode(q)))


def _pick_inject_param(ep: ExtractedEndpoint) -> str | None:
    # Prefer a non-id param for reflection/injection; fall back to any param.
    non_id = [p for p in ep.params if p not in ep.id_like_params]
    if non_id:
        return non_id[0]
    return ep.params[0] if ep.params else None


class CandidateGenerator:
    def __init__(self, program: str, scope: Scope, extractor: EndpointExtractor):
        self.program = program
        self.scope = scope
        self.extractor = extractor

    def generate(self, js_inputs: list[JsInput]) -> list[dict]:
        """Return candidate finding dicts (also the thing written to disk)."""
        candidates: list[dict] = []
        for js in js_inputs:
            result = self.extractor.extract(js.text, js.source_url)
            candidates.extend(self._result_to_candidates(result, js))
        return candidates

    def _result_to_candidates(
        self, result: ExtractionResult, js: JsInput
    ) -> list[dict]:
        out: list[dict] = []
        for ep in result.endpoints:
            abs_url = urljoin(js.base_url, ep.url)
            # Scope gate: never emit a candidate for an out-of-scope endpoint.
            if not self.scope.is_allowed(abs_url):
                log.info("skipping out-of-scope endpoint from %s: %s",
                         js.source_url, abs_url)
                continue
            cand = self._to_candidate(ep, abs_url, js.source_url)
            if cand is not None:
                out.append(cand)
        return out

    def _to_candidate(
        self, ep: ExtractedEndpoint, abs_url: str, source_js: str
    ) -> dict | None:
        vc = ep.suspected_vuln_class
        note = (f"{AI_SOURCE_TAG}; from JS {source_js}; "
                f"reasoning: {ep.reasoning or 'n/a'}")

        if vc == "reflected_xss":
            param = _pick_inject_param(ep)
            if not param:
                log.info("reflected_xss endpoint %s has no params; skipping", abs_url)
                return None
            return {
                "program": self.program,
                "vuln_class": "reflected_xss",
                "target_url": _set_query_param(abs_url, param, "bbvseed"),
                "request": {"method": "GET", "inject_param": param},
                "notes": note,
            }

        if vc == "sqli_boolean":
            param = _pick_inject_param(ep)
            if not param:
                log.info("sqli_boolean endpoint %s has no params; skipping", abs_url)
                return None
            return {
                "program": self.program,
                "vuln_class": "sqli_boolean",
                "target_url": _set_query_param(abs_url, param, "1"),
                "request": {
                    "method": "GET", "inject_param": param, "base_value": "1",
                    "true_payload": "1 AND 1=1", "false_payload": "1 AND 1=2",
                    "repeats": 3,
                },
                "notes": note,
            }

        if vc == "idor":
            id_param = ep.id_like_params[0] if ep.id_like_params else None
            if not id_param:
                log.info("idor endpoint %s has no id-like param; skipping", abs_url)
                return None
            # Build a url_template with the id param as a {id} placeholder.
            # Use an alnum sentinel first so the placeholder isn't percent-encoded
            # by urlencode, then swap it in (the idor validator does a literal
            # "{id}" replace).
            template = _set_query_param(abs_url, id_param, "BBVIDPLACEHOLDER").replace(
                "BBVIDPLACEHOLDER", "{id}")
            return {
                "program": self.program,
                "vuln_class": "idor",
                "target_url": _set_query_param(abs_url, id_param, "REPLACE_A"),
                "request": {
                    "method": "GET",
                    "url_template": template,
                    "object_id_a": "REPLACE_A",
                    "object_id_b": "REPLACE_B",
                },
                "notes": (note + "; REVIEW REQUIRED: fill object_id_a/b with real "
                          "ids you own for accounts A and B, and set "
                          "BBV_IDOR_SESSION_A/B before ingest."),
            }

        log.info("endpoint %s classed 'unknown'; not emitting a candidate", abs_url)
        return None


def write_candidates(candidates: list[dict], out_dir: str | Path) -> list[Path]:
    """Write each candidate to its own JSON file. Returns the paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for i, cand in enumerate(candidates, start=1):
        name = f"{cand['program']}_{i:03d}_{cand['vuln_class']}.json"
        path = out / name
        path.write_text(json.dumps(cand, indent=2), encoding="utf-8")
        paths.append(path)
    return paths
