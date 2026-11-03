"""Claude API client for the ONE reasoning step in this codebase: extracting
candidate endpoints/params from already-fetched JS.

This talks to api.anthropic.com, which is reasoning infrastructure, not a
program target — so it does NOT (and must not) route through ScopedHttpClient.
The API key comes from config and is never logged.
"""
from __future__ import annotations

import json
import logging
from typing import Protocol

from .candidate_schema import RESPONSE_SCHEMA_HINT, ExtractionResult
from .config import Settings

log = logging.getLogger("bbv.claude")

_SYSTEM = (
    "You are a security recon assistant for an AUTHORIZED bug bounty engagement. "
    "You are given the text of a JavaScript file already fetched from an in-scope "
    "host. Extract API endpoints and parameters that are interesting for "
    "authorization/injection testing. Pay attention to parameters that look like "
    "object identifiers (user_id, account, order_id, numeric/sequential ids) and "
    "routes that look auth/authz-relevant. You do NOT attempt any exploit; you "
    "only read and report. Respond with ONLY a JSON object, no prose, no code "
    "fences, matching exactly this shape:\n" + RESPONSE_SCHEMA_HINT
)


class EndpointExtractor(Protocol):
    """Seam so candidate generation can be tested without a live API call."""

    def extract(self, js_text: str, source_hint: str) -> ExtractionResult: ...


class ClaudeExtractor:
    """Real implementation backed by the anthropic SDK."""

    def __init__(self, settings: Settings):
        if not settings.anthropic_api_key:
            raise RuntimeError(
                "BBV_ANTHROPIC_API_KEY is not set; cannot run Claude extraction"
            )
        # Imported lazily so the dependency isn't required for non-AI commands.
        import anthropic

        self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        self._model = settings.anthropic_model
        self._max_tokens = settings.anthropic_max_tokens

    def extract(self, js_text: str, source_hint: str) -> ExtractionResult:
        # One narrowly-scoped prompt per JS file (chunked by the caller).
        user = (
            f"JS file source: {source_hint}\n\n"
            f"```javascript\n{js_text}\n```\n\n"
            "Return the JSON object now."
        )
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=_SYSTEM,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(
            block.text for block in resp.content if getattr(block, "type", None) == "text"
        )
        return _parse_and_validate(text, source_hint)


class ReplayExtractor:
    """Returns a saved Claude JSON response instead of calling the API. For
    offline demos and tests ONLY — it replays a real response shape through the
    identical validation + conversion path; it is not a heuristic substitute for
    Claude in the product flow."""

    def __init__(self, response_json: str, source_label: str = "replay"):
        self._result = _parse_and_validate(response_json, source_label)

    def extract(self, js_text: str, source_hint: str) -> ExtractionResult:
        return self._result


def _parse_and_validate(text: str, source_hint: str) -> ExtractionResult:
    """Parse Claude's text into the validated schema. Malformed => empty result
    (logged), never a guess."""
    raw = _strip_code_fence(text).strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("Claude output for %s was not valid JSON (%s); discarding",
                    source_hint, e)
        return ExtractionResult()
    try:
        return ExtractionResult.model_validate(data)
    except Exception as e:  # pydantic ValidationError and friends
        log.warning("Claude output for %s failed schema validation (%s); discarding",
                    source_hint, e)
        return ExtractionResult()


def _strip_code_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        # drop opening fence (``` or ```json) and trailing fence
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines)
    return t
