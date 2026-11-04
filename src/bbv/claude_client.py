"""LLM-backed endpoint extraction for candidate generation.

This is the ONE reasoning step in this codebase: extracting candidate
endpoints/params from already-fetched JS. It supports multiple providers behind
a tiny interface (Anthropic, OpenAI, or any OpenAI-compatible self-hosted
endpoint such as Ollama/vLLM/LM Studio).

Whatever the provider, the model's output goes through the SAME pydantic
validation (candidate_schema) before anything touches disk: malformed output
from ANY provider is discarded and logged, never guessed at. The output is a
CANDIDATE only, with no trust bonus. The provider/model is recorded in the
candidate's provenance tag.

The provider endpoint is reasoning infrastructure, not a program target, so it
is deliberately NOT routed through ScopedHttpClient. API keys come from config
and are never logged.
"""
from __future__ import annotations

import json
import logging
from typing import Protocol

from .candidate_schema import RESPONSE_SCHEMA_HINT, ExtractionResult
from .config import Settings

log = logging.getLogger("bbv.llm")

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


# --------------------------------------------------------------------------
# Provider interface + implementations
# --------------------------------------------------------------------------
class LLMProvider(Protocol):
    def complete(self, prompt: str, *, system: str | None = None) -> str: ...


class AnthropicProvider:
    """Anthropic Messages API (via the anthropic SDK, already a dependency)."""

    def __init__(self, api_key: str, model: str, max_tokens: int):
        if not api_key:
            raise RuntimeError("provider=anthropic but BBV_ANTHROPIC_API_KEY is not set")
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(
            b.text for b in resp.content if getattr(b, "type", None) == "text"
        )


class OpenAIProvider:
    """OpenAI chat-completions API, implemented with plain httpx (already a
    dependency) so no extra SDK is needed. The same class covers any
    OpenAI-compatible self-hosted endpoint by overriding base_url; some such
    servers accept any (or no) API key."""

    def __init__(self, api_key: str, model: str, base_url: str, max_tokens: int):
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._max_tokens = max_tokens

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        import httpx

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        resp = httpx.post(
            f"{self._base_url}/chat/completions",
            json={"model": self._model, "max_tokens": self._max_tokens,
                  "messages": messages},
            headers=headers,
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"] or ""


def make_provider(settings: Settings) -> tuple[LLMProvider, str]:
    """Build the configured provider and a provenance tag like 'openai:gpt-4.1'.
    Raises RuntimeError with a clear message if a required secret/base_url is
    missing, so provider selection fails for the right reason."""
    p = (settings.llm_provider or "anthropic").strip().lower()
    if p == "anthropic":
        prov = AnthropicProvider(settings.anthropic_api_key, settings.anthropic_model,
                                 settings.anthropic_max_tokens)
        return prov, f"anthropic:{settings.anthropic_model}"
    if p in ("openai", "self_hosted"):
        base_url = settings.openai_base_url
        if p == "self_hosted" and not base_url:
            raise RuntimeError("provider=self_hosted but BBV_OPENAI_BASE_URL is not set")
        if p == "openai" and not settings.openai_api_key:
            raise RuntimeError("provider=openai but BBV_OPENAI_API_KEY is not set")
        base_url = base_url or "https://api.openai.com/v1"
        prov = OpenAIProvider(settings.openai_api_key, settings.openai_model, base_url,
                              settings.openai_max_tokens)
        return prov, f"{p}:{settings.openai_model}"
    raise RuntimeError(
        f"unknown BBV_LLM_PROVIDER {p!r} (expected anthropic | openai | self_hosted)")


# --------------------------------------------------------------------------
# Extractor: provider-agnostic. Builds the prompt, calls the provider, and runs
# the shared validation. Carries a provenance source_tag for candidate notes.
# --------------------------------------------------------------------------
class EndpointExtractor(Protocol):
    """Seam so candidate generation can be tested without a live API call."""

    source_tag: str

    def extract(self, js_text: str, source_hint: str) -> ExtractionResult: ...


class LLMExtractor:
    def __init__(self, provider: LLMProvider, source_tag: str):
        self._provider = provider
        self.source_tag = source_tag  # e.g. "ai-sourced:openai:gpt-4.1-mini"

    def extract(self, js_text: str, source_hint: str) -> ExtractionResult:
        user = (
            f"JS file source: {source_hint}\n\n"
            f"```javascript\n{js_text}\n```\n\n"
            "Return the JSON object now."
        )
        try:
            text = self._provider.complete(user, system=_SYSTEM)
        except Exception as e:  # network/auth/etc. — surface, do not fabricate
            log.warning("LLM provider call failed for %s (%s)", source_hint, e)
            raise
        return _parse_and_validate(text, source_hint)


def make_extractor(settings: Settings) -> LLMExtractor:
    """Factory: pick the provider from settings and wrap it in an extractor whose
    source_tag records provenance (provider:model)."""
    provider, tag = make_provider(settings)
    return LLMExtractor(provider, f"ai-sourced:{tag}")


class ReplayExtractor:
    """Returns a saved response instead of calling any provider. For offline
    demos and tests. Provider-agnostic: it bypasses the API entirely and runs
    the identical validation + conversion path."""

    source_tag = "ai-sourced:replay"

    def __init__(self, response_json: str, source_label: str = "replay"):
        self._result = _parse_and_validate(response_json, source_label)

    def extract(self, js_text: str, source_hint: str) -> ExtractionResult:
        return self._result


def _parse_and_validate(text: str, source_hint: str) -> ExtractionResult:
    """Parse model output into the validated schema. Malformed => empty result
    (logged), never a guess. Identical for every provider."""
    raw = _strip_code_fence(text).strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("LLM output for %s was not valid JSON (%s); discarding",
                    source_hint, e)
        return ExtractionResult()
    try:
        return ExtractionResult.model_validate(data)
    except Exception as e:  # pydantic ValidationError and friends
        log.warning("LLM output for %s failed schema validation (%s); discarding",
                    source_hint, e)
        return ExtractionResult()


def _strip_code_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines)
    return t
