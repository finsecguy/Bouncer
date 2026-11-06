"""Pydantic schema for Claude's JS-analysis output. Claude's response is
validated against this BEFORE anything is written to disk; malformed output is
rejected and logged, never guessed-at."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# The only vuln classes milestone-1 validators understand, plus 'unknown'.
SuspectedVulnClass = Literal["reflected_xss", "idor", "sqli_boolean", "unknown"]


class ExtractedEndpoint(BaseModel):
    model_config = {"extra": "ignore"}

    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    id_like_params: list[str] = Field(default_factory=list)
    suspected_vuln_class: SuspectedVulnClass = "unknown"
    reasoning: str = ""


class ExtractionResult(BaseModel):
    model_config = {"extra": "ignore"}

    endpoints: list[ExtractedEndpoint] = Field(default_factory=list)


# JSON schema handed to Claude so it returns exactly this shape.
RESPONSE_SCHEMA_HINT = """{
  "endpoints": [
    {
      "url": "string (absolute or root-relative path found in the JS)",
      "method": "GET|POST|PUT|DELETE|PATCH (best guess, default GET)",
      "params": ["parameter names the endpoint takes"],
      "id_like_params": ["subset of params that look like object identifiers, e.g. user_id, account, order_id, id"],
      "suspected_vuln_class": "reflected_xss | idor | sqli_boolean | unknown",
      "reasoning": "one sentence: why this endpoint/param is interesting"
    }
  ]
}"""
