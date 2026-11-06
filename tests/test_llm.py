"""Multi-provider LLM support: provider selection, shared malformed-output
rejection across ALL providers, and provenance tagging."""
import pytest

from bouncer.candidates import CandidateGenerator
from bouncer.claude_client import (LLMExtractor, make_extractor, make_provider)
from bouncer.config import Settings
from bouncer.scope import Scope


class FakeProvider:
    """Stand-in LLM that returns a canned string, so we can exercise the shared
    validation/conversion path without any network call."""
    def __init__(self, response: str):
        self._response = response
        self.calls = 0

    def complete(self, prompt, *, system=None):
        self.calls += 1
        return self._response


GOOD = '{"endpoints": [{"url": "/x", "params": ["q"], "suspected_vuln_class": "reflected_xss"}]}'
BAD_JSON = "sorry, here is what I found: not json"
BAD_SHAPE = '{"endpoints": "should be a list"}'


@pytest.mark.parametrize("tag", ["anthropic:m", "openai:m", "self_hosted:m"])
def test_malformed_output_rejected_for_every_provider(tag):
    # Same discard-and-return-empty behavior regardless of which provider tag.
    for bad in (BAD_JSON, BAD_SHAPE):
        ext = LLMExtractor(FakeProvider(bad), f"ai-sourced:{tag}")
        assert ext.extract("//js", "app.js").endpoints == []
    # Valid output still parses, for every provider.
    ext = LLMExtractor(FakeProvider(GOOD), f"ai-sourced:{tag}")
    assert len(ext.extract("//js", "app.js").endpoints) == 1


@pytest.mark.parametrize("tag,expected", [
    ("anthropic:claude-x", "ai-sourced:anthropic:claude-x"),
    ("openai:gpt-4.1", "ai-sourced:openai:gpt-4.1"),
    ("self_hosted:llama3", "ai-sourced:self_hosted:llama3"),
])
def test_notes_tag_provenance_per_provider(tag, expected):
    ext = LLMExtractor(FakeProvider(GOOD), f"ai-sourced:{tag}")
    scope = Scope.from_dict({"in_domains": ["x.test"], "in_cidrs": []})
    gen = CandidateGenerator("demo", scope, ext)
    from bouncer.candidates import JsInput
    cands = gen.generate([JsInput("app.js", "http://x.test/", "//js")])
    assert cands and cands[0]["notes"].startswith(expected)


def test_provider_selection_requires_the_right_secret():
    # anthropic without key
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        make_provider(Settings(_env_file=None, llm_provider="anthropic"))
    # openai without key
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        make_provider(Settings(_env_file=None, llm_provider="openai"))
    # self_hosted without base_url
    with pytest.raises(RuntimeError, match="OPENAI_BASE_URL"):
        make_provider(Settings(_env_file=None, llm_provider="self_hosted"))
    # unknown provider
    with pytest.raises(RuntimeError, match="unknown"):
        make_provider(Settings(_env_file=None, llm_provider="bogus"))


def test_provider_selection_tags():
    _, tag = make_provider(Settings(_env_file=None, llm_provider="anthropic",
                                    anthropic_api_key="k", anthropic_model="claude-x"))
    assert tag == "anthropic:claude-x"
    _, tag = make_provider(Settings(_env_file=None, llm_provider="openai",
                                    openai_api_key="k", openai_model="gpt-x"))
    assert tag == "openai:gpt-x"
    # self_hosted needs base_url, key optional.
    prov, tag = make_provider(Settings(_env_file=None, llm_provider="self_hosted",
                                       openai_base_url="http://localhost:11434/v1",
                                       openai_model="llama3"))
    assert tag == "self_hosted:llama3"


def test_make_extractor_carries_tag():
    ext = make_extractor(Settings(_env_file=None, llm_provider="openai",
                                  openai_api_key="k", openai_model="gpt-x"))
    assert ext.source_tag == "ai-sourced:openai:gpt-x"
