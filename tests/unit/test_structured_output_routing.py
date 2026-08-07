"""One decision about structured output, made once, honoured everywhere.

Measured 2026-08-07, live, with the whole reporting layer on a local
llama-server:

    17:25:54  report node entered; NarrativeAgent issued its structured call
    17:55:54  NarrativeAgent structured: connection error (attempt 1/3):
              Request timed out. -- retrying in 1s.

Exactly 1800 s, the ``request_timeout`` set in ``openai_provider``. The report
node produced not one log line in between, and "attempt 1/3" means the same
silence was about to repeat twice more: **90 minutes** of a job that looked
alive only because of the worker heartbeat.

``with_structured_output`` issues a tool-calling request that a local
OpenAI-compatible server handles pathologically -- an earlier measurement had
one mediator extraction run 13+ minutes without completing where the plain
text path takes ~3. The mediator was routed away from it in 0236656, but
``NarrativeAgent`` and ``ReportComposer`` were left calling it directly, so the
fix covered one of three callers.

The capability question is a property of the *endpoint*, not of the caller, so
it belongs in the registry with the rest of the provider capability table.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from maljan.llm.registry import structured_output_supported


def _config(provider: str, base_url: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        llm=SimpleNamespace(provider=provider, openai=SimpleNamespace(base_url=base_url))
    )


def _llm(llm_type: str = "openai-chat") -> MagicMock:
    m = MagicMock()
    m._llm_type = llm_type
    return m


class TestALocalServerIsNotTheVendorAPI:
    def test_a_custom_base_url_disables_structured_output(self) -> None:
        assert structured_output_supported(_config("openai", "http://127.0.0.1:8080/v1")) is False

    def test_the_vendor_api_keeps_it(self) -> None:
        assert structured_output_supported(_config("openai", None)) is True

    def test_an_empty_base_url_is_not_a_local_server(self) -> None:
        assert structured_output_supported(_config("openai", "")) is True


class TestTheCapabilityTableStillDecidesForOtherProviders:
    def test_a_provider_the_table_rejects_stays_rejected(self) -> None:
        assert structured_output_supported(_config("ollama", None)) is False

    def test_anthropic_is_supported(self) -> None:
        assert structured_output_supported(_config("anthropic", None)) is True


class TestWithoutConfigTheLlmTypeIsNormalised:
    """LangChain reports "openai-chat"; the table is keyed on "openai"."""

    def test_the_suffix_does_not_misclassify(self) -> None:
        assert structured_output_supported(None, _llm("openai-chat")) is True

    def test_an_unknown_name_is_refused(self) -> None:
        assert structured_output_supported(None, _llm("something-exotic")) is False

    def test_no_config_and_no_llm_is_refused(self) -> None:
        """Nothing known about the endpoint is not a reason to gamble 30 minutes."""
        assert structured_output_supported(None, None) is False


class TestItNeverRaises:
    @pytest.mark.parametrize("cfg", [object(), SimpleNamespace(), SimpleNamespace(llm=None)])
    def test_a_malformed_config_falls_back_instead_of_exploding(self, cfg: object) -> None:
        assert structured_output_supported(cfg) is False
