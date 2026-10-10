"""The prompt-usage capture reads langchain-anthropic's chunk and never changes what it returns.

``with_reported_prompt_usage`` overrides a private langchain-anthropic method.
Whatever that method returns is handed back as it came: a shape the reader
does not expect skips the capture alone, says so once, and leaves the stream
as it was.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.llm import anthropic_provider
from maljan.llm.generation_rate import PROMPT_USAGE_KEY


def _start_event() -> Any:
    usage = SimpleNamespace(
        input_tokens=40,
        output_tokens=1,
        cache_read_input_tokens=900,
        cache_creation_input_tokens=60,
        cache_creation=None,
        output_tokens_details=None,
    )
    return SimpleNamespace(type="message_start", message=SimpleNamespace(usage=usage))


def _wrapped(returns: Any) -> Any:
    class _Base:
        def _make_message_chunk_from_anthropic_event(self, event: Any, **kwargs: Any) -> Any:
            return returns

    return anthropic_provider.with_reported_prompt_usage(_Base)()


@pytest.fixture
def warned(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    said = MagicMock()
    monkeypatch.setattr(anthropic_provider, "logger", said)
    monkeypatch.setattr(
        anthropic_provider,
        "_capture_skipped_said",
        type(anthropic_provider._capture_skipped_said)(),
    )
    return said


class TestTheExpectedShape:
    def test_the_prompt_usage_is_kept_on_the_chunk(self, warned: MagicMock) -> None:
        message = SimpleNamespace(response_metadata={})
        result = (message, None)
        model = _wrapped(result)
        assert model._make_message_chunk_from_anthropic_event(_start_event()) is result
        kept = message.response_metadata[PROMPT_USAGE_KEY]
        assert kept["input_tokens"] == 1000
        assert kept["output_tokens"] == 0
        warned.warning.assert_not_called()


class TestAChangedShape:
    @pytest.mark.parametrize(
        "returns",
        [
            SimpleNamespace(response_metadata={}),
            (SimpleNamespace(response_metadata={}), None, "extra"),
            (SimpleNamespace(response_metadata=None), None),
        ],
        ids=["a-bare-message", "a-longer-tuple", "metadata-not-a-dict"],
    )
    def test_the_base_result_is_handed_back_and_the_capture_skipped(
        self, warned: MagicMock, returns: Any
    ) -> None:
        model = _wrapped(returns)
        assert model._make_message_chunk_from_anthropic_event(_start_event()) is returns
        assert model._make_message_chunk_from_anthropic_event(_start_event()) is returns
        warned.warning.assert_called_once()
        text = warned.warning.call_args.args[0].lower()
        assert "token" not in text

    def test_another_event_is_never_read(self, warned: MagicMock) -> None:
        returns = object()
        model = _wrapped(returns)
        delta = SimpleNamespace(type="content_block_delta")
        assert model._make_message_chunk_from_anthropic_event(delta) is returns
        warned.warning.assert_not_called()
