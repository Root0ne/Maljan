"""Anthropic LLM provider.

Builds ``langchain_anthropic.ChatAnthropic`` so that every request a job makes
is one the Anthropic API takes from a model of the current generation, and is
billed as a hosted API should bill it. What decides each field is a fact —
the vendor's documentation, carried as data, or the Anthropic Models API's own
description of the model — and nothing else:

* **Sampling.** Claude Haiku 5.5, and every model in the vendored table's
  ``fixed_sampling`` rows, refuses a non-default ``temperature``, ``top_p`` or
  ``top_k`` with a 400 on every request (the Thinking page's "Sampling
  parameters"). The Models API states no such capability, so the table's rows,
  each with the page it is documented on, are the fact; such a model is sent
  no sampling parameter. Any other model is sent the temperature it is built
  with, as before.
* **Thinking** is not configured: a model that thinks by default thinks as it
  would, and no ``budget_tokens`` is ever sent (a 400 on these models).
  How deep it goes is ``llm.anthropic.effort``, sent as
  ``output_config.effort`` when set; a level the Models API says the model does
  not take is refused here, before the job spends anything.
* **Prompt caching** is asked for only where a prefix is sent again — a
  request that continues a conversation — with explicit breakpoints on its
  newest user turn and on the turn the previous request ended with
  (``anthropic_history``); a single-shot call carries no marker and pays no
  write premium. ``llm.anthropic.prompt_cache_ttl`` sets the lifetime.
* **Streaming.** A request whose output cap is past what the Anthropic SDK
  sends unstreamed by its own rule (an answer it expects to run past ten
  minutes) is streamed and joined into the same answer. The SDK would not
  refuse it here — the provider always names a request timeout, which skips
  that check — but a long request that sends nothing until it ends is the one
  a network drops as idle (the API errors page, "Long requests").
* **The history.** Every request keeps the thinking blocks it replays valid
  (``anthropic_history.with_preserved_thinking``) and never sends a
  ``tool_use`` without its ``tool_result`` (``tool_replies``).
* **Structured output** asks for the schema's tool without forcing it, so no
  request depends on ``tool_choice`` ``any`` or ``tool``.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.core.logger import logger
from maljan.llm.registry import register_provider

_table_lock = threading.Lock()
_fixed_sampling: dict[str, str] | None = None


def _fixed_sampling_rows() -> dict[str, str]:
    """The vendored table's ``fixed_sampling`` rows, read once: family key -> source."""
    global _fixed_sampling
    from maljan.core.paths import resolve_data
    from maljan.llm.context_window import TABLE_PATH

    with _table_lock:
        if _fixed_sampling is not None:
            return _fixed_sampling
        rows: dict[str, str] = {}
        try:
            raw = json.loads(Path(resolve_data(TABLE_PATH)).read_text(encoding="utf-8"))
            for key, row in (raw.get("fixed_sampling") or {}).items():
                source = str(row.get("source") or "") if isinstance(row, dict) else ""
                if not str(key).startswith("_") and source:
                    rows[str(key).lower()] = source
        except Exception as exc:  # noqa: BLE001 — a table that cannot be read names no model
            logger.debug("the vendored fixed-sampling rows could not be read: %s", exc)
        _fixed_sampling = rows
        return _fixed_sampling


def fixed_sampling_source(model: object) -> str:
    """Where it is documented that ``model`` refuses sampling parameters, or ``""``.

    The longest table key the model's id starts with answers, as the table's
    windows are matched.
    """
    from maljan.llm.context_window import model_family

    family = model_family(model)
    if not family:
        return ""
    rows = _fixed_sampling_rows()
    matches = [key for key in rows if family.startswith(key)]
    return rows[max(matches, key=len)] if matches else ""


def needs_streaming(model: str, max_tokens: object) -> bool:
    """Whether a request with this cap is past what the Anthropic SDK sends unstreamed.

    The SDK's own rule, asked rather than copied: a non-streaming request it
    expects to run past ten minutes (by its reckoning, an output cap over
    21,333 tokens, or over a model's own non-streaming limit). The SDK applies
    it only to a client left at its default timeout, which this provider never
    is, so nothing would be refused; the rule is read as the line past which a
    request is long enough that an idle connection may be dropped. An SDK that
    moved the rule streams every capped request.
    """
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens <= 0:
        return False
    try:
        from anthropic._base_client import BaseClient
        from anthropic._constants import MODEL_NONSTREAMING_TOKENS

        BaseClient._calculate_nonstreaming_timeout(
            None,  # type: ignore[arg-type]
            int(max_tokens),
            MODEL_NONSTREAMING_TOKENS.get(str(model), None),
        )
    except ValueError:
        return True
    except Exception:  # noqa: BLE001 — a rule that cannot be read is not relied on
        return True
    return False


def cache_control(ttl: str) -> dict[str, str]:
    """The ``cache_control`` marker a breakpoint carries, at the configured lifetime."""
    marker = {"type": "ephemeral"}
    if str(ttl) == "1h":
        marker["ttl"] = "1h"
    return marker


_UNFORCED_CLASSES: dict[type, type] = {}


def with_unforced_structured_output(chat_class: Any) -> Any:
    """``chat_class`` whose structured output never forces a tool choice, and whose ``none`` is one.

    A ``tool_choice="none"`` binding (the analysts' nudge with the loop's tools
    withheld) is sent as Anthropic's ``{"type": "none"}``.

    ``ChatAnthropic.with_structured_output`` forces the schema's tool
    (``tool_choice`` ``tool``) unless thinking is configured, and several
    models of the current generation refuse a forced tool choice with a 400.
    The schema's tool is offered instead and the model calls it — the path
    langchain-anthropic itself takes when thinking is on. An answer that calls
    no tool parses to nothing, and every caller here then asks in text.
    """
    if not isinstance(chat_class, type) or not hasattr(chat_class, "with_structured_output"):
        return chat_class
    cached = _UNFORCED_CLASSES.get(chat_class)
    if cached is not None:
        return cached
    base: Any = chat_class

    def with_structured_output(
        self: Any,
        schema: Any,
        *,
        include_raw: bool = False,
        method: str = "function_calling",
        **kwargs: Any,
    ) -> Any:
        if method != "function_calling" or kwargs:
            return base.with_structured_output(
                self, schema, include_raw=include_raw, method=method, **kwargs
            )
        from operator import itemgetter

        from langchain_anthropic.chat_models import convert_to_anthropic_tool
        from langchain_core.output_parsers.openai_tools import (
            JsonOutputKeyToolsParser,
            PydanticToolsParser,
        )
        from langchain_core.runnables import RunnableMap, RunnablePassthrough
        from langchain_core.utils.pydantic import is_basemodel_subclass

        formatted = convert_to_anthropic_tool(schema)
        llm = self.bind_tools(
            [schema],
            ls_structured_output_format={
                "kwargs": {"method": "function_calling"},
                "schema": formatted,
            },
        )
        parser: Any
        if isinstance(schema, type) and is_basemodel_subclass(schema):
            parser = PydanticToolsParser(tools=[schema], first_tool_only=True)
        else:
            parser = JsonOutputKeyToolsParser(key_name=formatted["name"], first_tool_only=True)
        if not include_raw:
            return llm | parser
        parsed = RunnablePassthrough.assign(
            parsed=itemgetter("raw") | parser, parsing_error=lambda _: None
        ).with_fallbacks(
            [RunnablePassthrough.assign(parsed=lambda _: None)], exception_key="parsing_error"
        )
        return RunnableMap(raw=llm) | parsed

    def bind_tools(self: Any, tools: Any, *, tool_choice: Any = None, **kwargs: Any) -> Any:
        # ``ChatAnthropic`` reads a string choice as a tool's name, so the
        # ``"none"`` every other client takes would force a tool called
        # "none"; Anthropic spells it ``{"type": "none"}``.
        if tool_choice == "none":
            tool_choice = {"type": "none"}
        return base.bind_tools(self, tools, tool_choice=tool_choice, **kwargs)

    unforced = type(
        chat_class.__name__,
        (chat_class,),
        {"with_structured_output": with_structured_output, "bind_tools": bind_tools},
    )
    unforced.__module__ = __name__
    unforced.__qualname__ = chat_class.__qualname__
    _UNFORCED_CLASSES[chat_class] = unforced
    return unforced


@register_provider("anthropic")
class AnthropicProvider:
    """Builds LangChain ChatAnthropic instances."""

    name = "anthropic"

    def __init__(self, config: Settings) -> None:
        self._config = config

    def build_model(
        self,
        model: str,
        temperature: float,
        **kwargs: Any,
    ) -> BaseChatModel:
        from langchain_anthropic import ChatAnthropic  # type: ignore[import-untyped]

        settings = self._config.llm.anthropic
        secret = settings.api_key
        if not secret:
            raise LLMError("ANTHROPIC_API_KEY is not set but provider is 'anthropic'.")

        from pydantic import SecretStr

        api_key = secret if isinstance(secret, SecretStr) else SecretStr(str(secret))

        # The same request timeout as every other provider, named rather than
        # left to the SDK's default, until the model's pace is measured; each
        # request is then sized for its own output cap.
        from maljan.llm.generation_rate import with_sized_request_timeout
        from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

        kwargs.setdefault("timeout", float(PROVIDER_REQUEST_TIMEOUT_SECONDS))

        # A model documented to refuse sampling parameters is sent none.
        documented = fixed_sampling_source(model)
        if documented:
            logger.debug(
                "anthropic provider: %s is sent no sampling parameter (%s).", model, documented
            )
        else:
            kwargs["temperature"] = temperature

        effort = str(getattr(settings, "effort", "") or "")
        if effort:
            from maljan.llm.model_capabilities import takes_effort

            if takes_effort(model, effort) is False:
                raise LLMError(
                    f"llm.anthropic.effort is {effort!r}, which the Anthropic Models API says "
                    f"{model} does not take."
                )
            output_config = dict(kwargs.pop("output_config", None) or {})
            output_config.setdefault("effort", effort)
            kwargs["output_config"] = output_config

        if needs_streaming(model, kwargs.get("max_tokens")):
            kwargs.setdefault("streaming", True)
            kwargs.setdefault("stream_usage", True)

        # Every request keeps the thinking blocks it replays valid
        # (``maljan.llm.anthropic_history``), and none sends a ``tool_use``
        # without its ``tool_result``, whatever the history it was built from
        # (``maljan.llm.tool_replies``, applied last, over every other change).
        # The replies written there are a function of the history alone, so
        # the same history is completed the same way on every request.
        from maljan.llm.anthropic_history import with_preserved_thinking
        from maljan.llm.tool_replies import with_answered_tool_calls

        chat_class = with_answered_tool_calls(
            with_preserved_thinking(
                with_unforced_structured_output(with_sized_request_timeout(ChatAnthropic)),
                str(getattr(settings, "prompt_cache_ttl", "5m") or "5m"),
            ),
            "anthropic",
        )
        return chat_class(  # type: ignore[no-any-return]
            model_name=model,
            api_key=api_key,
            **kwargs,
        )
