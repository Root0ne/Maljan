"""One agent's own spend ceiling, held on the models built for it.

``llm.agents.<key>.max_spend_usd`` and ``max_unpriced_tokens`` are kept by the
job's spend meter (``core.spend.SpendMeter.agent_refusal``); this is where the
models of that agent ask it. An :class:`AgentCeiling` is attached to the
callbacks of each model the agent's entry lists (:func:`attach_agent_ceiling`),
its fallbacks included, so every call of that agent — whichever model answers
it — is checked before it is sent and counted once it returns, and no call
site has to remember to. A call made once the agent reached its ceiling
raises :class:`core.spend.AgentCeilingStop` before any request leaves, which
every caller already answers as a refusal by the spend ceiling: what the agent
produced so far is kept and its salvage path is taken. The first refusal is
written to the call feed (``TokenLedger.on_call``) as an
:data:`core.spend.AGENT_CEILING_RECORD` record naming the agent and its
ceiling.

Nothing is attached to an agent that sets no ceiling, so its models are the
models built before the ceiling existed.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from maljan.core.logger import logger

# Where LangChain logs a callback that raised.
_LANGCHAIN_LOGGER = "langchain_core.callbacks.manager"


class AgentCeiling(BaseCallbackHandler):
    """Checks one agent's own ceiling before each call of one model, and counts what it used."""

    # Raised before the request is sent, on the caller's own thread.
    raise_error = True
    run_inline = True

    def __init__(self, ledger: Any, agent: str, model: str) -> None:
        super().__init__()
        self.ledger = ledger
        self.agent = str(agent).lower()
        self.model = model

    def _meter(self) -> Any:
        from maljan.core.spend import SpendMeter

        meter = getattr(self.ledger, "spend", None)
        return meter if isinstance(meter, SpendMeter) else None

    def _check(self) -> None:
        from maljan.core.spend import AGENT_CEILING_RECORD, AgentCeilingStop

        meter = self._meter()
        if meter is None:
            return
        said, first = meter.agent_refusal(self.agent)
        if not said:
            return
        if first:
            tell = getattr(self.ledger, "_tell", None)
            if callable(tell):
                with contextlib.suppress(Exception):
                    tell(
                        {
                            "agent": self.agent,
                            "model": str(self.model),
                            "call": AGENT_CEILING_RECORD,
                            "reported": False,
                            "reason": said,
                        }
                    )
        raise AgentCeilingStop(f"a call of {self.model} was not made: {said}", self.agent)

    def on_chat_model_start(
        self, serialized: dict[str, Any], messages: Any, *, run_id: UUID, **kwargs: Any
    ) -> None:
        self._check()

    def on_llm_start(
        self, serialized: dict[str, Any], prompts: Any, *, run_id: UUID, **kwargs: Any
    ) -> None:
        self._check()

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        try:
            from maljan.core.token_ledger import turn_usage
            from maljan.llm.stream_watch import estimated_usage

            message = getattr(response.generations[0][0], "message", None)
            usage = turn_usage(message)
            # An answer ended while it streamed reports no usage and carries a
            # stated estimate, which the job's ceiling is charged too.
            self.note(usage, None if usage is not None else estimated_usage(message))
        except Exception as exc:  # noqa: BLE001 — counting never breaks a call
            logger.debug("agent ceiling: a call of %s was not counted (%s).", self.agent, exc)

    def note(self, usage: Any, estimated: Any = None) -> None:
        """One billed call or failed attempt of this model, toward the agent's ceiling."""
        meter = self._meter()
        if meter is not None:
            meter.note_agent_call(self.agent, usage, self.model, estimated=estimated)


class _QuietRefusal(logging.Filter):
    """Drops LangChain's warning for a callback error that is an agent's ceiling refusal.

    The refusal is raised from :meth:`AgentCeiling.on_chat_model_start` on
    purpose and said once by the meter; LangChain's own line for every refused
    call ("Error in AgentCeiling.on_chat_model_start callback") says nothing more.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args if isinstance(record.args, tuple) else ()
        return not (
            len(args) == 3
            and args[0] == AgentCeiling.__name__
            and str(args[2]).startswith("AgentCeilingStop(")
        )


_QUIET = _QuietRefusal()
if not any(isinstance(f, _QuietRefusal) for f in logging.getLogger(_LANGCHAIN_LOGGER).filters):
    logging.getLogger(_LANGCHAIN_LOGGER).addFilter(_QUIET)


def ceiling_of(model: Any) -> AgentCeiling | None:
    """The :class:`AgentCeiling` on ``model``'s callbacks, or ``None``."""
    callbacks = getattr(model, "callbacks", None)
    if not isinstance(callbacks, list):
        return None
    return next((cb for cb in callbacks if isinstance(cb, AgentCeiling)), None)


def attach_agent_ceiling(llm: Any, ledger: Any, agent: str) -> Any:
    """Hold ``llm`` to ``agent``'s own ceiling, where its entry sets one; returns ``llm``.

    ``agent`` is the ``llm.agents`` key the model was built from. A model list
    gets one per model, all counted toward the same agent. Nothing is attached
    when the job's meter knows no ceiling for ``agent``. Never raises.
    """
    if ledger is None or llm is None:
        return llm
    meter = getattr(ledger, "spend", None)
    asked = getattr(meter, "agent_ceiling", None)
    try:
        if not callable(asked) or asked(agent) is None:
            return llm
    except Exception:  # noqa: BLE001 — a ceiling that cannot be read is not attached
        return llm
    from maljan.llm.generation_rate import _fallback_list, model_name_of

    models = _fallback_list(llm)
    if models is not None:
        for inner in models:
            attach_agent_ceiling(inner, ledger, agent)
        return llm
    try:
        existing = list(getattr(llm, "callbacks", None) or [])
        if any(isinstance(cb, AgentCeiling) for cb in existing):
            return llm
        ceiling = AgentCeiling(ledger, agent, model_name_of(llm))
        object.__setattr__(llm, "callbacks", [*existing, ceiling])
        # A failed attempt the provider bills is charged by the model's retry
        # recorder; it counts toward this agent too (``RetryRecorder._charge``).
        from maljan.llm.transient import recorder_of

        recorder = recorder_of(llm)
        if recorder is not None:
            recorder.ceiling = ceiling
    except Exception:  # noqa: BLE001 — a model that takes no callbacks keeps none
        return llm
    return llm


def stopped_at_own_ceiling(llm: Any) -> bool:
    """Whether the agent ``llm`` was built for has reached its own ceiling. Never raises."""
    try:
        from maljan.llm.generation_rate import _fallback_list

        model = getattr(llm, "bound", None) or llm
        ceiling = ceiling_of(model)
        if ceiling is None:
            inner = _fallback_list(model) or []
            ceiling = next((c for c in map(ceiling_of, inner) if c is not None), None)
        if ceiling is None:
            return False
        meter = ceiling._meter()
        return meter is not None and ceiling.agent in meter.agents_stopped()
    except Exception:  # noqa: BLE001 — a question about the meter is never a failure
        return False


def carry_agent_ceiling(source: Any, target: Any) -> Any:
    """Attach ``source``'s ceiling to ``target`` as well, when it has one; returns ``target``.

    For a model rebuilt in place of another (the llama.cpp self-heal), as the
    retry recorder is carried (``transient.carry_retry_recorder``).
    """
    ceiling = ceiling_of(source)
    if ceiling is None:
        return target
    return attach_agent_ceiling(target, ceiling.ledger, ceiling.agent)
