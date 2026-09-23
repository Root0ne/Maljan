"""Record what a probe reached, and refuse a job that names something it did not.

Two halves of one rule. The settings probes write down every ``(endpoint,
model)`` pair they reached, with the sentence they came back with; submitting a
job reads that record for every model its agents would call and refuses the
job when one of them has no passing result.

The refusal names the agent, the model and the probe's last message, because
those three are what an operator needs to fix it: which card in the console,
which field on it, and what the endpoint said. A model nothing has ever probed
is refused in the same breath with the one sentence that applies — that it has
not been tested — rather than being let through on the grounds that nothing is
known against it.

The gate stands in two places, and it is the same sentence in both. Submitting
a job is one; applying a per-agent model (``core.llm.agents.*``) is the other,
because an operator who saves a model nothing can reach has made the mistake
the gate is about, and finding out at submit time means finding out on a page
that cannot fix it. The **Test** button beside the field is what turns the
refusal into a save.

``core.llm.require_probe`` turns the whole gate off, in both places. It exists
for the air-gapped batch case, where the endpoint is known good and nobody is
at a console to press a button, and it is the only way past: there is
deliberately no per-job and no per-save override, because a gate the caller
can wave away is not a gate.
"""

from __future__ import annotations

from typing import Any

from maljan.core.model_assignments import (
    ModelAssignment,
    assignments_for,
    endpoint_label,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger

logger = get_logger("services.model_probes")

# What a refusal says about a model no probe has ever been taken against.
NEVER_PROBED = "no probe has reached it"


def refusal_sentence(refusals: list[str]) -> str:
    """The whole refusal, as the submit form and the settings page both print it.

    One sentence in one place: an operator who reads it on the settings page
    and then on the submit form has to be reading the same instruction, or the
    second one looks like a different problem.
    """
    return (
        "A model this team would call has no passing probe. Test it in Settings, "
        "or turn off core.llm.require_probe for an air-gapped run. "
    ) + "; ".join(refusals)


async def record_probe(
    db: AsyncSession, *, endpoint: str, model: str, provider: str, ok: bool, detail: str
) -> None:
    """Write down what a probe reached, replacing this pair's previous answer.

    Per ``(endpoint, model)``: a second probe of the same pair is a newer
    answer to the same question, and two rows for it would leave the gate
    choosing between them.
    """
    if not str(model or "").strip() or not str(endpoint or "").strip():
        return
    from app.models.model_probe import ModelProbe

    row = (
        await db.execute(
            select(ModelProbe).where(ModelProbe.endpoint == endpoint, ModelProbe.model == model)
        )
    ).scalar_one_or_none()
    if row is None:
        db.add(
            ModelProbe(
                endpoint=endpoint,
                model=model,
                provider=str(provider or ""),
                ok=bool(ok),
                detail=str(detail or "")[:4000],
            )
        )
    else:
        row.provider = str(provider or "")
        row.ok = bool(ok)
        row.detail = str(detail or "")[:4000]
    await db.commit()


async def _results(db: AsyncSession, pairs: set[tuple[str, str]]) -> dict[tuple[str, str], Any]:
    """The stored results for the pairs asked about, keyed the way they are filed."""
    if not pairs:
        return {}
    from app.models.model_probe import ModelProbe

    endpoints = {endpoint for endpoint, _ in pairs}
    rows = (
        (await db.execute(select(ModelProbe).where(ModelProbe.endpoint.in_(endpoints))))
        .scalars()
        .all()
    )
    return {(row.endpoint, row.model): row for row in rows if (row.endpoint, row.model) in pairs}


def _sentence(assignment: ModelAssignment, detail: str) -> str:
    """One refusal, naming the agent, the model and what the probe last said.

    The endpoint appears as its label — scheme and host — not as the value the
    call is made with. This sentence is the body of the 422 ``create_job``
    answers, which any authenticated user can reach, and a base URL configured
    with userinfo (the ordinary shape for a llama.cpp behind basic auth) would
    otherwise show them the endpoint's credentials.
    """
    # A fallback is gated exactly as the first model is, and the sentence
    # says which one it is, so an operator knows which entry of the list to fix.
    names = "falls back to" if getattr(assignment, "position", 0) else "names"
    return (
        f"agent {assignment.agent!r} {names} model {assignment.model!r} at "
        f"{endpoint_label(assignment.endpoint)}: {detail}"
    )


AGENT_MODELS_KEY = "core.llm.agents"


async def unprobed_models_being_saved(
    db: AsyncSession,
    settings: Any,
    changes: dict[str, Any],
    stored: dict[str, Any] | None = None,
) -> list[str]:
    """Every per-agent model this save *moves* that no probe has reached.

    Only the entries whose model or endpoint changed. ``core.llm.agents`` is
    one JSON leaf and the console stages it whole, so every entry is "named"
    on every save; asking about all of them would refuse a change to agent B's
    temperature because agent A carries an untested model, which is a refusal
    about something the operator did not touch. Each entry is compared with
    the stored leaf and only the ones that differ in ``provider``, ``model`` or
    ``base_url`` are asked about; an entry that is new is asked about, because
    everything about it is a change.

    The settings the pairs are read against are the ones being written, so an
    operator moving an agent to a new endpoint and a new model in one save is
    judged on the pair they are moving it to.
    """
    if not getattr(settings.llm, "require_probe", True):
        return []
    entry = changes.get(AGENT_MODELS_KEY)
    if not isinstance(entry, dict) or not entry:
        return []
    was = (stored or {}).get(AGENT_MODELS_KEY)
    before = was if isinstance(was, dict) else {}
    moved = [
        str(name)
        for name, value in entry.items()
        if _points_somewhere_new(value, before.get(str(name)))
    ]
    return await unprobed_models(db, settings, moved)


def _points_somewhere_new(now: Any, was: Any) -> bool:
    """Whether an agent's entry names a model or an endpoint it did not before.

    Its fallbacks included: a model added to the list, or one of the list
    moved to another endpoint, is a model the agent may now call.
    """
    if not isinstance(now, dict):
        return False
    if not isinstance(was, dict):
        return True
    return _calls(now) != _calls(was)


def _calls(entry: dict[str, Any]) -> list[tuple[Any, Any, Any]]:
    """``(provider, model, base_url)`` for each model of an entry's list, in order."""
    rows = [entry, *[row for row in (entry.get("fallbacks") or []) if isinstance(row, dict)]]
    return [(row.get("provider"), row.get("model"), row.get("base_url")) for row in rows]


async def unprobed_models(db: AsyncSession, settings: Any, agents: list[str]) -> list[str]:
    """Every agent whose model has no passing probe, as sentences, or nothing.

    Empty when the gate is off, when the profile names no agent, and — the
    ordinary case — when every model an agent would call has been reached.
    """
    if not getattr(settings.llm, "require_probe", True):
        return []
    assignments = [a for a in assignments_for(settings, agents) if a.model and a.endpoint]
    stored = await _results(db, {a.key for a in assignments})
    refusals: list[str] = []
    for assignment in assignments:
        row = stored.get(assignment.key)
        if row is None:
            refusals.append(_sentence(assignment, NEVER_PROBED))
        elif not row.ok:
            refusals.append(_sentence(assignment, str(row.detail or "the probe did not reach it")))
    return refusals
