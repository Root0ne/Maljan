"""Refuse a job whose team needs a static provider that is not there.

A provider that degrades (r2, a generic MCP server, capa/YARA) costs a run
some evidence when it is missing, and the run says so. One that does not —
Ghidra, whose ``degrade_on_failure`` is false because a static run with no
decompiler is a confident report grounded in nothing — fails the run loudly
when the agent that needs it starts, which is minutes and a paid model call
after the sample was accepted. This asks first.

Every agent the chosen team can run — its stages' agents and every agent
they can ask — that opens a static provider is resolved to the provider it
would open, exactly as the run resolves it (the team's forced provider, the
definition's own, the job's or the deployment's). Each distinct provider that
does not degrade is asked ``readiness()``: for Ghidra over http, whether its
schema endpoint answers with the configured token. Nothing is loaded
and nothing is analysed. The mid-run loud failure stays: this is a check
before the job, not a replacement for the one inside it.

A provider switched off attaches nothing and fails nothing — the shipped
default is Ghidra, switched off — so it is refused only for an agent that was
given it by name: by its definition, by the team, or by the job.

The refusal is a sentence per agent naming the agent, the provider and where
it was looked for, as scheme and host only — ``POST /jobs`` answers it to any
authenticated user.
"""

from __future__ import annotations

import asyncio
from typing import Any

from maljan.core.logger import logger


def refusal_sentence(refusals: list[str]) -> str:
    """The whole 422 body: what is wrong, then one sentence per agent."""
    return (
        "A static provider this team needs is not ready, and a run without it fails "
        "when that agent starts. Start it, switch it on or correct its address, or "
        "choose a team that does not need it. "
    ) + "; ".join(refusals)


def _provider_for(settings: Any, provider_id: str) -> Any:
    """A provider object for ``provider_id``, built the way the job's container builds it.

    Construction is cheap and does no I/O (``StaticProvider.from_settings``);
    a per-agent provider is the same construction against a copy whose
    ``static.provider`` names it, as ``ServiceContainer.get_static_provider``
    does.
    """
    from maljan.providers.registry import get_static_provider

    cfg = settings
    if provider_id != str(settings.static.provider):
        cfg = settings.model_copy(deep=True)
        cfg.static.provider = provider_id
    return get_static_provider(cfg)


async def unready_static_providers(
    settings: Any, profile: str, *, global_provider: str | None = None
) -> list[str]:
    """One sentence per agent of ``profile`` whose non-degrading provider is not ready.

    ``global_provider`` is the job's own ``static_provider`` when it names
    one. Empty when every provider the team needs is ready, when the team
    needs none that fails loudly, and when the profile does not exist (that
    refusal is the caller's, with the list of the ones that do).
    """
    from maljan.agents.composition import (
        reachable_agents,
        reads_static_provider,
        static_provider_id_for,
    )

    team = settings.agents.profiles.get(profile)
    if team is None:
        return []
    named = [agent for stage in team.stages for agent in stage.agents]
    by_provider: dict[str, list[str]] = {}
    chosen: set[str] = set()
    for key in reachable_agents(settings, named):
        definition = settings.agents.definitions.get(key)
        if not reads_static_provider(definition):
            continue
        provider_id = static_provider_id_for(
            settings, key, profile=team, global_provider=global_provider
        )
        by_provider.setdefault(provider_id, []).append(key)
        if team.static_provider or getattr(definition, "static_provider", None) or global_provider:
            chosen.add(key)

    checks: list[tuple[str, Any, list[str]]] = []
    refusals: list[str] = []
    for provider_id, agents in by_provider.items():
        try:
            provider = _provider_for(settings, provider_id)
        except Exception as exc:  # noqa: BLE001 — an unknown id is refused elsewhere
            logger.debug("readiness: provider %r not built (%s)", provider_id, exc)
            continue
        if provider.capabilities.degrade_on_failure:
            continue
        if provider.switched_off():
            # Switched off, the provider attaches nothing and the run goes on
            # without it — the deployment default for a Ghidra nobody set up.
            # An agent that was *given* this provider by name was given it to
            # use, so for that agent it is a refusal all the same.
            refusals.extend(
                f"agent {key!r} needs static provider {provider_id!r}, which is switched off"
                for key in agents
                if key in chosen
            )
            continue
        checks.append((provider_id, provider, agents))
    if not checks:
        return refusals

    answers = await asyncio.gather(
        *(provider.readiness() for _, provider, _ in checks), return_exceptions=True
    )
    for (provider_id, provider, agents), answer in zip(checks, answers, strict=True):
        if isinstance(answer, BaseException):
            detail = type(answer).__name__
        elif answer.ok:
            continue
        else:
            detail = str(answer.detail or "no answer")
        where = provider.address()
        at = f" at {where}" if where else ""
        refusals.extend(
            f"agent {key!r} needs static provider {provider_id!r}{at}, which is not ready: {detail}"
            for key in agents
        )
    return refusals
