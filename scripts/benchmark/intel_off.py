"""The "intel off" arm: the same team with every lookup server withheld.

A lookup asks a service outside the deployment what it already knows of the
sample or of an indicator (a reputation report, an indicator report, a
submission's result); its answer can carry a family name or a C2 list that
public reports hold, which the benchmark would otherwise count the same as a
fact the run worked out from the bytes. The arm measures the run without them.

It is one team profile, derived from a base profile and never run here:

- the servers withheld are those whose declarations name a tool of a lookup
  kind (``scripts.benchmark.provenance.LOOKUP_KINDS``, the declared table of
  kinds that reach outside the deployment), read from the settings'
  declarations, never from a tool's or a server's name. A server is withheld
  whole, so any other tool it declares goes with it, and is named;
- they are added to the base profile's ``exclude_servers``. That one field
  withholds a server from the team's agents and from the triage pack, whose
  reputation step and server steps never ask a server the team withholds
  (``pipeline.nodes``), so the arm needs no global setting changed;
- a lookup declared by a source a profile cannot withhold (a provider block,
  not a tool server) is named as not withheld, never dropped silently.

The arm is checked by building the settings with it, and is written as the
profile to add under ``agents.profiles`` and the job config that selects it,
which starts the run without an earlier run's memory as every benchmark run
does (``scripts.benchmark.jobs``). Running it is a paid run, which needs the
owner's go-ahead per run.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from scripts.benchmark.jobs import job_config
from scripts.benchmark.provenance import LOOKUP_KINDS

from maljan.core.config import ALL_SERVERS
from maljan.core.declared_reading import declarations
from maljan.core.settings_overrides import build_settings

SUFFIX = "_intel_off"
PROFILES_KEY = "agents.profiles"
PAID_NOTE = "running the arm is a paid run: each run needs the owner's go-ahead"


class ArmError(RuntimeError):
    """The arm cannot be derived; the message names why."""


def intel_off(overrides: Mapping[str, Any], base: str | None = None) -> dict[str, Any]:
    """The intel-off arm of ``base`` (default: the active profile) under ``overrides``.

    ``overrides`` are stored settings by dotted key (``agents.profiles``,
    ``mcp.servers`` …), as the settings store holds them; empty, the model's
    defaults.
    """
    try:
        settings = build_settings(dict(overrides))
    except ValueError as exc:
        raise ArmError(f"the settings cannot be built: {exc}") from exc
    profiles = settings.agents.profiles
    name = base or settings.agents.profile
    if name not in profiles:
        raise ArmError(f"no profile {name!r}; the settings hold: {', '.join(sorted(profiles))}")
    profile = profiles[name]
    declared = declarations(settings)
    lookups: dict[str, list[str]] = {}
    not_withheld: list[str] = []
    for source, tool, facts in declared.tools_of_kind(LOOKUP_KINDS):
        if source.kind == "mcp":
            lookups.setdefault(source.key, []).append(tool)
        else:
            not_withheld.append(f"{source}: {tool} ({facts.kind})")
    excluded = list(profile.exclude_servers)
    every = ALL_SERVERS in excluded
    already = sorted(key for key in lookups if every or key in excluded)
    added = sorted(key for key in lookups if key not in already)
    with_them: dict[str, list[str]] = {}
    for key in sorted(lookups):
        held = declared.source(f"mcp:{key}")
        others = sorted(t for t in (held.tools if held else {}) if t not in lookups[key])
        if others:
            with_them[key] = others
    arm_key = f"{name}{SUFFIX}"
    arm = profile.model_copy(
        update={
            "label": f"{profile.label or name} (intel off)",
            "exclude_servers": excluded + added,
        }
    )
    definition = arm.model_dump(mode="json")
    checked = dict(overrides)
    checked[PROFILES_KEY] = {
        **{key: p.model_dump(mode="json") for key, p in profiles.items()},
        arm_key: definition,
    }
    try:
        build_settings(checked)
    except ValueError as exc:
        raise ArmError(f"the settings refuse the arm's profile: {exc}") from exc
    return {
        "profile": arm_key,
        "base_profile": name,
        "definition": definition,
        "settings_key": f"{PROFILES_KEY}.{arm_key}",
        "job_config": job_config({"profile": arm_key}),
        "withheld": {key: sorted(lookups[key]) for key in added},
        "already_withheld": {key: sorted(lookups[key]) for key in already},
        "withheld_with_them": {key: with_them[key] for key in added if key in with_them},
        "not_withheld": not_withheld,
        "lookup_kinds": sorted(LOOKUP_KINDS),
        "paid": PAID_NOTE,
    }


def render(arm: dict[str, Any]) -> str:
    """The arm as text: what it withholds, what goes with it, and how it is selected."""

    def servers(held: dict[str, list[str]]) -> str:
        return "; ".join(f"{key} ({', '.join(tools)})" for key, tools in held.items()) or "none"

    lines = [
        f"intel-off arm: profile {arm['profile']!r}, from {arm['base_profile']!r}",
        f"withheld: {servers(arm['withheld'])}",
        f"already withheld by the base profile: {servers(arm['already_withheld'])}",
        f"withheld with them (not lookups): {servers(arm['withheld_with_them'])}",
        "lookups a profile cannot withhold: " + (", ".join(arm["not_withheld"]) or "none"),
        f"exclude_servers: {', '.join(arm['definition']['exclude_servers']) or 'none'}",
        f"add it under {arm['settings_key']}; select it with the job config "
        f"{json.dumps(arm['job_config'], sort_keys=True)}",
        arm["paid"],
    ]
    if not arm["withheld"] and not arm["already_withheld"]:
        lines.insert(1, "no server declares a lookup: the arm is the base profile")
    return "\n".join(lines)
