"""Get an operator's own agent out of the way of a key the product later seeded.

Seeding a new built-in definition or profile takes a name. `triage`,
`android_static`, `reverser`, `mobile` and `deep_static` were all legal names
for an operator's own agent or team the day before they became built-ins, and
the identity check in ``AgentsConfig`` refuses a stored built-in that does not
match its seed — on *every* construction of ``Settings``, which is to say at
boot. An operator who had named an agent `reverser` would upgrade into an API
and a worker that cannot start and cannot be repaired from the console, because
the console needs the configuration to load in order to draw the page that
would fix it.

Refusing is defensible for a key an operator types *after* the seed exists —
the settings API still refuses that, per field, before anything is stored — and
it is defensible for the names that have been reserved since there was a
settings store. It is not defensible for one that was legal when they saved it,
which is what ``NEWLY_RESERVED_DEFINITIONS`` and ``NEWLY_RESERVED_PROFILES``
name and all this applies to.

So a stored entry under one of those names that is not the seed is renamed out
of the way — `reverser` becomes `reverser_custom` — and every reference to the
old name is rewritten in the same pass. The operator finds their agent under a
new name and a warning in the log, rather than a service that will not come
up.

The same function runs in two places, which is why it lives here and takes
plain dictionaries rather than models:

* ``Settings``, as a ``mode="before"`` validator, so *any* construction is safe
  — a worker reading the store, a script, a test, an import that was written
  before the seed existed.
* ``20260917000000_rename_colliding_agent_keys``, so the stored document is
  repaired once and the operator's console shows the new name instead of
  renaming it again on every read.

It is idempotent: a document whose colliding keys have already been renamed has
no collisions left, so a second pass changes nothing.
"""

from __future__ import annotations

import re
from typing import Any

from maljan.core.logger import logger

__all__ = [
    "AGENT_KEY_MAX_LENGTH",
    "NEWLY_RESERVED_DEFINITIONS",
    "NEWLY_RESERVED_PROFILES",
    "RENAME_SUFFIX",
    "AgentKeyRenames",
    "free_key",
    "rename_colliding_agent_keys",
    "set_if_list",
]

# The names this release took, and the only ones a rename applies to.
#
# Deliberately not "every built-in". `static`, `dynamic`, `network`, `judge`,
# `reporter`, `default` and `measurement` have been reserved for as long as
# there has been a settings store, so a stored document that edits one is an
# operator tampering with a built-in and the loud refusal is the right answer —
# it is what the console's own per-field error says, and renaming it would
# silently grow a duplicate of a built-in instead. These are different:
# they were legal names yesterday.
NEWLY_RESERVED_DEFINITIONS: frozenset[str] = frozenset(
    {"triage", "android_static", "reverser", "lead"}
)
NEWLY_RESERVED_PROFILES: frozenset[str] = frozenset({"mobile", "deep_static", "team_lead"})

# What a renamed key is called, before uniquifying. Chosen to read as the
# operator's own thing rather than as damage: `reverser_custom` is what they
# would have called it themselves had the name been taken at the time.
RENAME_SUFFIX = "_custom"

# ``AGENT_KEY_PATTERN`` allows 32 characters. A long key plus the suffix has to
# be cut rather than refused, or the rename would produce a key the model then
# rejects — which is the failure this module exists to prevent.
AGENT_KEY_MAX_LENGTH = 32


class AgentKeyRenames:
    """What was renamed, as two maps of old key to new key."""

    __slots__ = ("definitions", "profiles")

    def __init__(
        self,
        definitions: dict[str, str] | None = None,
        profiles: dict[str, str] | None = None,
    ) -> None:
        self.definitions: dict[str, str] = dict(definitions or {})
        self.profiles: dict[str, str] = dict(profiles or {})

    def __bool__(self) -> bool:
        return bool(self.definitions or self.profiles)

    def describe(self) -> str:
        parts = [f"agent {old!r} -> {new!r}" for old, new in sorted(self.definitions.items())]
        parts += [f"team {old!r} -> {new!r}" for old, new in sorted(self.profiles.items())]
        return "; ".join(parts)


def free_key(wanted: str, taken: set[str]) -> str:
    """``wanted`` with the suffix, and a counter if that is taken as well."""
    stem = wanted[: AGENT_KEY_MAX_LENGTH - len(RENAME_SUFFIX)]
    candidate = f"{stem}{RENAME_SUFFIX}"
    if candidate not in taken:
        return candidate
    for index in range(2, 1000):
        tail = f"{RENAME_SUFFIX}_{index}"
        candidate = f"{wanted[: AGENT_KEY_MAX_LENGTH - len(tail)]}{tail}"
        if candidate not in taken:
            return candidate
    # Unreachable through any document a human wrote; a key that is still taken
    # after 998 tries is a document generated by something in a loop, and a
    # deterministic last resort beats an exception at boot.
    return re.sub(r"[^a-z0-9_-]", "", f"{wanted[:20]}{RENAME_SUFFIX}_x")[:AGENT_KEY_MAX_LENGTH]


def _identity_of_definition(entry: dict[str, Any], seed: Any, key: str) -> tuple[Any, Any] | None:
    """The two dumps the identity check compares, or ``None`` if it cannot."""
    from maljan.core.config import (
        JUDGE_AGENT_KEY,
        AgentDefinition,
        _without_the_empty_builtin_tool_list,
    )

    try:
        merged = {**seed.model_dump(), **_without_the_empty_builtin_tool_list(entry)}
        current = AgentDefinition(**merged).model_dump()
    except Exception:  # noqa: BLE001 — a stored entry the seed cannot absorb is not the seed
        return None
    expected = seed.model_dump()
    if key != JUDGE_AGENT_KEY:
        current.pop("enabled", None)
        expected.pop("enabled", None)
    return current, expected


def _is_the_seeded_definition(entry: Any, seed: Any, key: str) -> bool:
    """Whether a stored entry under a seeded key *is* that seed.

    The same comparison ``AgentsConfig._seed_and_check`` makes, run early and on
    a raw dictionary. An entry that will not parse counts as not the seed, which
    is the answer that keeps the document loadable either way.
    """
    if not isinstance(entry, dict):
        return False
    pair = _identity_of_definition(entry, seed, key)
    if pair is None:
        return False
    current, expected = pair
    return bool(current == expected)


def _is_the_seeded_profile(entry: Any, seed: Any) -> bool:
    """Whether a stored team under a seeded key *is* that team."""
    from maljan.core.config import ProfileDefinition, _profile_stage_identity

    if not isinstance(entry, dict):
        return False
    try:
        current = ProfileDefinition(**entry).model_dump()
    except Exception:  # noqa: BLE001 — see ``_is_the_seeded_definition``
        return False
    expected = seed.model_dump()
    for dump in (current, expected):
        # The three fields the identity check forgives on a built-in team, and
        # the two per-stage fields it forgives inside one.
        dump.pop("exclude_servers", None)
        dump.pop("analysts", None)
        dump.pop("derived_from_analysts", None)
        dump["stages"] = _profile_stage_identity(dump.get("stages"))
    return bool(current == expected)


def set_if_list(mapping: Any, field: str, renames: dict[str, str]) -> Any:
    """``mapping`` with ``field`` rewritten, and only if it held a list.

    The one place the assignment happens, in this module and in the alembic
    revision that repairs the stored document, because getting it right at two
    of three call sites is what happened the first time. Three fields are
    rewritten — a team's `analysts`, a stage's `agents` and a server's `agents`
    — and all three are optional lists that accept no ``None``. Writing the key
    in with a ``None`` value turns a document that would have validated into
    one that will not, which is the failure this whole module exists to
    prevent: a debate stage has no `agents`, a team that carries stages needs
    no `analysts`, and a server with no agent restriction is the common case.

    Returns ``mapping`` itself when there is nothing to do, so a profile or a
    server that references no renamed key comes out of the rewrite as the same
    object it went in as. That is what keeps the migration from rewriting rows
    it has no business touching.

    The rewrite is inlined rather than delegated to a list helper on purpose.
    A helper that takes a value and hands back whatever it was given when that
    value is not a list reads as safe and is not: an absent key arrives as
    ``None`` and leaves as ``None``, and the caller writes it in. There is no
    such helper to reach for now.
    """
    if not isinstance(mapping, dict):
        return mapping
    values = mapping.get(field)
    if not isinstance(values, list):
        return mapping
    rewritten = [renames.get(v, v) if isinstance(v, str) else v for v in values]
    if rewritten == values:
        return mapping
    return {**mapping, field: rewritten}


def _rewrite_keys(mapping: Any, renames: dict[str, str]) -> Any:
    if not isinstance(mapping, dict):
        return mapping
    return {renames.get(k, k) if isinstance(k, str) else k: v for k, v in mapping.items()}


def _rename_agents_document(agents: dict[str, Any]) -> tuple[dict[str, Any], AgentKeyRenames]:
    """Rename inside ``core.agents`` and rewrite every reference it holds."""
    from maljan.core.config import _builtin_definitions, _builtin_profiles

    out = dict(agents)
    renames = AgentKeyRenames()

    definitions = out.get("definitions")
    if isinstance(definitions, dict):
        seeds = _builtin_definitions()
        taken = set(definitions) | set(seeds)
        renamed: dict[str, Any] = {}
        for key, entry in definitions.items():
            seed = seeds.get(key) if key in NEWLY_RESERVED_DEFINITIONS else None
            if seed is not None and not _is_the_seeded_definition(entry, seed, key):
                new_key = free_key(key, taken)
                taken.add(new_key)
                renames.definitions[key] = new_key
                renamed[new_key] = entry
            else:
                renamed[key] = entry
        out["definitions"] = renamed

    profiles = out.get("profiles")
    if isinstance(profiles, dict):
        profile_seeds = _builtin_profiles()
        taken = set(profiles) | set(profile_seeds)
        renamed_profiles: dict[str, Any] = {}
        for key, entry in profiles.items():
            profile_seed = profile_seeds.get(key) if key in NEWLY_RESERVED_PROFILES else None
            if profile_seed is not None and not _is_the_seeded_profile(entry, profile_seed):
                new_key = free_key(key, taken)
                taken.add(new_key)
                renames.profiles[key] = new_key
                renamed_profiles[new_key] = entry
            else:
                renamed_profiles[key] = entry
        out["profiles"] = renamed_profiles

    if renames.definitions and isinstance(out.get("profiles"), dict):
        # A renamed agent is still in whichever teams named it, under its old
        # name. Rewriting both spellings a team can use is what keeps those
        # teams valid — a stage naming an agent that no longer exists is
        # refused by the very check this rename exists to get past.
        rewritten: dict[str, Any] = {}
        for key, entry in out["profiles"].items():
            if not isinstance(entry, dict):
                rewritten[key] = entry
                continue
            profile = set_if_list(entry, "analysts", renames.definitions)
            stages = profile.get("stages")
            if isinstance(stages, list):
                restaged = [set_if_list(stage, "agents", renames.definitions) for stage in stages]
                if restaged != stages:
                    profile = {**profile, "stages": restaged}
            rewritten[key] = profile
        out["profiles"] = rewritten

    active = out.get("profile")
    if isinstance(active, str) and active in renames.profiles:
        out["profile"] = renames.profiles[active]

    return out, renames


def rename_colliding_agent_keys(document: Any) -> tuple[Any, AgentKeyRenames]:
    """Rename every colliding stored agent and team, and fix every reference.

    ``document`` is a settings-shaped mapping — the nested one ``Settings``
    validates, or the same shape assembled from stored rows by the migration.
    Returns the repaired document and what was renamed; the document is
    returned unchanged, and the renames empty, when nothing collides.

    The references that leave ``core.agents`` are rewritten here rather than in
    ``AgentsConfig``, because that model cannot see them: an agent key appears
    again in ``llm.agents``, in each MCP server's ``agents`` binding, and in the
    two ``react_*_overrides`` maps. Leaving any of them behind would silently
    drop a per-agent model choice or a timeout the operator set.
    """
    if not isinstance(document, dict):
        return document, AgentKeyRenames()
    agents = document.get("agents")
    if not isinstance(agents, dict):
        return document, AgentKeyRenames()

    renamed_agents, renames = _rename_agents_document(agents)
    if not renames:
        return document, renames

    out = {**document, "agents": renamed_agents}
    by_agent = renames.definitions

    if by_agent:
        llm = out.get("llm")
        if isinstance(llm, dict) and isinstance(llm.get("agents"), dict):
            out["llm"] = {**llm, "agents": _rewrite_keys(llm["agents"], by_agent)}

        mcp = out.get("mcp")
        if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
            servers = {
                key: set_if_list(server, "agents", by_agent)
                for key, server in mcp["servers"].items()
            }
            if servers != mcp["servers"]:
                out["mcp"] = {**mcp, "servers": servers}

        for field in ("react_agent_timeout_overrides", "react_agent_max_steps_overrides"):
            if isinstance(out.get(field), dict):
                out[field] = _rewrite_keys(out[field], by_agent)

    logger.warning(
        "An agent or team in the stored configuration used a name that is now built in, "
        "and was renamed to keep the configuration loadable: %s. "
        "Find it under the new name in Settings.",
        renames.describe(),
    )
    return out, renames
