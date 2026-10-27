"""What a tool server declares of its own tools, read when the client lists them.

Any MCP server may declare its tools itself, in each tool's definition as it
lists them (``maljan.tools.declared_facts``): the MCP ``annotations`` (kept on
each entry as the server's hints, ``core.declared_reading.with_hints``) and,
under the definition's ``_meta`` at :data:`FACTS_META_KEY`, a declaration in
the vocabulary of :class:`~maljan.core.tool_declarations.ToolFacts`. This
module reads that declaration for every server alike, by what the definition
holds, never by the server's or the tool's name:

* :func:`served_tool_facts` reads one server's listing: each tool's
  declaration as the model reads a stored one, leniently (a field this version
  does not know is left out with a warning; a declaration the model refuses is
  left out whole, with a warning), and each ``aggregate_of`` holding only
  tools the server listed. Everything read is the server's data, never trusted
  beyond what the model accepts.
* :func:`register_served` keeps the last listing of each source
  (``mcp:<key>``, ``provider:<id>``), made when its handle attached
  (``providers.servers``, a static provider's own attach), under the launch
  identity of the block that reached it (``tool_declarations.launch_identity``),
  and has held declarations rebuilt (``tool_declarations.declaration_version``).
  A block pointed at another server reads none of it.
* :func:`with_served` lays a source's served declaration under what its
  settings block puts in force (``ToolDeclarations.from_settings``), per tool
  and field by field: what the block says (an operator's stored declaration,
  and what the platform ships for a built-in block) is in force over what the
  server declares, and what neither says is not declared at all. A tool the
  block ships and an operator removed stays removed, whatever its server says.
  ``effects`` is merged one level down, as a stored change over a shipped
  declaration is (``tool_declarations.SUBFIELD_MERGED``).

**Whose word it is.** A server's declaration is its own claim about itself.
Only a block that trusts it (``trusts_served_declaration``: set by an operator
for a server they vouch for, and shipped set for the platform's own sidecars)
reads it as a declaration. Any other block reads only the claims that make
the platform more careful (:func:`_cautious`: it sends the sample or its hash
out, reaches the network, runs something, or is not read-only), and each
field such a claim sets is stored with the tool's entries as the server's own
statement: said, never moving a call to another row of the disclosure or the
effects part, and never read as declared by a reader of a stored record
(``core.declared_reading.declared_only``). Its kind is never put in force,
since a kind routes a tool, names its sections and tags it: a kind whose
answer moves or that reaches outside is kept apart as a claim
(``Declared.served_claims``), stored and said as the server's, and read only
by the reuse veto (``agents.tool_pinning``). The rest of it is what the
connection test proposes to the operator (``core.declaration_proposals``).
No block reads a kind of what a sandbox observed (``sandbox_...``) from a
server's claim unless the block's ``roles`` hold ``sandbox``.

A served declaration is read only where the live declarations are: by the
writer of an entry's facts and by the tools a request is about to offer. An
entry stores the facts in force when it was written, so a stored run never
reads a server's declaration again. A run's recorded declaration digests are
of the blocks alone; what each server declared is recorded by its own digest
when it attaches (:func:`served_digest`).
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ValidationError

from maljan.core.logger import logger
from maljan.core.tool_declarations import (
    EXECUTES_NO,
    KIND_DEPENDENT_FIELDS,
    SANDBOX_ROLE,
    SUBFIELD_MERGED,
    THIRD_PARTY_BYTES,
    THIRD_PARTY_HASH,
    ToolFacts,
    bump_declaration_version,
    check_tool_name,
    declaration_digest,
    known_aggregates,
    lenient_declaration,
    loggable_names,
)
from maljan.tools.declared_facts import FACTS_META_KEY

if TYPE_CHECKING:
    from maljan.core.tool_declarations import Declared

__all__ = [
    "FACTS_META_KEY",
    "forget_served",
    "laid_under",
    "layered",
    "register_served",
    "served",
    "served_digest",
    "served_facts_of",
    "served_tool_facts",
    "with_served",
]

# The start of every kind that says its answer is what a sandbox observed.
OBSERVED_KIND_PREFIX = "sandbox_"

_LOCK = threading.Lock()
# Each source's last served declaration, by its source text, with the launch
# identity of the block it was listed through.
_SERVED: dict[str, tuple[str, dict[str, ToolFacts]]] = {}


def _meta_of(definition: Any) -> Any:
    """A tool definition's ``_meta``: the SDK's object's ``meta``, or a mapping's ``_meta``."""
    if isinstance(definition, Mapping):
        held = definition.get("_meta")
        return held if held is not None else definition.get("meta")
    return getattr(definition, "meta", None)


def _name_of(definition: Any) -> str:
    if isinstance(definition, Mapping):
        return str(definition.get("name") or "")
    return str(getattr(definition, "name", "") or "")


def served_facts_of(definition: Any, where: str = "") -> ToolFacts | None:
    """What one tool definition declares under :data:`FACTS_META_KEY`; ``None`` for nothing.

    Read leniently, as a stored declaration is: unknown fields are left out
    and named in one warning; a declaration the model refuses, or one that is
    not a mapping, declares nothing, with a warning.
    """
    meta = _meta_of(definition)
    raw = meta.get(FACTS_META_KEY) if isinstance(meta, Mapping) else None
    if raw is None:
        return None
    name = _name_of(definition)
    if not isinstance(raw, Mapping):
        logger.warning(
            "Tool %s declares facts that are not a mapping; it is read as undeclared.",
            loggable_names([f"{where}{name}"]),
        )
        return None
    kept, left_out = lenient_declaration(raw)
    if left_out:
        logger.warning(
            "Tool %s declares fields this version does not read: %s; they are left out.",
            loggable_names([f"{where}{name}"]),
            loggable_names(left_out),
        )
    try:
        return ToolFacts.model_validate(kept)
    except ValidationError as exc:
        logger.warning(
            "Tool %s declares facts the model refuses (%d error(s)); it is read as undeclared.",
            loggable_names([f"{where}{name}"]),
            exc.error_count(),
        )
        return None


def served_tool_facts(definitions: Iterable[Any], where: str = "") -> dict[str, ToolFacts]:
    """Every tool a server's listing declares, by the name the server lists it under.

    A definition whose name no tool can have, or that declares nothing, is
    left out; each ``aggregate_of`` holds only tools of the listing
    (``tool_declarations.known_aggregates``).
    """
    out: dict[str, ToolFacts] = {}
    for definition in definitions:
        name = _name_of(definition)
        try:
            check_tool_name(name)
        except ValueError:
            continue
        facts = served_facts_of(definition, where)
        if facts is not None:
            out[name] = facts
    try:
        return known_aggregates(out, where=where)
    except ValueError:
        # Strict only in an operator's edit, which no listing is.
        return {name: f.model_copy(update={"aggregate_of": ()}) for name, f in out.items()}


def served_digest(tool_facts: Mapping[str, ToolFacts]) -> str:
    """A short digest of what a server declared of its tools; ``""`` for nothing."""
    if not tool_facts:
        return ""
    body = {name: _set_fields(facts) for name, facts in sorted(tool_facts.items())}
    return declaration_digest({"tool_facts": body})


def register_served(source: str, tool_facts: Mapping[str, ToolFacts], launch: str = "") -> None:
    """Keep ``tool_facts`` as what ``source`` declares now; held declarations are rebuilt.

    Kept under the launch identity of the block that started or reached the
    server (``tool_declarations.launch_identity``): a block pointed elsewhere
    later reads none of it. A listing that declares nothing forgets what the
    source declared before.
    """
    held = dict(tool_facts)
    with _LOCK:
        before = _SERVED.get(source)
        after = (launch, held) if held else None
        if after is None:
            _SERVED.pop(source, None)
        else:
            _SERVED[source] = after
        changed = before != after
    if changed:
        bump_declaration_version()


def served(source: str, launch: str | None = None) -> Mapping[str, ToolFacts]:
    """What ``source`` declared when it was last listed; empty for a source not listed.

    With ``launch``, only what it declared under that launch identity: a
    declaration kept under another one is not read (and stays kept until the
    source's next listing replaces it).
    """
    with _LOCK:
        held = _SERVED.get(str(source))
    if held is None:
        return {}
    kept_under, facts = held
    if launch is not None and kept_under and launch and kept_under != launch:
        return {}
    return dict(facts)


def forget_served(source: str | None = None) -> None:
    """Forget what ``source`` declared, or what every source did."""
    with _LOCK:
        if source is None:
            changed = bool(_SERVED)
            _SERVED.clear()
        else:
            changed = _SERVED.pop(str(source), None) is not None
    if changed:
        bump_declaration_version()


def _set_fields(facts: ToolFacts) -> dict[str, Any]:
    """The fields ``facts`` sets: each one it was given, and each that differs from its default.

    A field given at its default is set: an operator who cleared a tool's
    routed formats meant none, whatever its server declares.
    """
    given = set(facts.model_fields_set)
    given.update(facts.model_dump(exclude_defaults=True))
    out = facts.model_dump(mode="json", include=given)
    for name in SUBFIELD_MERGED:
        sub = getattr(facts, name, None)
        if name in out and isinstance(sub, BaseModel):
            own = set(sub.model_fields_set)
            own.update(sub.model_dump(exclude_defaults=True))
            out[name] = sub.model_dump(mode="json", include=own)
    return out


def _over(above: ToolFacts, below: ToolFacts) -> ToolFacts:
    """``above`` field by field over ``below``; ``above`` as it is where the two cannot merge."""
    upper, lower = _set_fields(above), _set_fields(below)
    merged = {**lower, **upper}
    for name in SUBFIELD_MERGED:
        top, bottom = upper.get(name), lower.get(name)
        if isinstance(top, Mapping) and isinstance(bottom, Mapping):
            merged[name] = {**bottom, **top}
    try:
        return ToolFacts.model_validate(merged)
    except ValidationError:
        return above


def _observed(kind: str) -> bool:
    """Whether ``kind`` says its answer is what a sandbox observed the sample do."""
    return kind.startswith(OBSERVED_KIND_PREFIX)


def _without_observed_kind(facts: ToolFacts, roles: Iterable[str]) -> ToolFacts | None:
    """``facts`` without a kind of what a sandbox observed, unless the block is a sandbox's.

    Only a block whose ``roles`` hold ``sandbox`` is read as one whose tools
    report what the sample did; a server saying so of itself is not. Such a
    claim is left out with the fields only its kind makes readable;
    ``None`` when nothing is left.
    """
    if not _observed(facts.kind) or SANDBOX_ROLE in set(roles):
        return facts
    kept = {
        name: value
        for name, value in _set_fields(facts).items()
        if name != "kind" and name not in KIND_DEPENDENT_FIELDS
    }
    if not kept:
        return None
    try:
        return ToolFacts.model_validate(kept)
    except ValidationError:
        return None


def _cautious(facts: ToolFacts) -> tuple[dict[str, Any], tuple[str, ...]]:
    """What a server's untrusted declaration says that only makes the platform more careful.

    It sends the sample (``discloses_sample``), or its hash or bytes to a
    third party; it reaches the network; it runs something; it is not
    read-only, said outright. Each with
    the dotted name of the field it sets. Never its kind (:func:`_claimed_kind`).
    """
    out: dict[str, Any] = {}
    named: list[str] = []
    if facts.discloses_sample is True:
        out["discloses_sample"] = True
        named.append("discloses_sample")
    effects = facts.effects
    if effects is not None:
        cautious: dict[str, Any] = {}
        if effects.third_party in (THIRD_PARTY_HASH, THIRD_PARTY_BYTES):
            cautious["third_party"] = effects.third_party
        # Reaching the sandbox service its server fronts is a place, not a
        # caution: only a plain "it reaches the network" is taken.
        if effects.network is True:
            cautious["network"] = True
        if effects.executes not in ("", EXECUTES_NO):
            cautious["executes"] = effects.executes
        if cautious:
            out["effects"] = cautious
            named.extend(f"effects.{name}" for name in cautious)
    if "read_only" in facts.model_fields_set and facts.read_only is False:
        out["read_only"] = False
        named.append("read_only")
    return out, tuple(named)


def _claimed_kind(facts: ToolFacts, roles: Iterable[str]) -> str:
    """The kind an untrusted server claims of its tool, where it can only make the platform careful.

    One whose answer moves or that reaches outside the deployment
    (``builtin_declarations.MOVING_KINDS``, ``OUTWARD_KINDS``), but never a
    reputation the verdict reads nor what a sandbox observed outside a
    sandbox's block; ``""`` otherwise. Never put in force: kept apart as the
    server's claim (``Declared.served_claims``).
    """
    from maljan.core.builtin_declarations import MOVING_KINDS, OUTWARD_KINDS, REPUTATION_KINDS

    kind = facts.kind
    if (
        kind
        and (kind in MOVING_KINDS or kind in OUTWARD_KINDS)
        and kind not in REPUTATION_KINDS
        and (not _observed(kind) or SANDBOX_ROLE in set(roles))
    ):
        return kind
    return ""


def _unset_in(held: ToolFacts | None, dotted: str) -> bool:
    """Whether ``held`` leaves the field ``dotted`` (``effects.network``) unset."""
    if held is None:
        return True
    top, _, sub = dotted.partition(".")
    fields = _set_fields(held)
    if not sub:
        return top not in fields
    below = fields.get(top)
    return not isinstance(below, Mapping) or sub not in below


def layered(
    held: Mapping[str, ToolFacts],
    served_facts: Mapping[str, ToolFacts],
    removed: Iterable[str] = (),
    *,
    trusted: bool = True,
    roles: Iterable[str] = (),
) -> tuple[dict[str, ToolFacts], dict[str, tuple[str, ...]], dict[str, dict[str, Any]]]:
    """``held`` over ``served_facts`` per tool and field; what only the server said; its claims.

    A tool in ``removed`` stays out. ``trusted``: the server's declaration
    fills whatever ``held`` leaves unset, but a kind of what a sandbox
    observed outside a sandbox's block (``roles``). Otherwise only its
    cautious claims (:func:`_cautious`) do, and each field they set that
    ``held`` did not is returned for the tool, to be stored with its entries
    as the server's own statement; a kind it claims (:func:`_claimed_kind`)
    where ``held`` declares none is returned apart, never put in force.
    """
    gone = set(removed)
    kept_roles = tuple(roles)
    out = dict(held)
    said: dict[str, tuple[str, ...]] = {}
    claims: dict[str, dict[str, Any]] = {}
    for tool, facts in served_facts.items():
        if tool in gone:
            continue
        own = held.get(tool)
        if trusted:
            claim = _without_observed_kind(facts, kept_roles)
            if claim is not None:
                out[tool] = claim if own is None else _over(own, claim)
            continue
        kind = _claimed_kind(facts, kept_roles)
        if kind and not (own is not None and own.kind):
            claims[tool] = {"kind": kind}
        cautious, named = _cautious(facts)
        if "discloses_sample" in cautious and not (
            _unset_in(own, "effects.third_party") and _unset_in(own, "effects.network")
        ):
            # Sending the sample's bytes says where they go: never over what
            # the block itself says of the tool's network and third party.
            cautious.pop("discloses_sample")
            named = tuple(name for name in named if name != "discloses_sample")
        if not cautious:
            continue
        try:
            claim = ToolFacts.model_validate(cautious)
        except ValidationError:
            continue
        merged = claim if own is None else _over(own, claim)
        fresh = tuple(name for name in named if _unset_in(own, name))
        if fresh:
            out[tool] = merged
            said[tool] = fresh
    return out, said, claims


def with_served(declared: Declared) -> Declared:
    """``declared`` with what its source's server declares laid under its own tools.

    In full where the block trusts its server's declaration
    (``trusts_served_declaration``); its cautious claims alone otherwise,
    each kept as the server's own statement (``Declared.served_fields``), and
    the kind it claims kept apart (``Declared.served_claims``).
    """
    return laid_under(declared, served(str(declared.source), declared.launch))


def laid_under(declared: Declared, held: Mapping[str, ToolFacts]) -> Declared:
    """``declared`` with ``held``, what its server declares of its tools, laid under its own.

    As :func:`with_served` lays what is kept, for a listing nothing has kept
    yet (a handle tagging its tools before its attach has succeeded).
    """
    from maljan.core.declared_reading import shipped_tools_of

    if not held:
        return declared
    removed = shipped_tools_of(str(declared.source)) - set(declared.tools)
    tools, said, claims = layered(
        declared.tools,
        held,
        removed,
        trusted=declared.trusts_served,
        roles=declared.roles,
    )
    return dataclasses.replace(declared, tools=tools, served_fields=said, served_claims=claims)
