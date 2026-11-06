"""What kind of work an agent does, as its definition declares it.

An agent definition's ``role`` picks the code that runs it (``static``,
``dynamic``, ``network`` and ``judge`` are classes; ``generic`` and ``lead``
are a prompt and tools), so an operator's own reverser is a ``generic`` agent
and the role says nothing about the code it reads. The platform still has to
know what an agent does to decide which of its own steps to offer it, and it
used to work that out from the tools the agent called. ``category`` is that
fact, declared:

* ``code_reader`` reads the sample's code: decompiled or disassembled
  functions. Shown as Reverser.
* ``static`` reads the sample's static facts without its code: format
  header, imports, strings, rule matches.
* ``dynamic`` reads what the sample did when it ran: the sandbox report.
* ``network`` reads the sample's network traffic and indicators.
* ``intel`` looks indicators up: reputation and threat intelligence.
* ``other`` is none of these, or more than one. The platform then works out
  what it can from the agent's tools and what they returned, as it did before
  the field existed.

A category decides only which platform steps an agent is offered. It never
restricts the tools an agent may call.

A definition stored before the field existed reads the category its role and
tools fit (:func:`fitting_category`); revision ``20261103000000`` writes that
value into the stored document once. The rule reads the role, the kinds of the
tool references and the input slices a definition names, never its name or the
name of a tool or server. Where they tell nothing, the category is ``other``,
which is exactly today's behaviour, and the caller says so.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "AGENT_CATEGORIES",
    "CATEGORY_REQUIRED",
    "CODE_READER",
    "OTHER",
    "ROLE_CATEGORIES",
    "declared_category",
    "fitting_category",
]

CODE_READER = "code_reader"
OTHER = "other"
# Every category a definition may declare, in the order the console offers them.
AGENT_CATEGORIES: tuple[str, ...] = (CODE_READER, "static", "dynamic", "network", "intel", OTHER)

# Why a new definition without a category is refused, in one sentence the
# settings API puts under the field.
CATEGORY_REQUIRED = (
    "choose the category that matches what this agent does: "
    + ", ".join(AGENT_CATEGORIES)
    + " (other when none fits)"
)

# The category each role with a class of its own fits. The static analyst's
# class reads its provider's decompiled functions, so it is a code reader; the
# judge and the reporter do none of the analysts' work. ``generic`` and
# ``lead`` are a prompt and tools and are read from their tools.
ROLE_CATEGORIES: dict[str, str] = {
    "static": CODE_READER,
    "dynamic": "dynamic",
    "network": "network",
    "judge": OTHER,
    "report": OTHER,
}

# The capability a reputation lookup is declared under (``core.reputation.
# REPUTATION_KIND``), restated so this module imports nothing of the settings.
_REPUTATION = "reputation"
_SANDBOX_PREFIX = "sandbox."
_SANDBOX_NETWORK = "sandbox.network"


def _get(item: Any, field: str) -> Any:
    """One field of a model or of its stored dict."""
    if isinstance(item, Mapping):
        return item.get(field)
    return getattr(item, field, None)


def fitting_category(definition: Any) -> tuple[str, bool]:
    """The category a definition's role and tools fit, and whether they told it.

    ``definition`` is a stored dict or a model. The second value is ``False``
    where nothing told the category and ``other`` stands in for it: the
    caller reports that rather than passing it over in silence. For a
    ``generic`` or ``lead`` definition, in order:

    * a ``provider`` reference: the agent holds a static provider's own
      tools, which open and read the sample's code -> ``code_reader``;
    * a ``sandbox`` reference -> ``dynamic``;
    * input slices that are all the sandbox's network capture -> ``network``,
      any other sandbox slice -> ``dynamic``;
    * tools that are only reputation capabilities (asks of other agents
      aside) -> ``intel``.
    """
    role = str(_get(definition, "role") or "")
    if role in ROLE_CATEGORIES:
        return ROLE_CATEGORIES[role], True
    tools = _get(definition, "tools")
    refs = list(tools) if isinstance(tools, list | tuple) else []
    kinds = [str(_get(ref, "kind") or "") for ref in refs]
    if "provider" in kinds:
        return CODE_READER, True
    if "sandbox" in kinds:
        return "dynamic", True
    sources = _get(definition, "data_sources")
    named = [str(s) for s in sources] if isinstance(sources, list | tuple) else []
    if named and all(s == _SANDBOX_NETWORK for s in named):
        return "network", True
    if any(s.startswith(_SANDBOX_PREFIX) for s in named):
        return "dynamic", True
    own = [ref for ref, kind in zip(refs, kinds, strict=True) if kind != "agent"]
    if own and all(
        _get(ref, "kind") == "capability" and _get(ref, "capability") == _REPUTATION for ref in own
    ):
        return "intel", True
    return OTHER, False


def declared_category(definition: Any) -> str | None:
    """The category a definition or a resolved agent declares, or ``None`` for none.

    ``None`` for no definition, for one that names no category and for a
    value that is not a category, so the caller falls back to what the
    agent's tools returned, exactly as for ``other``.
    """
    if definition is None:
        return None
    value = _get(definition, "category")
    return str(value) if value in AGENT_CATEGORIES else None
