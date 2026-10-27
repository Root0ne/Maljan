"""What a tool server says of each of its own tools, when it lists them.

A tool server declares its tools itself, in two parts of each tool's MCP
definition that any server can fill:

* the MCP ``annotations``: a ``title``, and ``readOnlyHint``,
  ``idempotentHint``, ``destructiveHint`` and ``openWorldHint``;
* under the definition's ``_meta``, at :data:`FACTS_META_KEY`, a declaration in
  the vocabulary of the platform's tool declarations
  (``core.tool_declarations.ToolFacts``): its kind, where its answer's rows,
  places and values are, the techniques it names, the formats it serves, what
  it shows and does not show, what a call does beyond answering, its budget.

The client reads both generically, for every server it attaches
(``core.served_declarations``), with what an operator stored for the tool over
it field by field; nothing is read by a server's or a tool's name. The
platform's own sidecars that import the platform declare their tools with
:func:`tool_declaration`; a sidecar that imports nothing of the platform
(``services/cli-sidecar``) writes the same two parts with a copy of it.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from mcp.types import ToolAnnotations

# The key of a tool definition's ``_meta`` under which its server declares it.
# Prefixed as MCP asks of a key that is not the protocol's own.
FACTS_META_KEY = "maljan/tool_facts"

# What a call does beyond answering (``ToolFacts.effects``), in the words every
# declaration uses: it runs nothing of the sample, reaches nothing beyond its
# own server and sends nothing of the sample to a third party.
NO_EFFECT: dict[str, Any] = {"executes": "no", "network": False, "third_party": "no"}


def tool_declaration(
    title: str,
    facts: Mapping[str, Any],
    *,
    read_only: bool = False,
    destructive: bool = False,
) -> dict[str, Any]:
    """The keyword arguments of FastMCP's ``tool`` decorator that declare one tool.

    ``facts`` is the tool's declaration; ``read_only`` says an identical call
    changes nothing and answers the same, and is declared both as the
    declaration's ``read_only`` and as the MCP hints ``readOnlyHint`` and
    ``idempotentHint``. ``destructive`` says a call removes something (a job's
    staged files). ``openWorldHint`` is what the declared effects say: a tool
    that reaches a network service beyond its own server.
    """
    held = copy.deepcopy(dict(facts))
    if read_only:
        held["read_only"] = True
    effects = held.get("effects")
    open_world = isinstance(effects, Mapping) and effects.get("network") is True
    return {
        "annotations": ToolAnnotations(
            title=title,
            readOnlyHint=read_only,
            destructiveHint=destructive and not read_only,
            idempotentHint=read_only,
            openWorldHint=open_world,
        ),
        "meta": {FACTS_META_KEY: held},
    }
