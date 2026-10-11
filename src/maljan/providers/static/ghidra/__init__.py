"""The Ghidra static provider and the adapters only it uses.

``provider`` is the provider itself; ``http_client`` its REST client,
``program`` the current-program switch, ``passes`` the anti-analysis scan the
triage pack asks of it, ``call_graph`` its call graph in the neutral shape,
and ``function_hashes`` its per-function hashes. Nothing outside
``providers.static`` imports any of them: the platform asks a static provider
through the interface in ``providers.base``.

The provider's names stay importable from the package, the path the provider
registry imports and the golden capture script reads.
"""

from maljan.providers.static.ghidra.provider import (
    GHIDRA_DID_NOT_MAKE_IT_CURRENT,
    GHIDRA_GUIDANCE,
    GHIDRA_NOT_ANSWERING,
    GHIDRA_PROMPT_FRAGMENT,
    GHIDRA_WORKFLOW,
    SAMPLE_NOT_OPENED,
    UNDECLARED_LOAD_TOOL,
    GhidraStaticProvider,
    ghidra_address,
    ghidra_not_answering,
    load_failure,
    not_made_current,
    open_ghidra_sample,
    sample_not_opened,
    sample_notes_of,
)

__all__ = [
    "GHIDRA_DID_NOT_MAKE_IT_CURRENT",
    "GHIDRA_GUIDANCE",
    "GHIDRA_NOT_ANSWERING",
    "GHIDRA_PROMPT_FRAGMENT",
    "GHIDRA_WORKFLOW",
    "SAMPLE_NOT_OPENED",
    "UNDECLARED_LOAD_TOOL",
    "GhidraStaticProvider",
    "ghidra_address",
    "ghidra_not_answering",
    "load_failure",
    "not_made_current",
    "open_ghidra_sample",
    "sample_not_opened",
    "sample_notes_of",
]
