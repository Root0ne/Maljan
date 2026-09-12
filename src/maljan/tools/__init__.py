"""Analysis capabilities as callable tools rather than pipeline stages.

Every function in this package is a plain function: explicit arguments, a
JSON-serialisable ``dict`` return, no ``Settings`` lookup and no global state
beyond a load cache for a rule corpus. That is what lets the same code back
both an in-process caller and a ``FastMCP`` sidecar under ``services/`` — the
sidecar is a thin ``@mcp.tool()`` wrapper and nothing else.

Two rules hold across the package:

* **facts, not verdicts.** A packer section name is reported as a match, not
  as "packed"; a capa rule is reported as a capability, not as malice. The
  judgement is the agent's job, and a tool that pre-judges removes the
  evidence the agent would have weighed.
* **an optional dependency is never fatal.** A function whose library is
  missing returns ``{"error": "<module> is not installed", ...}`` so the tool
  still exists on the manifest and the caller learns why it is empty.
"""

from __future__ import annotations
