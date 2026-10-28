"""VirusTotal's own MCP server, as one built-in tool server.

VirusTotal publishes ``vt-mcp`` two ways, and the difference decides what this
module is. Over **streamable-HTTP** the server runs on VirusTotal's side at
``https://ai.virustotal.com/mcp`` and authenticates with an *agent token*
(``vtai_…``), which is obtained from ``/agents/register`` without a browser and
without a VirusTotal API key. Over **stdio** the same server runs here, as
``vt-mcp`` on PATH or ``uvx --python 3.12 vt-mcp==0.8.4``, reading the same
token from ``VTAI_TOKEN``.

The built-in seeds the HTTP transport, because it installs nothing and the
registry already sends ``auth_token`` as a bearer header. The stdio form is
kept resolvable here rather than only in the documentation for one reason:
``submit_local_file`` exists only there. The remote server cannot open this
host's filesystem, so its manifest offers ``submit_file`` (the bytes, base64)
and no local-path tool at all.

The lookups are read-only and are ticked by default. The submit tools are not:
sending a sample to VirusTotal publishes it to everyone VirusTotal shares
samples with, which is a disclosure an operator makes deliberately.

The stdio constants below have no production caller and are not meant to: the
built-in seeds the HTTP transport, and the stdio form is a second server entry
an operator types. They are the executable half of what ``apps/docs/content/docs/deployment.mdx``
tells that operator to run, pinned by a test so the documentation and the
resolution rule cannot drift apart.
"""

from __future__ import annotations

import copy
import shutil

SERVER_KEY = "virustotal"
SERVER_LABEL = "VirusTotal MCP"

# The streamable-HTTP endpoint and the REST base, as ``/agents/register``
# reports them. Held here rather than only in the seed so the registration
# service and the probe name the same host.
MCP_ENDPOINT = "https://ai.virustotal.com/mcp"
REST_BASE_URL = "https://ai.virustotal.com/api/v3"
REGISTER_URL = f"{REST_BASE_URL}/agents/register"

# What this deployment calls itself when it registers. The family is a label
# VirusTotal attributes the agent's calls to; the version tracks the ``vt-mcp``
# release whose manifest is pinned in the golden fixture.
AGENT_FAMILY = "vt-mcp-maljan"
VT_MCP_VERSION = "0.8.4"

# The stdio form. VirusTotal's own setup pins 3.12, so the fallback does too —
# ``uvx`` builds the interpreter it is told to, and an unpinned one has been
# seen to resolve to a Python the package refuses to install on.
STDIO_COMMAND = "vt-mcp"
STDIO_FALLBACK_COMMAND = "uvx"
STDIO_FALLBACK_ARGS = ("--python", "3.12", f"vt-mcp=={VT_MCP_VERSION}")

# Read-only lookups: ticked by default, and the whole default tool list.
LOOKUP_TOOLS: tuple[str, ...] = (
    "get_analysis",
    "get_domain_report",
    "get_file_report",
    "get_ip_report",
    "get_submission",
    "get_url_report",
)
# Everything that sends a sample to VirusTotal. Never ticked by a default.
# ``submit_local_file`` is stdio-only; ``submit_file`` takes the bytes.
SUBMIT_TOOLS: tuple[str, ...] = ("submit_file", "submit_local_file")


# What the catalog says of the server as a whole, beside how it is reached: it
# is a reputation service (``MCPServerConfig.roles``) and what it says of its
# lookups as a whole (``reputation_service``), the address of its
# report on a sample (``reference_urls``), and how its credential is obtained
# (``credential_bootstrap``, the generic mechanism of
# ``app.services.credential_bootstrap``): one POST naming the agent family and
# the ``vt-mcp`` release, one ``vtai_`` token back, and the agent id and public
# handle the operator recognises the deployment by in VirusTotal's own
# listing. The note is what the console said beside the button before the
# step was a declaration. Its tools are declared by nothing here: what each is
# is read from what the server lists (``core.derived_declarations``).
ROLES: tuple[str, ...] = ("reputation",)
# The service its lookups' answers are attributed to, and the rank the triage
# pack asks them at: before the threat-intel sidecar (20), which relays the
# same service through a key of its own.
REPUTATION_SERVICE: dict[str, object] = {"name": "VirusTotal", "rank": 10}
REFERENCE_URLS: tuple[str, ...] = ("https://www.virustotal.com/gui/file/{sha256}",)
CREDENTIAL_BOOTSTRAP: dict[str, object] = {
    "url": REGISTER_URL,
    "body": {"agent_family": "{family}", "agent_version": VT_MCP_VERSION},
    "token_json_path": "/agent_token",
    "token_prefix": "vtai_",
    "family": AGENT_FAMILY,
    "facts": {"public_handle": "/public_handle", "agent_id": "/agent_id"},
    "note": (
        "The agent token is free and is issued to this deployment without an account. "
        "VirusTotal enforces its own published quotas on it; a lookup over quota comes "
        "back as a 429 with a retry delay, and the analyst carries on without that answer. "
        "Only the read-only lookups are ticked. The submit tools upload the sample itself "
        "to VirusTotal, where it is shared with their customers, so they stay off until "
        "you tick them in the Tools step."
    ),
}


def stdio_command(command_exists: object = None) -> tuple[str, list[str]]:
    """The command and args that launch ``vt-mcp`` over stdio on this host.

    ``vt-mcp`` installed as a tool wins, because it is the form VirusTotal's
    own setup produces and it starts without resolving anything. Otherwise the
    call falls back to ``uvx``, which fetches the pinned release on first use.
    The lookup is injectable so a test can state which of the two a host has
    rather than depend on the host it runs on.
    """
    which = command_exists if callable(command_exists) else shutil.which
    if which(STDIO_COMMAND):
        return STDIO_COMMAND, []
    return STDIO_FALLBACK_COMMAND, list(STDIO_FALLBACK_ARGS)


def catalog_entry() -> dict[str, object]:
    """The catalog's fields of the server's block beside its launch, as a fresh copy."""
    return {
        "roles": list(ROLES),
        "reference_urls": list(REFERENCE_URLS),
        "credential_bootstrap": copy.deepcopy(CREDENTIAL_BOOTSTRAP),
        "reputation_service": dict(REPUTATION_SERVICE),
    }
