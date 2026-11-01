"""What each of this repository's stdio tool servers needs on the host, as data.

A sidecar probes these when it starts and answers them as its capability
manifest (``tools.capabilities.manifest``), which a run reads once it has
attached the server. Kept here rather than in the server's own file so the
same declaration can be checked before a job is accepted, without starting
the server: ``POST /jobs`` and the system status name a tool whose library or
executable is missing on this host (``Requirement.installed``) before any
money is spent on a run that would only say so afterwards.

Keyed by the directory under ``services/`` the server's ``server.py`` lives
in, which is what its stdio launch names, whatever key an operator gave the
server's block.
"""

from __future__ import annotations

from maljan.tools import crypto_constants, emulated_strings, readers, rules, transforms, upx
from maljan.tools.capabilities import ToolNeeds, binary, data, module

# The wall clock each rule engine is given. Named once so the tool's own
# default and the manifest that declares it cannot drift: a model told
# ``timeout_s: null`` for a scan that gives up after a minute has been told
# something untrue by the structure whose premise is that it was computed.
YARA_TIMEOUT_S = 60
# capa and FLOSS have no wall clock of the server's own: what bounds a call is
# the ``timeout_s`` its caller passes — the triage pack passes the operator's
# ``static.capa.timeout_seconds`` and what is left of ``triage.budget_seconds``
# — and a call that passes none is bounded by the job's timeout. Their time
# grows with the sample's code, not with anything the server can know in
# advance, and a fixed ceiling stopped a large sample's emulation half-way
# whatever the operator had allowed. The manifest declares ``timeout_s: null``.
CAPA_TIMEOUT_S: int | None = None
FLOSS_TIMEOUT_S: int | None = emulated_strings.FLOSS_TIMEOUT_S

# capa and YARA are extras of their own (``pyproject.toml``), so the general
# remedy, which names the ``tools`` extra, would name the wrong one.
CAPA_REMEDIATION = "install capa on the host that runs this server: uv sync --extra capa"
YARA_REMEDIATION = "install yara-python on the host that runs this server: uv sync --extra yara"

# The rule corpora fetched rather than vendored (``.gitignore``), so a fresh
# clone or worktree has none until they are fetched. The worker hands its own
# reading of capa the operator's setting, and the server's tool reads the
# default; Sigma's are the server's default unless its environment names
# others. A tool whose data is vendored declares none.
CAPA_RULES = data(rules.DEFAULT_CAPA_RULES, setting="static.capa.rules_dir", pattern="*.yml")
SIGMA_RULES = data(rules.DEFAULT_SIGMA_RULES, override=rules.SIGMA_RULES_ENV, pattern="*.y*ml")

# What each tool needs beyond the interpreter, probed once when the server
# starts (a data path only before a job). A tool that is not listed always answers.
ANALYSIS: list[ToolNeeds] = [
    ToolNeeds("identify_file"),
    ToolNeeds("hashes"),
    ToolNeeds("signing_info"),
    ToolNeeds("strings"),
    ToolNeeds("iocs_from_text"),
    ToolNeeds("iocs_from_file"),
    ToolNeeds("pe_info", (module("pefile"),)),
    ToolNeeds("elf_info", (module("elftools"),)),
    ToolNeeds("macho_info", (module("macholib"),)),
    ToolNeeds("apk_info", (module("androguard"),), without="the zip-level facts"),
    ToolNeeds("carve_payloads"),
    ToolNeeds(upx.TOOL, facts=upx.CAPABILITY_FACTS),
    ToolNeeds(
        "archive_list",
        (module("py7zr"),),
        without="zip and tar members; 7z needs py7zr",
        without_reads=("7z",),
    ),
    ToolNeeds("document_info", (module("olefile"),), without="the PDF and OOXML halves"),
    ToolNeeds(
        "yara_scan",
        (module("yara"),),
        timeout_s=YARA_TIMEOUT_S,
        without="the regex fallback over the corpus",
        remediation=YARA_REMEDIATION,
    ),
    ToolNeeds("sigma_match", (module("sigma"), SIGMA_RULES)),
    ToolNeeds("sigma_match_sandbox", (module("sigma"), SIGMA_RULES)),
    ToolNeeds(
        "capa",
        (module("capa"), CAPA_RULES),
        timeout_s=CAPA_TIMEOUT_S,
        long_running=True,
        remediation=CAPA_REMEDIATION,
    ),
    ToolNeeds(
        "floss",
        (binary("floss", emulated_strings.floss_unavailable),),
        timeout_s=FLOSS_TIMEOUT_S,
        long_running=True,
        remediation=emulated_strings.FLOSS_REMEDIATION,
    ),
    ToolNeeds("resolve_api_hashes"),
    ToolNeeds("decode_string_blobs"),
    ToolNeeds(crypto_constants.TOOL),
    ToolNeeds("function_index"),
    ToolNeeds(
        transforms.TOOL,
        (module("cryptography"),),
        without="every operation but aes",
        facts=transforms.CAPABILITY_FACTS,
    ),
    ToolNeeds("put_sample"),
    ToolNeeds("put_sample_begin"),
    ToolNeeds("put_sample_chunk"),
    ToolNeeds("put_sample_finish"),
    ToolNeeds(readers.RUN_READER),
    ToolNeeds(readers.RELEASE_JOB),
]

# The two retrievals over a vector store need its client; every other lookup
# reads the vendored catalogues.
KNOWLEDGE: list[ToolNeeds] = [
    ToolNeeds("resolve_technique"),
    ToolNeeds("attck_lookup"),
    ToolNeeds("attck_validate"),
    ToolNeeds("api_capability"),
    ToolNeeds("lolbin_lookup"),
    ToolNeeds("family_lookup", (module("qdrant_client"),)),
    ToolNeeds("similar_cases", (module("qdrant_client"),)),
]

# Every tool here reads the capture with the platform's own reader, which
# needs no optional library.
NETWORK: list[ToolNeeds] = [
    ToolNeeds("read_pcap_summary"),
    ToolNeeds("extract_dns"),
    ToolNeeds("extract_http"),
    ToolNeeds("pcap_summary"),
    ToolNeeds(readers.RUN_READER),
    ToolNeeds(readers.RELEASE_JOB),
]

# The threat-intel server is not here: what its lookups need is a service's
# key, a setting the worker hands it, not a library or an executable this
# host can be checked for.
BY_DIRECTORY: dict[str, list[ToolNeeds]] = {
    "analysis-mcp": ANALYSIS,
    "knowledge-mcp": KNOWLEDGE,
    "network-mcp": NETWORK,
}


def without_reads(tool: str, server: str | None = None) -> frozenset[str] | None:
    """The routed formats only the missing requirement of ``tool`` reads, or ``None`` unsaid.

    Read from the shipped declarations above (``ToolNeeds.without_reads``):
    ``server`` is the key a built-in sidecar is attached under (``analysis``
    for ``analysis-mcp``), and with none every shipped sidecar is looked in, as
    for a pack step's token, which names no server. ``None`` when no shipped
    tool of that name says which formats its missing part reads.
    """
    lists = (
        [BY_DIRECTORY[f"{server}-mcp"]]
        if server is not None and f"{server}-mcp" in BY_DIRECTORY
        else []
        if server is not None
        else list(BY_DIRECTORY.values())
    )
    for needs in lists:
        for entry in needs:
            if entry.name == tool and entry.without_reads:
                return frozenset(entry.without_reads)
    return None
