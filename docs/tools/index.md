# Tools

Agents reach analysis tools in three ways, and each is configuration rather
than code:

- **A static provider** — the reverse-engineering tool the static analyst
  attaches: Ghidra, radare2, capa and YARA, an MCP server of your own, or
  nothing (`core.static.provider`).
- **A sandbox provider** — where samples are detonated, or which uploaded report
  stands in (`core.sandbox.provider`).
- **Tool servers (MCP)** — the built-in sidecars, VirusTotal's own server, and
  any server an operator adds, each with the tools it exposes and the agents
  that may call it (`core.mcp.servers`).

Every call an agent makes, whichever way it went, is written to the evidence
ledger with a citable id.

<div class="grid cards" markdown>

-   :material-magnify-scan:{ .lg .middle } __Ghidra__

    ---

    The decompiler, as an MCP server in its own container. A team that needs
    it waits for it.

    [:octicons-arrow-right-24: Ghidra](ghidra.md)

-   :material-console:{ .lg .middle } __radare2__

    ---

    r2mcp over stdio, degrading cleanly when it is not installed.

    [:octicons-arrow-right-24: radare2](radare2.md)

-   :material-shield-search:{ .lg .middle } __capa and YARA__

    ---

    Deterministic capability and rule matches, as a provider, as tools and in
    the triage pack.

    [:octicons-arrow-right-24: capa and YARA](capa-yara.md)

-   :material-flask-outline:{ .lg .middle } __Sandboxes__

    ---

    CAPEv2, Hatching Triage, an uploaded report, any REST sandbox, or the mock.

    [:octicons-arrow-right-24: Sandboxes](sandboxes.md)

-   :material-earth:{ .lg .middle } __VirusTotal__

    ---

    VirusTotal's own MCP server, registered with an agent token.

    [:octicons-arrow-right-24: VirusTotal](virustotal.md)

-   :material-puzzle-outline:{ .lg .middle } __Analysis and knowledge sidecars__

    ---

    The built-in tool servers: file analysis, ATT&CK knowledge, capture views
    and reputation.

    [:octicons-arrow-right-24: Sidecars](sidecars.md)

-   :material-power-plug-outline:{ .lg .middle } __Generic MCP servers__

    ---

    Any MCP server, attached to the agents you choose, with the tools you tick.

    [:octicons-arrow-right-24: Generic MCP servers](generic-mcp.md)

</div>

## Static providers at a glance

| `core.static.provider` | What it attaches | When it is missing |
| :-- | :-- | :-- |
| `ghidra` (the shipped value) | The Ghidra MCP server's tools; `core.static.ghidra.enabled` is off by default | Does not degrade: a job whose team needs it is refused at submit |
| `r2` | r2mcp's tools | Degrades: the run goes on and names what was missing |
| `capa_yara` | No tools: two deterministic passes whose results are written to the ledger | Degrades |
| `generic_mcp` | The tools of the `core.mcp.servers` entry named by `core.static.generic.server` | Degrades |
| `none` | Nothing | — |

A job can choose its own provider with `static_provider`, a team can force one
on every member, and an agent definition can name its own. Which agents open a
provider, and what happens when one fails, is in
[Providers](../architecture.md#providers).

## Every tool says what it cannot do

Each built-in sidecar answers `capabilities`: which of its tools need an
optional library, a binary or a setting, and which of those are present on its
host. The console's server card names the unavailable tools before a run, a
tool marked unavailable is kept out of the list the model is given, and a tool
that cannot answer returns an error with a code and a remedy rather than
raising. See [Built-in tool servers](../architecture.md#built-in-tool-servers).

## The measurement baseline

The `measurement` team withholds every tool server and forces the static
provider to `none`, so the same sample can be run with and without tools. See
[Teams and profiles](../usage/teams.md#the-measurement-baseline).
