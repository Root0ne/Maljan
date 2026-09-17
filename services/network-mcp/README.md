# network-mcp

PCAP tooling over stdio MCP: DNS queries, conversation summaries and the
protocol breakdown of a capture the sandbox produced.

Four tools: `read_pcap_summary`, `extract_dns` and `extract_http` walk packets,
and `pcap_summary` gives the whole-capture view — external conversations, TLS
SNI destinations and detected beaconing — from `maljan.tools.pcap`.

Launched by `maljan.core.config._builtin_servers()` as the `network` server —
`sys.executable services/network-mcp/server.py`, cwd `services/network-mcp`,
with `MALJAN_STAGING_DIR` and `MALJAN_SAMPLE_ROOTS` passed through — and its
tools are bound to the `network` analyst.

## Which captures it may read

Every `pcap_path` is resolved (symlinks followed) and refused unless it lands
inside the staging directory `MALJAN_STAGING_DIR` names or one of the
directories listed in `MALJAN_SAMPLE_ROOTS` (separated by `:`, empty by
default). The capture a sandbox run produced is in one of them because the
worker exports the directory it fetched it to. A refusal is `{"error":
{"code": "path_outside_roots", ...}}` and names no host path; see "Which
directories a sidecar may read" in `docs/configuration.md`.

## Capabilities and errors

`capabilities` (no argument) answers `{server, version, tools: [{name,
optional_dependency, available, reason, timeout_s}]}`, computed when the server
starts by probing what each tool needs on this host. A tool that cannot answer
returns `{"error": {"code", "message", "remediation"}, "tool"}` rather than
raising; see *Writing a tool server* in `docs/configuration.md`.
