# network-mcp

PCAP tooling over stdio MCP: DNS queries, conversation summaries and the
protocol breakdown of a capture the sandbox produced.

Four tools: `read_pcap_summary`, `extract_dns` and `extract_http` walk packets,
and `pcap_summary` gives the whole-capture view — external conversations, TLS
SNI destinations and detected beaconing — from `maljan.tools.pcap`.

Launched by `maljan.core.config._builtin_servers()` as the `network` server —
`sys.executable services/network-mcp/server.py`, cwd `services/network-mcp`, no
environment variables passed through — and its tools are bound to the `network`
analyst.

## Capabilities and errors

`capabilities` (no argument) answers `{server, version, tools: [{name,
optional_dependency, available, reason, timeout_s}]}`, computed when the server
starts by probing what each tool needs on this host. A tool that cannot answer
returns `{"error": {"code", "message", "remediation"}, "tool"}` rather than
raising; see *Writing a tool server* in `docs/configuration.md`.
