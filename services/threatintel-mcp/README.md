# threatintel-mcp

Reputation lookups over stdio MCP: VirusTotal file and URL verdicts, AbuseIPDB
address reports, with a mock fallback when neither key is set.

Launched by `maljan.core.config._builtin_servers()` as the `threatintel` server —
`sys.executable services/threatintel-mcp/server.py`, cwd `services/threatintel-mcp`,
with `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` passed through — and its tools
are bound to the `judge`.

## Capabilities and errors

`capabilities` (no argument) answers `{server, version, tools: [{name,
optional_dependency, available, reason, timeout_s}]}`, computed when the server
starts by probing what each tool needs on this host. A tool that cannot answer
returns `{"error": {"code", "message", "remediation"}, "tool"}` rather than
raising; see *Writing a tool server* in `docs/configuration.md`.
