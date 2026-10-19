# threatintel-mcp

Reputation lookups over stdio MCP: VirusTotal hash, domain and address verdicts
and AbuseIPDB address reports. A lookup whose service has no key answers
nothing in its place: its manifest cell is unavailable, so the platform
withholds it, and a call that reaches it answers `not_configured`. Every
indicator is checked for its shape (IP address, DNS name, MD5/SHA-1/SHA-256
hex digest) before a URL is built from it; anything else answers
`bad_argument`, and an address that is not public answers "not a public address". Every
lookup answers JSON: VirusTotal's engine counts under `last_analysis_stats` (a count it
did not give is absent, and no counts give no verdict) and a `summary`.

Launched by `maljan.core.config._builtin_servers()` as the `threatintel` server —
`sys.executable services/threatintel-mcp/server.py`, cwd `services/threatintel-mcp`,
with `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` passed through — and its tools
are bound to the `judge`.

## Capabilities and errors

`capabilities` (no argument) answers `{server, version, tools: [{name,
optional_dependency, available, reason, timeout_s}]}`, computed when the server
starts by probing what each tool needs on this host. A tool that cannot answer
returns `{"error": {"code", "message", "remediation"}, "tool"}` rather than
raising; see *Writing a tool server* in `apps/docs/content/docs/configuration.mdx`.
