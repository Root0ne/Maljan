# network-mcp

PCAP tooling over stdio MCP: DNS queries, conversation summaries and the
protocol breakdown of a capture the sandbox produced.

Four tools: `read_pcap_summary`, `extract_dns` and `extract_http` walk packets,
and `pcap_summary` gives the whole-capture view — external conversations, TLS
SNI destinations and detected beaconing — from `maljan.tools.pcap`.

Every one of them reads the whole capture as a stream, one packet in memory at
a time (`maljan.analysis.pcap_summary.each_packet`). `packet_limit` is
optional and has no default: a limit applies only when the caller passes one.
Every answer states how many packets it read and how many the capture holds —
the text tools on their first line (`14887 of 14887 packets in the capture
read.`), `pcap_summary` as `packets_read`, `packets_in_capture` and
`packet_limit`. `read_pcap_summary` with no `packet_limit` answers the whole
capture's facts, as `pcap_summary` writes them; with one it lists that many
packets from `offset`, one line each, and names the offset of the next page.

Launched by `maljan.core.config._builtin_servers()` as the `network` server —
`sys.executable services/network-mcp/server.py`, cwd `services/network-mcp`,
with `MALJAN_STAGING_DIR` and `MALJAN_SAMPLE_ROOTS` passed through, plus the
one directory name the spawn composes for the job (`MALJAN_STAGING_JOB`) — and
its tools are bound to the `network` analyst.

## Which captures it may read

Every `pcap_path` is resolved (symlinks followed) and refused unless it lands
inside this job's staging directory — `MALJAN_STAGING_DIR` plus the job leaf,
the same directory the analysis sidecar writes this job's uploads into, and
whose `captures/` child holds the captures fetched for this job — or one of the
directories listed in `MALJAN_SAMPLE_ROOTS` (separated by `:`, empty by
default). A capture fetched for another job is refused by every spelling, even
where a sample root contains the staging base; nothing here writes. The capture a sandbox run produced is in one of them because the
worker exports the directory it fetched it to. A relative `pcap_path` is read
inside the job's own directory (`captures/<file>`), and a bare file name inside
its captures.

A refusal is `{"error": {"code": "path_outside_roots" | "no_such_file", ...}}`
and names no host path. Its remediation lists this run's captures by those
job-relative names, or says the run holds none; `pcap_path` is required on
every tool, so it never says to leave the argument out. When a job has exactly
one capture, the platform hides `pcap_path` from the schema the network tools
are bound with and fills it in (`maljan.agents.tool_pinning`), the way it fills
the sample's own path; see "Which directories a sidecar may read" in
`docs/configuration.md`.

## Capabilities and errors

`capabilities` (no argument) answers `{server, version, tools: [{name,
optional_dependency, available, reason, timeout_s}]}`, computed when the server
starts by probing what each tool needs on this host. A tool that cannot answer
returns `{"error": {"code", "message", "remediation"}, "tool"}` rather than
raising; see *Writing a tool server* in `docs/configuration.md`.
