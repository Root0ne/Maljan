# VirusTotal

`virustotal` is a built-in tool server that is not a process of the
deployment: it is VirusTotal's own MCP server, reached over streamable-HTTP at
`https://ai.virustotal.com/mcp`. Nothing is installed for it and no VirusTotal
API key is involved. It ships **disabled**, because it needs a credential only a
registration produces.

## Register

<div class="mj-steps" markdown>

1. Open **Settings → Setup guides → Add a tool server → Connect VirusTotal**.
2. Press the button. It calls `POST /api/v1/settings/virustotal/register`, which
   asks VirusTotal for an agent token, stores it as this server's `auth_token`
   in its own encrypted row, turns the server on, and answers with the masked
   state and the public handle VirusTotal now knows the deployment by.
3. Test it. Until a token is stored, the Test button answers "no agent token"
   rather than dialling out.

</div>

Registering again replaces the token.

## The tools

| Tool | Ticked by default | What leaves the host |
| :-- | :-- | :-- |
| `get_file_report` | yes | a hash |
| `get_url_report` | yes | a URL |
| `get_domain_report` | yes | a domain |
| `get_ip_report` | yes | an IP address |
| `get_analysis` | yes | an analysis id |
| `get_submission` | yes | a submission id |
| `submit_file` | **no** | the sample's bytes |

!!! danger "Ticking `submit_file` publishes the sample"

    The sample's bytes are uploaded to VirusTotal, shared with VirusTotal's
    customers and partners under their own terms, and cannot be recalled. For a
    sample belonging to a client, carrying customer data or under an NDA, that
    is a decision to make deliberately. See [What the VirusTotal server
    sends](../security.md#what-the-virustotal-server-sends).

## Who uses it

`virustotal` is referenced by every agent that reads the file or weighs the
run: the `static` and `network` analysts, the judge, and the seeded `triage`,
`android_static` and `reverser` agents. Their prompts say to look the hash up
once, cite it like any other tool result, and treat a reputation label as one
source rather than as the verdict. The triage pack makes one reputation lookup
on the sample's sha256 through it when it is enabled. A disabled server
contributes no tools and no degradation reason.

Over quota, the server answers a call with a 429 carrying `Retry-After`; the
agent records that answer and carries on without it.

## Beside the threat-intel sidecar

`services/threatintel-mcp` still offers VirusTotal and AbuseIPDB lookups over
their REST APIs with `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY`. Where both
are on, `virustotal` supersedes its VirusTotal half, while AbuseIPDB stays the
only source for IP abuse reports. See [Analysis and knowledge
sidecars](sidecars.md).

## The stdio alternative

The same server runs locally as `vt-mcp`, reading the agent token from
`VTAI_TOKEN`, and that form offers `submit_local_file`, which uploads by path.
Install it only if you want that tool:

```bash
uv tool install --python 3.12 vt-mcp==0.8.4
```

Add it as a second tool server with transport `stdio`, and put `VTAI_TOKEN` in
its `env_allow` so the token reaches the child from the worker's environment
rather than from a setting the console echoes back. See [VirusTotal over
stdio](../deployment.md#virustotal-over-stdio-optional) and [VirusTotal's own
MCP server](../configuration.md#virustotals-own-mcp-server).
