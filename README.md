<p align="center">
  <img src="docs/assets/logo.svg" alt="Maljan" width="112">
</p>

<h1 align="center">Maljan</h1>
<p align="center"><em>Multi-Agent Malware Analysis Framework</em></p>

[![CI](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml/badge.svg)](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Root0ne/Maljan/actions/workflows/codeql.yml/badge.svg)](https://github.com/Root0ne/Maljan/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Root0ne/Maljan/badge)](https://scorecard.dev/viewer/?uri=github.com/Root0ne/Maljan)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Maljan connects LLM agent teams to malware-analysis tools. A team is an ordered
list of **stages** — triage, then the passes the sample is worth, then a debate,
a verdict and a report — and each stage runs the agents it names over the tools
they are given: signature scanners, rule engines, binary and capture readers, a
sandbox, an ATT&CK catalogue. A stage carries a condition, so a team applies to
a sample rather than being written for one; a stage that declines says why. The
facts about a sample — what it is, its hashes and signature, what the rule
engines and the reputation services say — are established by code before any
agent starts and are cited by id; the decisions are the team's. The output is a
report against MITRE ATT&CK and a STIX 2.1 bundle.

The organising rule is that **the agent decides and the code says what is wrong
with the decision.** Nothing rewrites a claim, a technique id, a confidence or
an attribution behind the producer's back: a problem is put back to the producer
as feedback, it gets one turn to fix it, and what it will not fix stays on the
record where a reader can see it. Every tool call is written to an evidence
ledger with a citable id, and every section of the report names the ids it was
built from — so a claim in a report resolves back to the call it came out of.

Nothing is bound to Windows. Routing is by the sample's own format, and a
format nothing recognises gets the neutral path and a report that says so
rather than a rejection.

## The teams that ship

| Team | Stages | For |
| :-- | :-- | :-- |
| `default` | `triage_pack` → `analysis` (static, dynamic, network) → `debate` → `verdict` → `report` | The general case, and the architecture this project measured itself on. |
| `measurement` | The same four model stages, without the pack and with every tool server withheld | What the ensemble contributes on its own, with nothing to call. |
| `mobile` | `triage_pack` → `triage` → `android_static` → `dynamic` → `debate` → `verdict` → `report` | An APK or a DEX. The Android stage declines on anything else and says so. |
| `deep_static` | `triage_pack` → `triage` → `static` → `reversing` → `network` → `debate` → `verdict` → `report` | Reading the code: the reversing stage takes each static finding into the decompiler. |
| `team_lead` | `triage_pack` → `lead` → `verdict` → `report` | One lead agent plans, asks the specialists through `ask_<agent>` tools, and reports what they established. |

`triage_pack` is the deterministic pre-analysis pack, which runs no model; the
`triage` stage after it is the triage *agent*.

Teams are configuration, not code. A team of your own is an ordered list of
stages and a prompt per agent, written in the console; see
[docs/configuration.md](docs/configuration.md).

Samples are submitted, tracked and read in a web console; the whole
configuration of a deployment lives in that console as well, not in environment
files.

## The console

| | |
|---|---|
| <img src="docs/assets/dashboard.png" alt="Dashboard"> | <img src="docs/assets/analysis-summary.png" alt="Analysis summary"> |
| **Dashboard.** Totals, failure rate, recent analyses and verdict distribution. | **Analysis.** One run, its stages, its evidence ledger and the report built from it, with Markdown, PDF, HTML, STIX 2.1 and MISP export. |
| <img src="docs/assets/settings-configuration.png" alt="Settings configuration"> | <img src="docs/assets/settings-guide.png" alt="Setup guide"> |
| **Configuration.** Every application setting, grouped, searchable, with its origin and when a change takes effect. | **Setup guides.** Short walkthroughs that configure one subsystem at a time and test the connection before saving. |

## Quick start

The compose stack is the supported way to run Maljan. It needs Docker with the
Compose plugin, and `make setup` once to fetch the third-party trees the
`ghidra-mcp` image is built from.

```bash
git clone https://github.com/Root0ne/Maljan.git && cd Maljan
make setup                          # dependencies, pre-commit, external/
cp docker/.env.example docker/.env  # then fill in every secret it declares
make dev-up                         # docker compose up -d, development overlay
```

The development overlay is for a workstation; [docs/deployment.md](docs/deployment.md)
covers a production deployment.

Every secret in [`docker/.env.example`](docker/.env.example) is declared with
`:?` in the compose file, so the stack refuses to start while one is missing;
[docs/getting-started.md](docs/getting-started.md) has the commands that
generate them. Open <http://localhost:3000>, register the first account from
the login page, promote it to `admin` once in the database, then walk
**Settings → Setup** to point the deployment at a language model, a sandbox and
the rest. A fresh deployment starts on catalog defaults that are
`localhost`-shaped, so that pass is not optional.

The API serves its OpenAPI schema and `/docs` only when `DEBUG` is true; a
production deployment has no interactive schema.

## Documentation

Everything below lives in [docs/](docs/README.md) and is written against the
code in this repository. The same set is published as a browsable site at
<https://root0ne.github.io/Maljan/>.

| Document | What it covers |
| :-- | :-- |
| [getting-started.md](docs/getting-started.md) | Prerequisites, the two configuration files, starting the stack, first login and first analysis. |
| [configuration.md](docs/configuration.md) | The bootstrap environment contract, Settings → Configuration, the setup guides, connection probes, JSON export and import, secret storage. |
| [architecture.md](docs/architecture.md) | Components, the request and job lifecycle, teams as stages, agents and their tools, the evidence ledger, validation loops and report assembly. |
| [deployment.md](docs/deployment.md) | Compose services and healthchecks, required secrets, health endpoints, Kubernetes and systemd notes, upgrades and migrations. |
| [operations.md](docs/operations.md) | Logs, what a run's metrics mean, staged samples, the audit trail, rate limits, backups and a troubleshooting table. |
| [security.md](docs/security.md) | Authentication, roles, API keys, secret encryption, what an export leaves out, CORS and cookie flags, vulnerability reporting. |
| [development.md](docs/development.md) | Repository layout, `make` targets, the test suites, CI jobs and the branch workflow. |
| [api.md](docs/api.md) | Router groups, the evidence endpoint, the run-summary fields, the stage events on the WebSocket, authentication and pagination. |

Release notes are in [CHANGELOG.md](CHANGELOG.md).

## Licence

MIT — see [LICENSE](LICENSE). The third-party rule sets Maljan can use carry
their own licences and are not redistributed here; `make external` fetches
them, licence files included.
