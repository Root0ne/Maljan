# Maljan documentation

The operator and contributor documentation for Maljan. Each document below is
written against the code in this repository: the bootstrap contract in
`apps/api/app/bootstrap.py`, the settings catalog in `src/maljan/core/`, the
routers under `apps/api/app/api/v1/` and the compose stack in `docker/`.

## Index

| Document | What it covers |
| :-- | :-- |
| [getting-started.md](getting-started.md) | Prerequisites, the two configuration files, starting the stack, first login and first analysis. |
| [configuration.md](configuration.md) | The bootstrap environment contract, Settings → Configuration, the setup guides, connection probes, JSON export and import, secret storage. |
| [console.md](console.md) | The navigation tree, the analysis tabs, the Conversation view and how the console follows a run. |
| [architecture.md](architecture.md) | Components, the request and job lifecycle, teams as stages, agents and their tools, the evidence ledger, validation loops and report assembly. |
| [deployment.md](deployment.md) | Compose services and healthchecks, required secrets, health endpoints, Kubernetes and systemd notes, upgrades and migrations. |
| [operations.md](operations.md) | Logs, what a run's metrics mean, staged samples, the audit trail, rate limits, backups and a troubleshooting table. |
| [security.md](security.md) | Authentication, roles, API keys, secret encryption, what an export leaves out, CORS and cookie flags, vulnerability reporting. |
| [development.md](development.md) | Repository layout, `make` targets, the test suites, CI jobs and the branch workflow. |
| [api.md](api.md) | Router groups, the evidence endpoint, the run-summary fields, the stage events on the WebSocket, authentication and pagination. |
| [paper.md](paper.md) | Where the published evaluation, its harness and its fixtures live. |

Images used by these documents and by the top-level
[README.md](https://github.com/Root0ne/Maljan/blob/dev/README.md) live in
[assets/](assets).

## Historical design record

The specs, plans and superpowers notes that once lived under `docs/specs/`,
`docs/plans/` and `docs/superpowers/` are no longer carried in the working
tree; read them with `git log -- docs/plans docs/specs docs/superpowers`.
