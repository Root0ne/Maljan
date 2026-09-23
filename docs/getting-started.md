# Getting started

This document takes a clean checkout to a first finished analysis on the
compose stack. It covers the two configuration files the stack needs, the
commands that bring it up, the first account, and where results appear. For the
meaning of every setting see [configuration.md](configuration.md); for
production concerns see [deployment.md](deployment.md).

## Prerequisites

- Python 3.13 and [uv](https://astral.sh/uv/)
- Docker with the Compose plugin
- Node.js 22 only if you intend to run the web app outside Docker
- Free host ports for Postgres, Redis, Qdrant, MinIO, Ghidra MCP, the API and
  the frontend; every published port binds to `BIND_ADDRESS` (`127.0.0.1` by
  default)

```bash
git clone https://github.com/Root0ne/Maljan.git
cd Maljan
make setup        # uv sync --all-extras --all-packages, pre-commit, external/
```

`external/` is not carried in git. `make setup` runs
`scripts/dev/fetch_external.sh`, which reconstructs it; `make external` does the
same on its own. The `ghidra-mcp` image is built from that tree, so the stack
cannot build without it.

## The two configuration files

Maljan reads two files, and neither is committed.

**`docker/.env`** — variables Compose substitutes into
[`docker/docker-compose.yml`](https://github.com/Root0ne/Maljan/blob/dev/docker/docker-compose.yml).
Every one of them
is declared with `:?`, so Compose refuses to start while any is missing.

```bash
cp docker/.env.example docker/.env
python -c "import secrets; [print(f'{k}={secrets.token_urlsafe(32)}') for k in ('GHIDRA_MCP_AUTH_TOKEN','REDIS_PASSWORD','QDRANT_API_KEY','POSTGRES_PASSWORD','MINIO_ROOT_PASSWORD')]"
python -c "from cryptography.fernet import Fernet; print('SETTINGS_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
```

Pick a `MINIO_ROOT_USER` of your own and paste the generated values in.

**`bootstrap.env`** (repository root) — the same contract as process
environment, for anything you run outside Compose: `make migrate`, the API or
the worker started by hand. Copy it from the example and fill in the secrets.

```bash
cp bootstrap.env.example bootstrap.env
```

[`bootstrap.env.example`](https://github.com/Root0ne/Maljan/blob/dev/bootstrap.env.example)
is the entire process
environment surface the API and the worker read. Every other application
setting — LLM provider, sandbox, static analyst, tool servers, agents, rate
limits, enrichment — lives in the settings store and is edited from the web
console. There is no automatic import of a previous `.env` deployment.

## Start the stack

```bash
make dev-up          # compose up -d with the development overlay
make dev-logs        # follow
```

`make dev-up` sources `bootstrap.env` when it exists and layers
`docker/docker-compose.dev.yml` over the production file, so the frontend runs
`next dev` and the worker restarts on a source edit. For the production shape
instead:

```bash
cd docker && POSTGRES_PORT=${POSTGRES_PORT:-5433} docker compose up -d --build
```

Either way the one-shot `migrate` service runs `alembic upgrade head` against a
healthy Postgres first, and the API and the worker wait for it to exit
successfully. If host port 5432 is taken, publish Postgres elsewhere with
`POSTGRES_PORT`; that changes only the host-side publish, since Compose always
points `DATABASE_URL` at `postgres:5432` inside the network.

Access points, on `BIND_ADDRESS`:

| Service | URL |
| :-- | :-- |
| Console | `http://localhost:3000` |
| API health | `http://localhost:8000/health` |
| Ghidra MCP | `http://localhost:8089/check_connection` |
| MinIO console | `http://localhost:9001` |

## First account

Register from the console's login page, or against the API:

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"...","full_name":"You"}'
```

A registered account gets the `analyst` role. Settings → Configuration, the
audit log and API-key management require `admin`, and there is no endpoint that
grants it, so promote the first account once, directly in the database:

```bash
docker compose -f docker/docker-compose.yml exec postgres \
  psql -U maljan -d maljan -c "UPDATE users SET role='ADMIN' WHERE email='you@example.com';"
```

Log out and back in afterwards.

## Configure the stack once

A fresh deployment starts on the catalog defaults, which are `localhost`-shaped
and therefore wrong inside the Docker network. Open **Settings → Setup** and
walk the guides you need; at minimum:

- **Connect a language model** — provider, endpoint and credentials. A local
  OpenAI-compatible server is reached from the containers at
  `http://host.docker.internal:8080/v1`.
- **Choose a static analyser** — for the bundled container, the Ghidra MCP URL
  is `http://ghidra-mcp:8089` with the `GHIDRA_MCP_AUTH_TOKEN` you generated.
- **Connect a sandbox** — CAPEv2, Triage, a generic REST sandbox, an uploaded
  report, or the mock provider, which is the default.
- **Long-term memory** — Qdrant at `http://qdrant:6333` with `QDRANT_API_KEY`.

Each guide ends in a review step and applies the staged values in one write.
Connection tests are available on the settings that have a probe. An instance
that is already configured can be reproduced with a JSON export instead; see
[configuration.md](configuration.md).

### A smaller model, when the machine has less memory

The default model is unchanged and is what every number in the paper rests on.
For a machine that cannot hold it, `gemma4:12b` behind Ollama is a documented
option, with one setting it requires:

```
core.llm.provider                   = ollama
core.llm.ollama.expert_model        = gemma4:12b
core.llm.ollama.judge_model         = gemma4:12b
core.llm.ollama.disable_thinking    = true
core.llm.ollama.num_ctx             = 32768
```

`disable_thinking` is not optional for it. At the shipped default the
connection test reports that the model *answered nothing* — the reasoning went
into the thinking channel and the answer came back empty — and with
`core.llm.require_probe` on, the API refuses every job until the setting is
turned on. With it on, the same test passes in a quarter of a second.

What was measured, on a 30 GB laptop with an 8 GB card, one sample at a time:
three samples, the same verdicts as the default model on the two that matter
(Benign for a signed utility, Malware for a PE loader) and one step milder on
the third; about **13.6 GB of memory still free at the worst moment**, against
**8.4 GB** for the default model on the same three; roughly a fifth faster over
the set; and **fewer techniques named** — two in total against seven, which is
the cost. Three samples are not a benchmark, and this does not change the
default.

## First analysis, with the default team

Upload a sample from the console and start an analysis, or drive the API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"..."}' | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -X POST http://localhost:8000/api/v1/samples/upload \
  -H "Authorization: Bearer $TOKEN" -F 'file=@sample.exe'

curl -X POST http://localhost:8000/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sample_id":"<id from the upload>"}'
```

Progress streams over the WebSocket at `/ws/analysis/{job_id}`, which is what
the console's analysis page subscribes to. The **CONVERSATION** tab draws the
run as the exchange it is — every agent's messages, its tool calls and the
verdict — while the analysis header draws the stages the team has, each one
filling in as it starts and finishes; the **EVIDENCE** tab is the ledger of
every tool call the run made. See [console.md](console.md). When the run
finishes, the report appears under the analysis detail page, and the same
content is available as Markdown, HTML, PDF, STIX 2.1 and a MITRE view under
`/api/v1/reports/{report_id}/...` — see [api.md](api.md).

Read the report from the evidence up rather than from the verdict down. Every
section of it carries the ledger ids it was built from, rendered as chips; a
chip opens that call on the EVIDENCE tab with its arguments, its result and how
long it took. The **Evidence** card on the summary tab counts what the whole
report is standing on — how many calls were made, how many failed, and how many
sections can name nothing at all.

## Then: measure the model without tools

`measurement` is the same three analysts as `default` with every tool server
withheld and the static provider forced to `none`. Running the same sample
under it answers a question the default team cannot: how much of the verdict
was the tools and how much was the model.

Switch teams under **Settings → Agents and pipeline → Teams**, or per job:

```bash
curl -X POST http://localhost:8000/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sample_id":"<id>","config":{"profile":"measurement"}}'
```

The run will produce a report with an all but empty evidence ledger, and that
is the point: compare its verdict, its techniques and its
`run_summary.corroboration` against the same sample's default run. A
measurement team is a profile rather than three tool-free clones of the
definitions, so the agents it measures cannot drift from the ones `default`
runs.

## Then: an APK, with the mobile team

`mobile` is a six-stage team for a mobile sample — `triage`, `android_static`
and `dynamic`, then the debate, the verdict and the report. Upload an APK and run
it under `profile: "mobile"`.

Two things are worth watching on the stage strip. The `android_static` stage
runs only when the sample really is an APK or a DEX (`when: file_type in
("apk", "dex")`), and the `dynamic` stage only when a sandbox report reached
the run. Submit a PE under the same team and the Android stage appears as a row
that declined, with the condition it failed written next to it — the team was
applied, and the console shows what it chose not to do.

The third seeded team, `deep_static`, adds a `reversing` stage that is handed
the static stage's findings and asked to confirm or refute each of them at
function level. It needs a static provider with a decompiler behind it —
Ghidra or r2 — to be worth running.

## Without Docker

The standalone CLI runs the pipeline without the API, the worker or any of the
backing services:

```bash
uv run maljan analyze sample_1 --mock --name test.exe
```

It builds the core `Settings` model directly, so it reads the process
environment (and a `.env` in the working directory) rather than the settings
store — the one remaining consumer that still works that way.
