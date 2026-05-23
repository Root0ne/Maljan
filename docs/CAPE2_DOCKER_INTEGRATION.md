# CAPEv2 integration (Docker dev stack)

This document covers Maljan's sandbox integration on top of **CAPEv2** in two parts (the legacy Triage / tria.ge backend has been removed entirely):

1. **Dev side (the Docker stack in this repo):** CAPEv2 web + REST API in a container, alongside Postgres, with no real VM. Lets you exercise Maljan's `CAPEv2Client` integration end-to-end.
2. **Prod side (follow-up):** Real sample analysis needs a Linux host + KVM + Windows guest VM — the upstream CAPE deployment path.

---

## 1. Why two parts?

CAPEv2's architecture is monolithic: web / REST API + scheduler + result server + reporting modules run **on the same host** and analysis requires a **real hypervisor + Windows guest VM**. Upstream ships no Dockerfile and a Docker-only "full CAPEv2" is not feasible.

The approach in this repo:

| Component | In Docker? | Note |
|---|---|---|
| Django web + REST API (`/apiv2/*`) | Yes | The surface Maljan talks to |
| Postgres (task DB) | Yes | Sibling container inside compose |
| Scheduler / Result Server | No | They do nothing useful without a real VM |
| MongoDB / Elasticsearch | No | Reporting is optional and stays off |
| KVM + Windows guest | No | Has to be installed separately on the host |

**Bottom line:** Sample submission succeeds, a task row is written to the DB, but its status stays `pending` (no worker to process it). Maljan's `submit → poll → fetch_report` path works; only `wait_for_completion` ends in timeout because there is no real VM. For full analysis see the "Prod" section below.

---

## 2. Run the dev stack

### 2.1. Build + start

```powershell
docker compose -f docker/cape-compose.yml up -d --build
```

First build takes ~10-15 minutes (Ubuntu base + Python deps). Subsequent builds are cached and finish in seconds.

### 2.2. Verify

```powershell
# Is Postgres ready?
docker exec maljan-cape-postgres pg_isready -U cape -d cape

# Does the REST API respond?
curl http://localhost:18000/apiv2/

# Token-protected endpoint:
curl -H "Authorization: Token maljan_cape_dev_token" `
     http://localhost:18000/apiv2/tasks/list/
```

### 2.3. Point Maljan at CAPE

Root `.env`:

```
SANDBOX__BACKEND=cape2
SANDBOX__CAPE2_BASE_URL=http://localhost:18000
SANDBOX__CAPE2_API_TOKEN=maljan_cape_dev_token
SANDBOX__CAPE2_TIMEOUT_SECONDS=300
SANDBOX__CAPE2_POLL_INTERVAL_SECONDS=10
```

Restart the Maljan worker + API:

```powershell
# In order:
#   - apps/api uvicorn process
#   - apps/api arq worker process
```

`tests/unit/test_sandbox_client.py` already covers `CAPEv2Client` with mock httpx — no changes needed.

### 2.4. Stack commands

```powershell
# Tail logs
docker compose -f docker/cape-compose.yml logs -f cape-web

# Open a shell
docker exec -it maljan-cape-web bash

# Stop
docker compose -f docker/cape-compose.yml down

# Reset DB
docker compose -f docker/cape-compose.yml down -v
```

---

## 3. Architecture details

### 3.1. Maljan side

No code changes required. Relevant entry points:

- [src/maljan/loaders/cape2_client.py](../src/maljan/loaders/cape2_client.py) — REST client
- [src/maljan/core/config.py:192-226](../src/maljan/core/config.py#L192-L226) — `SandboxConfig.backend` accepts `cape2`
- [src/maljan/core/container.py](../src/maljan/core/container.py) — factory branch for `backend == "cape2"`

### 3.2. CAPE container layout

| File | Role |
|---|---|
| [docker/cape/Dockerfile.cape-web](../docker/cape/Dockerfile.cape-web) | Ubuntu 22.04 + Python 3.10 + minimum CAPE deps |
| [docker/cape/entrypoint.sh](../docker/cape/entrypoint.sh) | conf/* patch + alembic migrate + Django runserver |
| [docker/cape-compose.yml](../docker/cape-compose.yml) | cape-postgres + cape-web services |

### 3.3. Entrypoint config patches

On startup, `entrypoint.sh` does the following:

1. `conf/cuckoo.conf` → `database.connection` = Postgres DSN
2. `conf/reporting.conf` → `[mongodb]`, `[elasticsearchdb]` `enabled = no`
3. `conf/web.conf` → `recaptcha = no`
4. `conf/api.conf` + `conf/apiv2.conf` → flip all `enabled = no` → `yes`
5. `conf/api.conf` → `token` = the `CAPE_API_TOKEN` env value
6. `alembic upgrade head` (SQLAlchemy schema bring-up)
7. `python3 web/manage.py runserver 0.0.0.0:8000`

### 3.4. REST endpoints

Maljan's `CAPEv2Client` hits the following routes (verified against upstream `external/CAPEv2/web/apiv2/urls.py`):

| Method | Path | Role |
|---|---|---|
| POST | `/apiv2/tasks/create/file/` | Sample submission |
| GET | `/apiv2/tasks/view/{id}/` | Task status |
| GET | `/apiv2/tasks/get/report/{id}/` | Full JSON report |

> **Bug-fix note:** `cape2_client.py` previously called `/apiv2/tasks/report/{id}/` (wrong path). Fixed in scope of this audit.

---

## 4. Production / real-analysis follow-up

Docker alone is not enough for real sample analysis. The upstream-supported path is:

### 4.1. Host requirements

- **Linux** (Ubuntu 22.04 / 24.04 recommended)
- **KVM** or **QEMU** + libvirt
- **CPU:** virtualization support (Intel VT-x / AMD-V)
- **RAM:** 16 GB minimum (Windows VM 4 GB + host)
- **Disk:** 200 GB+ (Windows VM images + analysis output)

### 4.2. Install path

```bash
# external/CAPEv2/installer/cape2.sh automates everything:
sudo bash external/CAPEv2/installer/cape2.sh base cape
```

The script (1500+ lines) installs:
- KVM/libvirt
- Python deps + native deps (yara, ssdeep, suricata, capa)
- PostgreSQL + MongoDB
- Systemd units (cape, cape-rooter, cape-processor, cape-web)
- Nginx + uWSGI reverse proxy

### 4.3. Windows guest VM

CAPE ships examples under `data/guest_images_examples/`. Typical flow:

1. Build a Windows 10 VM under KVM (4 GB RAM, 60 GB disk)
2. Grant the Linux `cape` user libvirt access
3. Run `extra/win10_disabler.ps1` inside the VM (telemetry off, defender disabled)
4. Install the **CAPE agent** inside the VM (`external/CAPEv2/agent/agent.py`)
5. Register the VM in `conf/kvm.conf` (label, ip, snapshot name)
6. Start the CAPE services:
   ```bash
   sudo systemctl start cape cape-rooter cape-processor cape-web
   ```

### 4.4. Dev → Prod cutover

**No Maljan code changes** required. Only `.env`:

```diff
- SANDBOX__CAPE2_BASE_URL=http://localhost:18000
+ SANDBOX__CAPE2_BASE_URL=http://cape-prod-host.internal:8000
- SANDBOX__CAPE2_API_TOKEN=maljan_cape_dev_token
+ SANDBOX__CAPE2_API_TOKEN=<prod token from cape conf/api.conf>
```

---

## 5. Known limitations (dev stack)

| Limitation | Detail | Workaround |
|---|---|---|
| Samples are not executed | No scheduler/worker | Move to the prod setup |
| `wait_for_completion` times out | Status never reaches "reported" | Use `SANDBOX__CAPE2_TIMEOUT_SECONDS=10` to fail fast |
| No-Mongo reporting | Some UI sections are empty | The web UI still shows the successful submission |
| pyre2 fails to build | Some signature modules will not load | The web / REST path is unaffected |
| Windows host | KVM is Linux-only | For Hyper-V see `conf/hyperv.conf.default` |

---

## 6. Mock backend

For local development and CI where the sandbox is not needed at all, use the `mock` backend that reads fixture files:

```
SANDBOX__BACKEND=mock
```

`MockSandboxClient` loads pre-baked report JSON from `data/samples/dynamic/{sha256|name}.json` — no real CAPE instance required. Switch to the `cape2` backend for production use.
