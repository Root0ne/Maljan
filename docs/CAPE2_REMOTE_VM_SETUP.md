# CAPEv2 on a remote Ubuntu VM — split-deployment setup

This runbook covers the deployment where the **CAPEv2 sandbox runs inside a separate
Ubuntu VM** and the **rest of Maljan runs on the Windows host** (API, worker, web,
llama-server, Ghidra-MCP, Postgres/Redis/MinIO/Qdrant).

It is the reference for `SANDBOX__CAPE2_BASE_URL=http://<UBUNTU_VM_IP>:8000` in
`.env.example`.

```
  Windows host                                   Ubuntu VM (bridged IP, e.g. 192.168.1.50)
  ------------------------------------           ----------------------------------------
  Maljan API  :8000                              CAPEv2 web + apiv2  :8000  (bind 0.0.0.0)
  Maljan worker (ARQ) ──── HTTP/REST ─────────▶  KVM guest VM (detonation, isolated)
  llama-server :8080                             rooter / inetsim / internet egress
  Ghidra-MCP   :8089
  Postgres/Redis/MinIO/Qdrant
```

Only **one** address crosses the machine boundary: the worker calls the VM's CAPE
REST API. The VM never reaches back into Windows and never touches the Windows disk.

---

## 1. How Maljan talks to CAPE (what connects, what it pulls)

Maljan uses the **REST backend** (`CAPEv2Client`, `src/maljan/loaders/cape2_client.py`).
On each analysis the worker submits the sample, polls until the task is reported, and
fetches one `report.json`. That single report fans out to both behavioral agents:

| Endpoint (on the VM)                     | Purpose                                      |
| ---------------------------------------- | -------------------------------------------- |
| `POST /apiv2/tasks/create/file/`         | Upload the sample as multipart bytes -> task id |
| `GET  /apiv2/tasks/view/{id}/`           | Poll status until `reported`/`failed`/`aborted` |
| `GET  /apiv2/tasks/get/report/{id}/`     | Fetch the full JSON report                   |

| Agent          | Reads from `report.json`                                        | Produces |
| -------------- | -------------------------------------------------------------- | -------- |
| Dynamic analyst | `behavior.processes` (pid/ppid/cmdline/calls), `behavior.calls`, `behavior.apistats`, `signatures[]` | process tree, registry mods, notable APIs, sandbox signatures |
| Network analyst | `network.dns / http / tcp / udp / hosts / domains`             | domains (DGA-scored), IPs, URLs, user-agents, JA3/JA3S |

No parser or source changes are needed — the internal models
(`extractors/dynamic_extractor.py`, `extractors/network_extractor.py`) were built
around the CAPE `report.json` schema.

> Deep-PCAP inspection (the `network-mcp` tools) is **not** used in this remote setup —
> the PCAP files live on the VM, and the report's structured `network` block already
> gives the network analyst its IOCs. If you ever need raw PCAP analysis on Windows,
> fetch the file from the VM first; it is out of scope here.

### CAPE MCP (interactive tools, over HTTP) — enabled in this deployment

On top of the REST report, the dynamic analyst can call CAPE's MCP tools
(`search_task`, `get_task_iocs`, `get_task_config`, `get_latest_tasks`, ...) ad-hoc
during its ReAct loop. CAPE ships the MCP server (`external/CAPEv2/mcp/server.py`,
launched by `scripts/cape_mcp_wrapper.py`).

Because CAPE is on a **separate VM**, the MCP runs over **HTTP** (streamable-http), not
stdio. The toolkit (`MCPLangChainToolkit`) and `dynamic_analyst._initialize_mcp_client`
support `transport=http` — they connect to the wrapper running as an HTTP server on the
VM instead of launching a local subprocess. Setup is in §2.1 (VM) and §3.1 (Windows).

> The MCP path is **additive**: even with it disabled, the REST report already feeds both
> agents. Enable it for richer, on-demand CAPE queries; disable it (`MCP__CAPE__ENABLED=
> false`) to keep the pipeline purely report-driven.

---

## 2. Ubuntu VM — CAPEv2 setup

1. **Install CAPEv2** on the Ubuntu VM following upstream
   (https://github.com/kevoreilly/CAPEv2). Production needs KVM and at least one guest
   VM (typically a Windows 10 guest) for detonation. Pin the same upstream commit the
   Windows reference clone tracks if you want parity (see §5), or take a current commit.

2. **Bind the API to a reachable interface, not loopback.** CAPE's `web`/`apiv2` must
   listen on `0.0.0.0:8000` so the Windows host can reach it:
   - In the gunicorn/uwsgi unit (or `python manage.py runserver`) use `0.0.0.0:8000`.
   - Confirm the port in `conf/cuckoo.conf` and `conf/api.conf`.

3. **Enable token auth** (recommended even on a lab LAN). In `conf/api.conf`:
   ```
   [api]
   token_auth_enabled = yes
   ```
   Mint a DRF token (`poetry run python manage.py drf_create_token <user>` per CAPE
   docs) and record it — it becomes `SANDBOX__CAPE2_API_TOKEN` on Windows. An empty
   token is acceptable **only** for a fully isolated lab with `token_auth_enabled = no`.

4. **Networking.** Prefer **bridged** networking so the VM gets a LAN-routable IP; then
   `SANDBOX__CAPE2_BASE_URL=http://<VM_IP>:8000`. If you must use NAT/host-only, add a
   host port-forward to guest `:8000` and use the forwarded address. Open the VM's
   firewall for inbound `8000` **from the Windows host only**:
   ```
   sudo ufw allow from <WINDOWS_HOST_IP> to any port 8000 proto tcp
   ```

5. **Detonation network.** The guest VM needs realistic egress (internet, or
   `rooter`/inetsim) for C2 traffic to appear in the report. Configure per CAPE's
   routing docs. The malware runs **inside the guest**, isolated from Windows.

6. **Sanity-check on the VM** before leaving it:
   ```
   curl -s http://localhost:8000/apiv2/tasks/list/ -H 'Authorization: Token <token>' | head
   ```

### 2.1 CAPE MCP server on the VM (for the interactive MCP tools)

To let the dynamic analyst call CAPE tools ad-hoc, run the MCP wrapper **on the VM** as
an HTTP server (it needs CAPE's Python env + DB access, so it must live next to CAPE).
Copy `scripts/cape_mcp_wrapper.py` to the VM (or mount the repo) and run:

```bash
CAPE_ROOT=/opt/CAPEv2 CAPE_MCP_HOST=0.0.0.0 CAPE_MCP_PORT=9004 \
  python scripts/cape_mcp_wrapper.py \
    --transport streamable-http --cape-root /opt/CAPEv2
```

This serves the MCP endpoint at `http://<VM_IP>:9004/mcp/`. Open the VM firewall for
inbound `9004` from the Windows host, the same way as `8000`. Run it under systemd/tmux
so it survives reboots. (Skip this whole step if you only want the REST report path.)

---

## 3. Windows host — Maljan configuration

### 3.1 `.env` (operator file, gitignored)

```
SANDBOX__BACKEND=cape2
SANDBOX__CAPE2_BASE_URL=http://<UBUNTU_VM_IP>:8000
SANDBOX__CAPE2_API_TOKEN=<token from conf/api.conf>
SANDBOX__CAPE2_TIMEOUT_SECONDS=1200      # detonation+processing >> the 300s default
SANDBOX__CAPE2_POLL_INTERVAL_SECONDS=15

# CAPE MCP over HTTP (interactive tools; requires the VM MCP server from 2.1)
MCP__CAPE__ENABLED=true
MCP__CAPE__TRANSPORT=http
MCP__CAPE__URL=http://<UBUNTU_VM_IP>:9004/mcp/
MCP__CAPE__AUTH_TOKEN=                    # only if the MCP server enforces one
```

Everything else stays on Windows at `localhost` / Docker container names — only the two
`<UBUNTU_VM_IP>` URLs cross the boundary. Postgres/Redis/MinIO/Qdrant, Ghidra-MCP
(`:8089`), and llama-server (`:8080`) are unchanged. To run report-only (no interactive
MCP), set `MCP__CAPE__ENABLED=false` — the REST path still feeds both agents.

### 3.2 Windows Defender exclusions (admin PowerShell)

The worker writes the real sample to disk before uploading it to CAPE, so Defender must
not quarantine those paths:

```powershell
Add-MpPreference -ExclusionPath "D:\Projects\Maljan\data\samples"
Add-MpPreference -ExclusionPath "D:\Projects\Maljan\data\uploads"
```

(Also keep the model/ghidra project dirs excluded as before.)

### 3.3 Re-establish `external/` tooling on the new machine

`external/` is **gitignored** — it does NOT travel with the repo. On the new Windows
machine you must re-create it:

- **Ghidra-MCP** (static analysis, `:8089`): clone
  `https://github.com/bethington/ghidra-mcp`, check out the pinned tag (see §5), then
  re-apply Maljan's two customizations from `docs/migration/ghidra-mcp-patches/`:
  ```
  git -C external/ghidra-mcp checkout v5.6.0
  git -C external/ghidra-mcp apply ../../docs/migration/ghidra-mcp-patches/01-remove-destructive-folder-endpoints.patch
  git -C external/ghidra-mcp apply ../../docs/migration/ghidra-mcp-patches/02-pin-ghidra-12.0.3-dockerfile.patch
  docker compose -f docker/docker-compose.yml build ghidra-mcp
  ```
  Validate: `curl http://localhost:8089/mcp/schema` returns the tool catalog.

- **CAPEv2 (Windows clone):** reference only. The runtime CAPE and the MCP server both
  live on the VM (the MCP wrapper needs CAPE's Python env + DB, so it runs there, not on
  Windows — see §2.1). Nothing on Windows imports this clone; clone it for reference or
  skip it.

---

## 4. Validation (end-to-end)

1. **Connectivity smoke test** from Windows once the VM is up:
   ```powershell
   curl http://<UBUNTU_VM_IP>:8000/apiv2/tasks/list/ -H "Authorization: Token <token>"
   ```
   Expect JSON, not a connection refusal/timeout. This confirms binding + firewall +
   token in one shot.

2. **One live run** through the pipeline:
   - Set the `.env` above and restart the worker.
   - Submit a benign test sample via the web UI.
   - Confirm in the logs: a CAPE `task_id` is assigned, polling reaches `reported`, and
     the report fetch succeeds.
   - Confirm in the report UI: the **dynamic** tab shows processes / API stats /
     signatures, and the **network** tab shows DNS / HTTP / host IOCs — i.e. both agents
     received real CAPE data.

3. If the report fetch is slow on large samples, that is the HTTP read, not detonation.
   `CAPEv2Client`'s per-request HTTP timeout defaults to 30s; very large `report.json`
   payloads (tens of MB) may need that raised — flag it if you hit it.

---

## 5. External-repo version status (as of this migration)

Checked against upstream on 2026-06-24:

| Clone                | Pinned at            | Upstream latest        | Gap          | Action |
| -------------------- | -------------------- | ---------------------- | ------------ | ------ |
| `external/ghidra-mcp` | `0c0299d` (v5.6.0)   | `v5.14.1` (2026-06-18) | 189 commits  | **Kept pinned.** See below. |
| `external/CAPEv2`     | `976b3690` (Apr 21)  | `master` (2026-06-24)  | 277 commits  | **Kept pinned** (Windows clone is reference-only; the VM runs its own CAPE). |

**Why ghidra-mcp stayed pinned for the migration.** The two local customizations
(remove destructive `/create_folder` + `/delete_file` endpoints; pin a reproducible
Ghidra 12.0.3 Dockerfile) both sit on files upstream heavily rewrote (the Dockerfile for
the Ghidra 12.1.2 build; the headless server in nearly every release). Advancing is a
manual conflict reconciliation + a full Ghidra Docker rebuild + `:8089` re-validation —
a deliberate task, not a safe fast-forward. The customizations are preserved as portable
patches under `docs/migration/ghidra-mcp-patches/` so they survive the move at any
version.

**Optional upgrade to v5.14.1 (do it on the new machine, after the migration works):**
```
git -C external/ghidra-mcp stash            # park any local edits
git -C external/ghidra-mcp checkout v5.14.1
# re-apply the two Maljan patches; resolve conflicts against the new Dockerfile/Java
git -C external/ghidra-mcp apply --3way ../../docs/migration/ghidra-mcp-patches/01-*.patch
git -C external/ghidra-mcp apply --3way ../../docs/migration/ghidra-mcp-patches/02-*.patch
docker compose -f docker/docker-compose.yml build ghidra-mcp
curl http://localhost:8089/mcp/schema       # re-validate
```
v5.14.1 brings Ghidra 12.1.2, overlay address-space support, a `search_tools` meta-tool,
new xref tools, and stability fixes — worthwhile, but gate it behind a green `/mcp/schema`
and a static-analyst smoke run.
