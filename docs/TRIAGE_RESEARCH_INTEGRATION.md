# Triage / Recorded Future Sandbox — Research Integration

Maljan ships a third sandbox backend, `triage`, that submits samples to
[tria.ge](https://tria.ge) (rebranded as "Recorded Future Sandbox"). It is
**intended for academic / research-paper use**, not for production analysis
of customer or sensitive samples.

## Why include it

For a research paper Maljan needs:

1. **Reproducibility.** Reviewers must be able to verify that a reported
   verdict was supported by the sandbox observations cited. Every Triage
   submission yields a public URL `https://tria.ge/<sample_id>` that anyone
   can open. The TriageClient writes this URL into the normalized report
   under `report["sandbox_url"]`.
2. **External ground-truth for family attribution.** Triage's
   `extracted[].config` block carries extracted malware-family metadata
   (`family`, `c2`, `botnet`, `mutex`, `keys`, `credentials`). The pipeline
   promotes it verbatim into the normalized report under `extracted`. This
   serves as an external check against Maljan's own family-attribution
   layer.
3. **Multi-platform coverage CAPE lacks.** Triage exposes mature behavioral
   profiles for APK / DEX, macOS (DMG, mach-O, PKG), and multi-arch Linux
   (ARM, ARM64, MIPS, PPC, x86_64). CAPE alone covers mainly Windows.
4. **Decrypted TLS captures.** `GET /samples/{sample_id}/{task_id}/dump.pcapng`
   contains traffic with HTTPS already decrypted — useful for the network
   analyst when a sample uses TLS-wrapped C2.

## Why **not** for customer / private samples

The public-cloud tier has two hard constraints:

* **All submissions are world-visible.** Anyone can browse, download, and
  reanalyse the binary at `https://tria.ge/<sample_id>`.
* **Submissions cannot be deleted via the API.** Public-cloud users have to
  contact Recorded Future support for takedown.

The container logs a `WARNING` every time the `triage` backend is selected.
For private samples use the `cape2` backend instead.

## Acceptable use (per Triage AUP)

Permitted: malware research, malware analysis, IOC enrichment, academic study.
Prohibited: bypassing content filters, gaming, cryptomining, copyright
infringement, offensive hacking. Researcher-tier API access is conditioned
on these terms. See `https://tria.ge/policy` and `https://www.recordedfuture.com/terms-of-use`.

## Setup

1. Sign up at `https://tria.ge/signup` (pick **Researcher** account — API
   access is not on the free Individual tier).
2. Copy your token from `https://tria.ge/account` -> API access.
3. Configure `.env`:

   ```env
   SANDBOX__BACKEND=triage
   SANDBOX__TRIAGE_API_TOKEN=tria_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   SANDBOX__TRIAGE_BASE_URL=https://api.tria.ge
   SANDBOX__TRIAGE_TIMEOUT_SECONDS=1800
   SANDBOX__TRIAGE_POLL_INTERVAL_SECONDS=15

   # Behavioral analysis settings
   SANDBOX__TRIAGE_BEHAVIORAL_TIMEOUT=120   # seconds per task (Triage cap 3600)
   SANDBOX__TRIAGE_NETWORK_MODE=internet    # internet | drop | tor

   # Optional: pin a specific OS image (otherwise auto-pick by extension)
   # SANDBOX__TRIAGE_FORCE_OS_TAG=os:android-13-x64

   # Optional: pull the decrypted PCAPNG per behavioral task.
   # SANDBOX__TRIAGE_FETCH_PCAPNG=true
   # SANDBOX__TRIAGE_PCAP_DIR=data/triage_pcaps
   ```

4. Install httpx (already a Maljan dependency, no extra install needed).
5. Submit a sample as usual:

   ```bash
   uv run maljan analyze <sha256> -s samples/zararli.apk --name triage-test -i 3
   ```

The `report["sandbox_url"]` field in the persisted analysis report holds
the citeable URL; quote it in the paper alongside the Maljan verdict.

## Submission flow (deterministic behavioral execution)

The client always embeds an explicit OS-tag profile in the submit
payload. This guarantees behavioral execution even on accounts that have
zero saved profiles configured via the web UI (the default state of a
fresh Researcher account, where Triage's "auto" mode silently falls back
to static-only).

```
submit (interactive=false, profiles=[{"profile": {"tags": ["os:<os>-<ver>-<arch>"]}}])
  -> pending
  -> scheduled
  -> running            [behavioral profile executing]
  -> processing
  -> reported
```

Profile selection logic (`_pick_profile_tag`):

| Extension                  | OS tag                  |
|----------------------------|-------------------------|
| `.apk`, `.dex`             | `os:android-13-x64`     |
| `.elf`, `.so`, `.sh`, `.deb`, `.bin` | `os:ubuntu-22.04-amd64` |
| `.dmg`, `.pkg`, `.app`, `.scpt` | `os:macos-10.15-amd64` |
| everything else            | `os:windows10-2004-x64` |

Override per-deployment with `SANDBOX__TRIAGE_FORCE_OS_TAG` (use any tag
from `GET /v0/resources`, e.g. `os:windows11-21h2-x64`). Use the legacy
interactive flow (`SANDBOX__TRIAGE_INTERACTIVE=true` +
`SANDBOX__TRIAGE_AUTO_PROFILE=true`) only when the account has profiles
saved via the web UI; otherwise prefer embedded profiles.

## CTI surface in the normalized report

Every fetch produces a flat `report["cti"]` block consolidating the
research-relevant fields from `summary` + `overview.json` +
per-task `report_triage.json`:

```python
report["cti"] = {
    "family":    [...],                  # detected malware families
    "ttp":       ["T1055", "T1059.001"], # MITRE ATT&CK technique IDs (deduped)
    "tags":      [...],
    "score":     8,                      # Triage 1-10
    "c2": {
        "urls":    [...],                # http://... / tcp://...
        "domains": [...],                # raw domains
        "ips":     [...],                # raw IPs
    },
    "mutexes":      [...],
    "keys":         [{"kind": "AES", "key": "...", "value": ...}],
    "credentials":  [{"protocol": "ftp", "host": "...", "username": "..."}],
    "dropped_files":[{"name": "...", "sha256": "...", "md5": "...", "path": "..."}],
    "dropper_urls": [{"type": "...", "url": "..."}],
    "ransom_notes": [{"family": "...", "emails": [...], "wallets": [...], ...}],
    "network": {
        "dns_queries": [...],
        "http_urls":   [...],
        "domains":     [...],
        "ips":         [...],
        "tls_ja3":     [...],            # JA3 fingerprints from TLS flows
        "tls_sni":     [...],            # SNI values observed
    },
    "indicators":  [{"ioc": "...", "description": "..."}],
    "yara_rules":  [...],                # rule names that fired
}
```

In addition the report carries:

* `report["sandbox_url"]` — citeable `https://tria.ge/<id>` URL.
* `report["sandbox_share_url"]` — token-embedded variant from `/magic`
  (paper reviewer can open without an API key).
* `report["sandbox_errors"]` — surfaced `errors[]` from summary +
  overview (`{task, backend, reason}`) so an empty behavioral section
  is explained instead of silent.
* `report["pcapng_paths"]` — local PCAPNG paths (only when
  `SANDBOX__TRIAGE_FETCH_PCAPNG=true`).
* `report["dump_paths"]` — local dropped-binary paths (only when
  `SANDBOX__TRIAGE_FETCH_DUMPS=true`). The bytes themselves, not just
  hashes.
* `report["onemon_paths"]` — local raw kernel-monitor JSON paths (only
  when `SANDBOX__TRIAGE_FETCH_ONEMON=true`).
* `report["behavior_rich"]` — raw per-task `report_triage.json` payloads
  for any analyst that wants the unmapped Triage shape.
* `report["signatures_rich"]` — raw signature objects with indicators
  and YARA rules attached.
* `report["extracted"]` — overview-level + per-task `extracted[].config`
  blocks promoted verbatim.
* `report["triage_score"]` — overall 1-10 from `analysis.score`.

The CTI synthesizer dedupes lists while preserving first-seen order so a
paper-time export is stable across reruns of the same sample.

## Beyond file submission

The TriageClient exposes three additional submission entry points
(callable directly on the client instance — not part of the generic
`SandboxClient` Protocol):

```python
client.submit_url("http://phishing.example.com/login", kind="url")
# Triage opens the URL in a browser sandbox.

client.submit_url("https://hosted.example.com/sample.exe", kind="fetch")
# Triage downloads the URL and analyses the resulting binary.

client.submit_url("https://tria.ge/250303-abcdefg", kind="import")
# Replay an existing public Triage analysis on the current environment.
# NOTE: kind=import is a paid-tier feature. On the public Researcher
# account it returns HTTP 400 ("The importing samples from the public
# cloud feature is not enabled."). Use kind=fetch for any public URL
# Triage can download itself, or upload via submit() instead.
```

All three honor the same `force_os_tag` / `behavioral_timeout` /
`network_mode` knobs configured on the client.

## CTI consumption inside the verdict path

Once the TriageClient populates ``report["cti"]``, the LangGraph pipeline
forwards it to the chief judge:

1. ``pipeline/nodes.py::make_judge_node`` extracts
   ``state["sandbox_report"]["cti"]`` and passes it as ``cti_block`` to
   ``JudgeAgent.give_verdict()``.
2. ``JudgeAgent`` renders a compact ``SANDBOX_CTI`` block via
   ``_build_cti_block`` (truncated to ~1 KB worst-case) and appends it
   to the verdict prompt right after the long-term-memory block. The
   verdict system prompt instructs the LLM to treat families it lists
   as ground-truth — they MUST appear in the Bundle's Malware SDO; C2
   entries become Indicator + Infrastructure SDOs; extracted
   credentials / mutexes / keys become Indicator objects.
3. ``pipeline/nodes.py::make_report_node`` reads the same CTI off state
   (``state["sandbox_cti"]``) and attaches the full original dict to the
   persisted extended STIX bundle under
   ``stix_bundle_extended["x_maljan_cti"]``. The MalwareReport schema
   does not need a dedicated column — the permissive STIX dump field
   carries the CTI verbatim for paper exports and API consumers.

Other sandbox backends (mock / CAPEv2) produce no CTI block, so
``cti_block`` is ``None`` for them and the prompt section is silently
skipped — no behavior change for non-Triage runs.

## Corpus search

`client.search_corpus(query, limit=20)` wraps `GET /v0/search`. Use it
for family attribution checks ("did the corpus see other samples in this
family?"):

```python
similar = await client.search_corpus("family:emotet", limit=50)
```

Triage's search syntax accepts `family:`, `tag:`, `md5:`, `sha256:`,
`signature:`, etc. — anything the web UI's filter row supports.

## Coverage summary (current build)

| Triage feature | Status |
|----------------|--------|
| `POST /samples` (file/url/fetch/import) | yes |
| `defaults.{timeout, network, geolocation}` | yes |
| `password` / `user_tags` / `target` | yes |
| Embedded + saved profiles | embedded by default; saved via interactive flow |
| `GET /samples/{id}` status polling | yes |
| `GET /samples/{id}/summary` | yes |
| `GET /samples/{id}/overview.json` (incl. errors) | yes |
| `GET /samples/{id}/{task}/report_triage.json` | yes |
| `GET /samples/{id}/{task}/dump.pcapng` | opt-in |
| `GET /samples/{id}/{task}/files/{name}` (drops) | opt-in |
| `GET /samples/{id}/{task}/logs/onemon.json` | opt-in |
| `GET /samples/{id}/magic` (shareable URL) | yes |
| `GET /v0/search` (corpus query) | helper exposed |
| `POST /samples/{id}/profile` (legacy interactive flow) | yes |
| `GET /samples/{id}/events` (JSONL stream) | no (we poll) |
| `GET /samples/{id}/sample` (download original) | no (have it locally) |
| `DELETE /samples/{id}` | no (public cloud rejects) |
| `/profiles`, `/yara`, `/users`, `/org-settings` CRUD | no (admin) |
| URL-scan endpoints | no (we don't submit URLs end-to-end yet) |

## Score mapping

Triage uses a 1-10 maliciousness scale; Maljan uses 0.0-1.0 confidence. The
mapping applied by the normalizer is approximate and only used as a soft
prior — the final Maljan verdict still comes from the analyst negotiation
loop:

| Triage score | Triage label | Maljan rough equivalent |
|------------- |--------------|-------------------------|
| 10           | Known bad (family match) | confidence ≥ 0.95 |
| 8-9          | Likely malicious | 0.75-0.90 |
| 5-7          | Suspicious | 0.40-0.65 |
| 2-4          | Likely benign | 0.10-0.30 |
| 1            | Clean | ≤ 0.10 |

## Endpoints used

Documented at `https://tria.ge/docs/cloud-api/`. All require
`Authorization: Bearer <token>`.

| Endpoint | Purpose |
|----------|---------|
| `POST /v0/samples` | Submit a sample (`kind: file`, `interactive: false`) |
| `GET  /v0/samples/{id}` | Status (`pending`, `static_analysis`, `scheduled`, `running`, `processing`, `reported`, `failed`) |
| `GET  /v0/samples/{id}/summary` | Per-task summary used for normalization |
| `GET  /v0/samples/{id}/overview.json` | Aggregated signatures, IOCs, `extracted[].config` |
| `GET  /v0/samples/{id}/{task_id}/report_triage.json` | Per-task rich behavior with signature marks |
| `GET  /v0/samples/{id}/{task_id}/dump.pcapng` | Decrypted PCAP (optional, not auto-fetched) |
| `GET  /v0/search` | Corpus search (e.g. `family:emotet`) for similar-sample queries |

## Supported sample types (Triage)

Windows (DLL/EXE/MSI), Office (2003 + 2007+ + OpenOffice + RTF + SLK + IQY +
HTA), scripts (BAT/PS1/JS/JSE/VBE/PL/VBS/WSF), macOS (APP/DMG/PKG/mach-O/SCPT/SH),
Android (APK/DEX), Linux (ELF/SH on ARM, ARM64, MIPS, PPC, x86_64), images
(SVG static, PNG/JPG QR), JAR/LNK/URL/JNLP, archives (7z, ACE, BZ2, CAB,
DAA, EML, GZIP, IMG, ISO, LZ, LZH, MSG, PKZIP, RAR, TAR, TNEF, VBN, VHD,
XAR, XZ, ZIP). Source: `https://tria.ge/docs/cloud-api/filetypes/`.

## Known limitations

* No public rate limits documented. If you submit at high volume you may see
  HTTP 429s — the client uses exponential backoff on poll failures.
* Maximum behavioral runtime via API: 3600 seconds (1 hour).
* The `GET /samples/{id}/sample` download endpoint returns the **unencrypted**
  binary. Anyone with the URL can download it. Treat the URL as sensitive
  even when the sample itself is public.
* On the public cloud `DELETE /samples/{id}` always returns 403; deletions
  require contacting support.

## Replacing or supplementing CAPE

The two backends are mutually exclusive at runtime (single `SANDBOX__BACKEND`
value). For a paper that compares Maljan against an external sandbox
ground-truth, the typical flow is:

1. Run the experiment corpus once with `SANDBOX__BACKEND=cape2` to capture
   the in-house verdicts.
2. Re-run with `SANDBOX__BACKEND=triage` to capture the external
   ground-truth. Each report has both `report["sandbox_url"]` and
   `report["extracted"][*].config.family` so the comparison can be
   automated.
3. Compare verdicts and family attributions across the two runs in the
   evaluation chapter.
