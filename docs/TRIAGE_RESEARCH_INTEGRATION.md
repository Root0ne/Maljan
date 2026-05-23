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
   SANDBOX__TRIAGE_TIMEOUT_SECONDS=600
   SANDBOX__TRIAGE_POLL_INTERVAL_SECONDS=15
   ```

4. Install httpx (already a Maljan dependency, no extra install needed).
5. Submit a sample as usual:

   ```bash
   uv run maljan analyze <sha256> -s samples/zararli.apk --name triage-test -i 3
   ```

The `report["sandbox_url"]` field in the persisted analysis report will hold
the citeable URL; quote it in the paper alongside the Maljan verdict.

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
