# capa and YARA

capa (FLARE's capability detector) and YARA reach a run in three places, so a
run can have their answers even with no static provider at all.

| Where | What runs | Written to the ledger as |
| :-- | :-- | :-- |
| The triage pack | `yara_scan` and `capa` (under the static provider's budget), before any analyst starts | the pack's own entries |
| The `analysis` sidecar | the `capa` and `yara_scan` tools, which an agent calls | the agent's calls |
| The `capa_yara` static provider | two deterministic passes, no tools and no model loop | entries under the agent id `capa_yara` |

## The `capa_yara` provider

```
core.static.provider          = capa_yara
core.static.capa.rules_dir    = data/capa-rules
core.static.yara.rules_dir    = data/yara_rules
```

| Setting | Default | Notes |
| :-- | :-- | :-- |
| `core.static.capa.rules_dir` | `data/capa-rules` | capa's rules. |
| `core.static.capa.signatures_dir` | `data/capa-signatures` | capa's library signatures. |
| `core.static.capa.timeout_seconds` | `300` | capa's budget. |
| `core.static.capa.backend` | `auto` | `auto`, `vivisect`, `pefile` or `binja`. |
| `core.static.yara.rules_dir` | `data/yara_rules` | The operator's own rule directory, scanned only by this provider. |
| `core.static.yara.timeout_seconds` | `60` | The scan's budget. |

Both libraries are optional extras of the package, `capa` (flare-capa) and
`yara` (yara-python): `uv sync --extra capa --extra yara`. The backend image
installs the `yara` and `tools` extras. A missing library costs the provider
its evidence, with one warning, rather than failing a job.

## The rule corpora of the `analysis` sidecar

The Sigma and YARA corpora the `analysis` tool server scans with are named in
that server's `env` (**Settings → Tool servers → `analysis` → `env`**):

| Name | What it names | Default |
| :-- | :-- | :-- |
| `MALJAN_SIGMA_RULES_DIR` | Directory of Sigma rule YAML, loaded recursively. | `data/sigma_rules` |
| `MALJAN_YARA_RULES_DIR` | The YARA rule file the scan compiles. | `data/yara_ttp_rules.yaml` |

A path that does not exist means an empty corpus and no matches, not a failure.
A YARA pattern must be a fact about a sample rather than a word that describes
one; how the shipped rules are written, and how a rule asserts nothing when it
cannot be that specific, is in [Rule corpora](../configuration.md#rule-corpora).

## A rule match is not a claim

A technique that only a deterministic rule asserted, and no analyst claimed, is
marked as such in the report's ATT&CK table — "rule match only" with the rule
and its string count — and grounds no capability word in the report's prose.
capa's place in the triage pack is described in [The triage
pack](../architecture.md#the-triage-pack).
