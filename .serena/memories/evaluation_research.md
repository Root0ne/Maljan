# Evaluation Harnesses, Datasets & Research Findings

> NEW memory, written 2026-07-05. The June-2026 research/eval era: measurement harnesses,
> vendored datasets, and headline A/B results. Canonical source:
> `docs/academic-article/findings-log.md` (~1,486 lines, append-only paper-seed log; entries
> tagged IMPLEMENTED/EXPERIMENTAL/OBSERVED/HYPOTHESIS/NEGATIVE; §0 thesis, §1 system
> contributions, §2 empirical systems findings, §3 prompting experiments, §4 literature-driven
> roadmap + "Datasets used"; changelog at the end).

## Measurement harnesses (`tests/evaluation/eval_*.py` — NOT pytest; run via `uv run python`)
- `eval_temporal_drift.py` — concept-drift eval (§4 Item 5, MARD-style). Dated manifest ->
  first-seen-year cohorts, per-cohort ATT&CK P/R/F1 ± bootstrap CI. Contains `_ensure_llm_healthy`
  (LLM health check before scoring), JSONL checkpoint/resume, llama-server OOM auto-restart,
  `--dry-run`, `--max-per-cohort`. Ground truth: `ground_truth/attck_malware/<slug>.json`.
- `eval_narrative_quality.py` — MaLAware-style (MSR 2025) paired A/B: NarrativeAgent vs
  deterministic fallback; faithfulness/coverage/structure/linter scores; sign test.
- `eval_hint_ablation.py` — end-to-end schema-pruning hint ablation (§1.7.1); real LLM paired
  ON/OFF; TTP P/R/F1 + hallucination vs 691-ID catalog.
- `run_family_rag_ab.py` — family-RAG + ATT&CK-case LLM-in-the-loop A/B; runs eval_temporal_drift
  twice as subprocess (RAG flags off/on); **forces `SANDBOX__BACKEND=mock`** (no live malware
  upload) + `NEGOTIATION__MAX_ITERATIONS=1`; resumable. (Docstring says n=210 but realized
  leakage-free subset = n=19 — ab_on/ab_off.jsonl.)
- `eval_family_rag_retrieval.py` — leakage-free retrieval measurement (U3): RAT-collection
  `extracted/<Family>/a0/`=TRAIN vs `a1/`=TEST; recall@k + MRR vs chance. Offline.
- `eval_view_decomposition.py` — equal-budget monolithic vs N-view A/B (§3.6; fixes §3.2
  unequal-budget confound).
- `eval_category_inference.py` — keyword vs semantic vs hybrid category backend, full vs
  behavioral regimes.
- `eval_technique_mapping.py` — TF-IDF vs semantic (BGE-384) evidence->ATT&CK mapping on TRAM2.
- `eval_autocorrect_ablation.py` — §1.5.2 `correct_isr_reports` ablation (server-free).
- `eval_function_rag.py` — TraceRAG function-retrieval A/B (offline synthetic corpus).
- Support: `benchmark_runner/suite.py`, `metrics.py`, `category_eval_data.py`,
  `collect_temporal_manifest.py` (MalwareBazaar manifest builder + downloader; AES zips via
  pyzipper, password "infected"; `--source csv|api`, `$MALWAREBAZAAR_AUTH_KEY`).
- Plus 8 `test_*.py` pure-scoring unit tests.

## Datasets (binaries NEVER committed; only derived text catalogs vendored in `data/`)
- **MABEL** — vx-underground-attributed features-only CSV (475 families, ~82k Windows-PE rows,
  no binaries). Feeds `build_family_feature_kb.py --csv` -> `data/family_fingerprints_mabel_v1.json`
  (U3) and `build_attck_case_kb.py --mabel-csv` (capa->ATT&CK mining) ->
  `data/attck_case_corpus_v1.json` (U2). Embedding-parity tradeoff (CSV columns != runtime profile).
- **Ultimate-RAT-Collection** — Windows RAT binaries, folder-per-family .7z (pw "infected"),
  649 families/36 GB. Extracted (gitignored) to `data/samples/extracted/<Family>/a0|a1/`
  (7,111 PE). -> `data/family_fingerprints_rat_v1.json` = 278 perfect-parity fingerprints
  (same `build_static_analysis`->`build_sample_profile_text` renderer as runtime). Also the
  a0/a1 TRAIN/TEST split for leakage-free retrieval eval.
- **U-numbering (§4)**: U1 = deeper per-family sampling; U2 = ATT&CK case-prior RAG corpus;
  U3 = family-feature fingerprint catalog. U2/U3 share the sample-profile-text embedding space.

## KB builders (`scripts/`)
- `build_family_feature_kb.py` (--samples-dir | --csv; min_per_family=3) ->
  `data/family_fingerprints_v1.json` (schema maljan-family-fingerprints/v1).
- `build_attck_case_kb.py` (--qdrant-url | --cases-jsonl | --mabel-csv; max_per_family=12) ->
  `data/attck_case_corpus_v1.json` (schema maljan-attck-case-corpus/v1; stores text, index
  embeds at load).

## Headline results (remember these before proposing changes)
- **Family-RAG + case-RAG A/B (2026-06-22): NO measurable TTP gain** (n=19, static-only/mock/
  1-round; F1 0.012->0.015, within noise) -> **both RAGs stay gated OFF**; retrieval layer kept
  for richer regimes. `family_rag_ab.json` vendored.
- **Leakage-free U3 retrieval**: recall@5=0.199, MRR=0.122 = ~6.3x chance (158 families/629
  samples) — real-but-modest; validates advisory/LLM-as-decider design.
- **Concept drift (Item 5)**: NO measurable drift across 7 yearly cohorts (delta −0.004; F1
  0.055–0.089, CIs overlap). Static-only recall structurally low (0.04–0.06), hallucination ~0.
  Argues dynamic analysis is needed for recall.
- **Hint ablation (§1.7.1)**: schema-pruning hint's benefit = run COMPLETION (fallback bundles
  1/17 -> 6/17), not mapping accuracy.
- **Autocorrect ablation (§1.5.2)**: swap_valid damages ~38% correct IDs to recover ~21% ->
  default zero-regression mode (`attck_autocorrect_swap_valid=False`).
- **Category inference (§1.7)**: keyword 0.792 acc (full) vs semantic 0.376 (NEGATIVE) vs
  hybrid 0.812 -> default backend stays "keyword".
- **View decomposition**: §3.2 INCONCLUSIVE (unequal budget); redone equal-budget in §3.6;
  feature remains OFF by default (`LLM__VIEW_DECOMPOSITION_VIEWS=0`).
- **Negatives (§2)**: MTP/spec-decoding no gain on A3B MoE; quantized V-cache + 256k ctx wedges
  llama-server (hence 131k + f16 V-cache in run_llama.ps1).
