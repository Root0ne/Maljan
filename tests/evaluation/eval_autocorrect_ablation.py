"""Ablation: does the §1.5 autocorrect (correct_isr_reports) recover from the
small model's ATT&CK technique-ID errors?

Real ground truth (TRAM2 human labels) + real evidence (TRAM2 sentences) + the
production hybrid backend. Server-free (no LLM); we *simulate* the small model's
known error modes and measure whether the deterministic correction fixes them.

Three rate-free scenarios inject one known error into every claim, then compare
the corrected output (ON) against the OFF baseline (the raw injected id passes
through untouched, which is the pipeline's behaviour with the feature disabled):

  - hallucinated input (raw id = invalid T9999): can ON eliminate the invalid id
    and recover the correct technique?
  - wrong-valid input  (raw id = a valid but wrong id): can ON swap to the
    correct technique?
  - correct input      (raw id = the true label): does ON PRESERVE it? This is
    the false-correction / regression safety check.

Metrics per scenario: accuracy (final == ground-truth label) and hallucination
rate (final id well-formed but absent from the catalog), OFF vs ON.

Run:  uv run python tests/evaluation/eval_autocorrect_ablation.py [--limit N]
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

from maljan.core.config import Settings
from maljan.memory.attck_validator import ATTCKValidator
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

_OUTPUT_DIR = Path(__file__).resolve().parent

TRAM2_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense"
    "/tram/main/data/tram2-data/single_label.json"
)
_CACHE = Path.home() / ".cache" / "maljan" / "tram2_single_label.json"
_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# Deterministic pool of valid catalog IDs for the "wrong-valid" injection.
_WRONG_POOL = ["T1059", "T1071", "T1486", "T1055", "T1547", "T1078"]
_INVALID_ID = "T9999"


def _fetch_tram2() -> list[dict[str, str]]:
    if _CACHE.exists():
        data: list[dict[str, str]] = json.loads(_CACHE.read_text(encoding="utf-8"))
        return data
    with urllib.request.urlopen(TRAM2_URL, timeout=60) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8")
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE.write_text(raw, encoding="utf-8")
    fresh: list[dict[str, str]] = json.loads(raw)
    return fresh


def _wrong_valid_id(label: str) -> str:
    for cand in _WRONG_POOL:
        if cand != label:
            return cand
    return _WRONG_POOL[0]


def _run_scenario(
    validator: ATTCKValidator,
    pairs: list[tuple[str, str]],
    inject: str,
    min_align: float,
    swap_valid: bool,
) -> dict[str, float]:
    """Inject one error type into every claim, correct, and score ON vs OFF."""
    on_correct = off_correct = 0
    on_halluc = off_halluc = 0
    n = len(pairs)
    for text, label in pairs:
        raw_id = (
            _INVALID_ID
            if inject == "halluc"
            else _wrong_valid_id(label)
            if inject == "wrong"
            else label  # "correct"
        )
        # OFF baseline: raw id passes through untouched.
        if raw_id == label:
            off_correct += 1
        if not validator.validate_ttp_id(raw_id):
            off_halluc += 1

        claim = ClaimEvidence(
            claim="analyst finding", evidence_ref=text, confidence=0.8, technique_id=raw_id
        )
        reports = {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}
        validator.correct_isr_reports(reports, min_alignment=min_align, swap_valid=swap_valid)
        final = claim.technique_id

        if final == label:
            on_correct += 1
        if final is not None and not validator.validate_ttp_id(final):
            on_halluc += 1

    return {
        "off_acc": off_correct / n,
        "on_acc": on_correct / n,
        "off_halluc": off_halluc / n,
        "on_halluc": on_halluc / n,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=800, help="even-stride sample (0 = all)")
    args = ap.parse_args()

    cfg = Settings().preprocessing
    backend = cfg.attck_index_backend
    # Mirror the pipeline's backend-aware threshold selection.
    min_align = (
        cfg.attck_autocorrect_min_alignment_semantic
        if backend == "semantic"
        else cfg.attck_autocorrect_min_alignment
    )
    print(f"backend={backend} min_alignment={min_align}", flush=True)
    validator = ATTCKValidator.get_instance(backend=backend)

    entries = _fetch_tram2()
    pairs_all: list[tuple[str, str]] = []
    for e in entries:
        text = (e.get("text") or "").strip()
        label = (e.get("label") or "").strip().upper()
        if text and _TID_RE.match(label) and validator.validate_ttp_id(label):
            pairs_all.append((text, label))
    if args.limit and len(pairs_all) > args.limit:
        stride = len(pairs_all) / args.limit
        pairs = [pairs_all[int(i * stride)] for i in range(args.limit)]
    else:
        pairs = pairs_all
    print(f"TRAM2: {len(pairs_all)} valid pairs; ablation on {len(pairs)}.", flush=True)

    scenarios = [
        ("hallucinated input (raw=T9999)", "halluc"),
        ("wrong-valid input", "wrong"),
        ("correct input (regression)", "correct"),
    ]
    # Compare the old behaviour (swap valid IDs too) against the production-
    # default fix (swap_valid=False: only fix invalid IDs).
    modes = [("swap_valid=True (old)", True), ("swap_valid=False (default/fixed)", False)]

    lines = [
        "# Autocorrect ablation (TRAM2 ground truth, hybrid backend)",
        "",
        f"- Backend: {backend} | min_alignment: {min_align} | N = {len(pairs)} claims.",
        "- Real evidence (TRAM2 sentence) + real label; the small model's error is "
        "simulated, the correction is real. OFF = raw injected id passes through.",
        "- accuracy = final id == ground-truth label; hallucination = final id "
        "well-formed but absent from the catalog.",
    ]
    for mode_name, swap in modes:
        lines += [
            "",
            f"## Mode: {mode_name}",
            "",
            "| scenario | acc OFF | acc ON | halluc OFF | halluc ON |",
            "|---|---|---|---|---|",
        ]
        for name, inject in scenarios:
            print(f"[{mode_name}] {name} ...", flush=True)
            m = _run_scenario(validator, pairs, inject, min_align, swap)
            lines.append(
                f"| {name} | {m['off_acc']:.3f} | {m['on_acc']:.3f} | "
                f"{m['off_halluc']:.3f} | {m['on_halluc']:.3f} |"
            )
    report = "\n".join(lines)
    print("\n" + report, flush=True)
    out = _OUTPUT_DIR / "autocorrect_ablation.md"
    try:
        out.write_text(report + "\n", encoding="utf-8")
        print(f"\nWrote {out}", flush=True)
    except OSError:
        pass


if __name__ == "__main__":
    main()
