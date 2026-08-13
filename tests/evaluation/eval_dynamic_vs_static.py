"""C4 — does the dynamic evidence path change what the pipeline finds?

Paired, on real samples: the same binary, the same static evidence, the same
model at temperature 0, with **one key different** in the graph's initial state.

    dynamic arm      state["sandbox_report"] = the archived CAPE report
    static-only arm  state["sandbox_report"] = None

Both arms are driven by injecting the *archived* report rather than submitting to
the sandbox, which makes the experiment deterministic and re-runnable without
network access — and, more importantly, guarantees the two arms differ in exactly
one thing. A live submission would also vary detonation timing, VM state and
retention.

**The covariate this experiment must report, or its delta is misleading.** §3.21
measured the cohort's network evidence and found that of 130 distinct domains,
**40 appear in all 43 samples** — the analysis VM's own WPS Office and Kingsoft
telephony, present in every capture. Each sample's domains are 63.5-81.6%
cohort-ubiquitous, median **71.4%**. A "dynamic channel" that is seven-tenths
constant is a weaker treatment than its name suggests, so this harness records
each sample's ubiquitous share alongside its delta. Reporting the effect without
it would invite the reader to attribute to malware behaviour what is partly the
sandbox describing itself.

Design lessons from this project's own failures, all of them paid for:

* **The model server is restarted between samples** (§3.22: without it, C3 reached
  17.8 GB of a 20 GB cgroup cap, began thrashing inside its own limit, and died at
  102/105 arms on judge connection errors that were really a suffocating server).
  It is launched as a transient systemd unit so its memory is accounted to its own
  cgroup rather than to whatever launched this (§E5 §3).
* **Host state is recorded at both ends of every arm** (§3.18: four arms died while
  the host swapped, and nothing retained could say whether the pipeline or the
  machine had failed).
* **Every archived report is verified against the sha it claims to describe**
  before use (§6: the sandbox answers a request for a deleted report with HTTP 200
  and a 63-byte error body).
* **Checkpointed per (sample, arm)**, so an interruption costs one run.
* **Output cardinality is reported**, because a batch whose N inputs produce far
  fewer than N distinct outputs is repeating itself.

Run:  .venv/bin/python tests/evaluation/eval_dynamic_vs_static.py [--limit N]
Requires llama-server (restarted per sample by this script) and Ghidra.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src"))

import httpx  # noqa: E402

from tests.evaluation.eval_temporal_drift import (  # noqa: E402
    available_fixture_slugs,
    extract_predicted_tids,
    load_ground_truth,
    resolve_fixture_slug,
)
from tests.evaluation.metrics import TTPAccuracyMetrics  # noqa: E402

REPORTS_DIR = _REPO_ROOT / "data" / "cape_reports"
SAMPLES_DIR = _REPO_ROOT / "data" / "samples"
CONTAINER_DIR = "/data/samples"
# The same ground-truth fixtures C5 scores against, so the two studies agree.
GT_DIR = _HERE / "ground_truth" / "attck_malware"
COHORT = _HERE / "dynamic_cohort_n100.json"
OUT = _HERE / "dynamic_vs_static.json"
CHECKPOINT = _HERE / "dynamic_vs_static_checkpoint.jsonl"
SEED = 20260812

LLAMA_UNIT = "c4-llama"
LLAMA_BIN = "/home/user/maljan-llm-build/ik_llama.cpp/build-cuda/bin/llama-server"
LLAMA_MODEL = str(_REPO_ROOT / "models" / "Qwen3.6-35B-A3B-IQ3_K_R4.gguf")
GRACE = _REPO_ROOT / "logs" / "night-job.grace"


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def host_memory() -> dict[str, int]:
    """MemAvailable, SwapFree, and how much of the model server is paged out."""
    out: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            if key in ("MemAvailable", "SwapFree"):
                out[key] = int(rest.split()[0]) // 1024
    except OSError:
        pass
    try:
        pids = subprocess.run(
            ["pgrep", "-x", "llama-server"], capture_output=True, text=True, timeout=5
        ).stdout.split()
        if pids:
            for line in Path(f"/proc/{pids[0]}/status").read_text().splitlines():
                if line.startswith(("VmSwap:", "VmRSS:")):
                    out["llama_" + line.split(":")[0][2:].lower()] = int(line.split()[1]) // 1024
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return out


def restart_llama() -> bool:
    """Fresh model server per sample, in its own cgroup. Returns True when healthy.

    §3.22: the verdict study did not do this and reached 17.8 GB of its 20 GB cap
    before suffocating. The transient unit keeps the memory accounted where it
    belongs; the grace marker tells the guard this drop is declared.
    """
    GRACE.parent.mkdir(parents=True, exist_ok=True)
    # The epoch goes *inside* the marker, not just on its mtime: the guard
    # reads its age with a builtin rather than stat(1), because the pass that
    # needs this answer is the one where forking has stopped working.
    GRACE.write_text(f"{int(time.time())}\n")
    subprocess.run(["pkill", "-f", "llama-server"], capture_output=True)
    subprocess.run(
        ["systemctl", "--user", "reset-failed", f"{LLAMA_UNIT}.service"], capture_output=True
    )
    time.sleep(5)
    subprocess.Popen(
        [
            "systemd-run",
            "--user",
            f"--unit={LLAMA_UNIT}",
            "--collect",
            "--property=MemoryMax=20G",
            "--property=MemorySwapMax=2G",
            LLAMA_BIN,
            "-m",
            LLAMA_MODEL,
            "-c",
            "65536",
            "-t",
            "16",
            "-fa",
            "on",
            "-ctk",
            "q8_0",
            "-ctv",
            "q8_0",
            "-ngl",
            "999",
            "-ot",
            r"blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU",
            "--context-shift",
            "on",
            "--jinja",
            "--alias",
            "qwen3.6-35b-a3b",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            if httpx.get("http://localhost:8080/health", timeout=5).json().get("status") == "ok":
                GRACE.unlink(missing_ok=True)
                return True
        except Exception:  # noqa: BLE001 — still starting
            pass
        time.sleep(5)
    GRACE.unlink(missing_ok=True)
    return False


def restart_ghidra(base: str, token: str) -> None:
    subprocess.run(["docker", "restart", "maljan-ghidra-mcp"], capture_output=True, timeout=180)
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    for _ in range(40):
        try:
            httpx.get(f"{base}/get_metadata", headers=hdr, timeout=5)
            return
        except Exception:  # noqa: BLE001
            time.sleep(3)


# ---------------------------------------------------------------------------
# Cohort and the contamination covariate
# ---------------------------------------------------------------------------


def load_report(sha: str) -> dict[str, Any] | None:
    """Read an archived report, refusing anything that is not about this sample."""
    path = REPORTS_DIR / f"{sha}.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return None
    got = str(((payload.get("target") or {}).get("file") or {}).get("sha256") or "")
    return payload if got.lower() == sha.lower() else None


def sample_domains(report: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for entry in (report.get("network") or {}).get("domains") or []:
        name = entry.get("domain") if isinstance(entry, dict) else str(entry)
        if name:
            out.add(str(name))
    return out


def ubiquitous_domains(reports: dict[str, dict[str, Any]]) -> set[str]:
    """Domains present in every sample — the sandbox describing itself (§3.21)."""
    sets = [sample_domains(r) for r in reports.values()]
    if not sets:
        return set()
    common = set(sets[0])
    for s in sets[1:]:
        common &= s
    return common


# Degradation reasons the static-only arm is **supposed** to carry: they are the
# manipulation restating itself. Removing the sandbox report necessarily leaves
# the pipeline without dynamic detonation data and leaves the two analysts that
# consume it with nothing to claim. Counting those as evidence that the arms
# differ for uncontrolled reasons would flag every pair in the study and bury a
# valid result under a caveat that describes the design working correctly.
_TREATMENT_MARKERS = ("no sandbox report", "dynamic detonation unavailable")
_TREATMENT_STARVED_ANALYSTS = {"dynamic", "network"}


def incidental_reasons(reasons: list[str], arm: str) -> set[str]:
    """Degradation this arm suffered that the manipulation does not explain.

    For the dynamic arm every reason is incidental — nothing was withheld from
    it. For the static-only arm, reasons naming the absent sandbox report are
    the treatment, and an "analysts produced no claims" list is stripped of the
    analysts that had nothing to consume; if that list names *only* those, the
    reason is fully explained and drops out, and if it also names, say, the
    static analyst, what remains is a real failure the pair must answer for.
    """
    out: set[str] = set()
    for raw in reasons:
        why = str(raw).strip()
        if arm != "static_only":
            out.add(why)
            continue
        low = why.lower()
        if any(marker in low for marker in _TREATMENT_MARKERS):
            continue
        head, sep, tail = why.partition("analysts produced no claims:")
        if sep and not head.strip():
            named = {p.strip().lower() for p in tail.split(",") if p.strip()}
            remaining = named - _TREATMENT_STARVED_ANALYSTS
            if not remaining:
                continue
            out.add(f"analysts produced no claims: {', '.join(sorted(remaining))}")
            continue
        out.add(why)
    return out


def techniques_by_source(result: Any) -> dict[str, list[str]]:
    """Which ISR source claimed which techniques, so the delta can be attributed.

    Added after the eighth pair, because the interim data raised a question the
    harness could not answer. In **7 of 7** dynamic arms with recorded reasons,
    the pipeline reported "analysts produced no claims: dynamic, network" — the
    two LLM analysts that consume the sandbox report produced nothing *while
    holding it* — and yet the dynamic arm predicted more techniques than the
    static-only arm (median 12 against 8).

    §3.21 measured `sigma_layer` firing on 43/43 of this cohort with unique
    technique credit on 43/43, which makes the deterministic rule engine the
    obvious candidate. Obvious is not measured. This records the attribution so
    the claim "the dynamic channel reaches the output through Layer-0 rules
    rather than through the analysts assigned to it" can be checked rather than
    inferred.
    """

    def _get(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    out: dict[str, list[str]] = {}
    isr_reports = _get(result, "isr_reports", {}) or {}
    items = isr_reports.items() if isinstance(isr_reports, dict) else []
    for name, isr in items:
        tids = set()
        for claim in _get(isr, "claims", []) or []:
            tid = _get(claim, "technique_id", None)
            if tid:
                tids.add(str(tid).upper())
        out[str(name)] = sorted(tids)
    return out


def predicted_from_result(result: Any) -> set[str]:
    """The techniques this run predicted: ISR claims ∪ cascade-corroborated.

    **Not** ``state["judge_report"]``, which `pipeline/state.py` declares as
    ``str | None`` — a prose paragraph. Reading ``.get("ttp_mappings")`` off it
    threw ``AttributeError`` after the first smoke arm had already spent twenty
    minutes producing a perfectly good result, which is the whole argument for
    smoke-testing a long study before launching it.

    Delegates to C5's extractor rather than re-deriving the set, so the two
    studies' F1 numbers are computed from the same definition and can be read
    against each other. Ground truth already resolves the same way.
    """
    return extract_predicted_tids(result)


def bootstrap_ci(values: list[float], iters: int = 4000) -> tuple[float, float]:
    vals = [float(v) for v in values]
    if len(vals) < 2:
        return (vals[0], vals[0]) if vals else (0.0, 0.0)
    rng = random.Random(SEED)
    means = sorted(
        sum(rng.choice(vals) for _ in range(len(vals))) / len(vals) for _ in range(iters)
    )
    return means[int(0.025 * iters)], means[int(0.975 * iters)]


# ---------------------------------------------------------------------------
# One arm
# ---------------------------------------------------------------------------


async def run_arm(sha: str, report: dict[str, Any] | None, truth: set[str]) -> dict[str, Any]:
    """One full pipeline pass. `report is None` is the static-only arm."""
    from maljan.core.config import get_settings
    from maljan.core.container import ServiceContainer
    from maljan.pipeline.builder import build_graph

    cfg = get_settings()
    restart_ghidra(cfg.mcp.ghidra.url.rstrip("/"), cfg.mcp.ghidra.auth_token)
    container = ServiceContainer(config=cfg)
    graph = build_graph(container)

    state: dict[str, Any] = {
        "file_hash": sha,
        "file_name": f"{sha}.exe",
        "sample_path": str(SAMPLES_DIR / f"{sha}.exe"),
        "static_sample_path": f"{CONTAINER_DIR}/{sha}.exe",
        "sandbox_report": report,  # the only difference between arms
        "file_type": "PE32 executable",
        "platform": "windows",
        "reports": {},
        "revised_reports": {},
        "isr_reports": {},
        "tool_evidence": {},
        "discussion_history": [],
        "sycophancy_detected": False,
        "confidence_history": [],
        "iteration_count": 0,
        "is_consensus": False,
        "final_decision": None,
        "judge_report": None,
        "stix_output": None,
        "run_summary": None,
        "malware_report": None,
        "malware_report_markdown": None,
        "stix_bundle_extended": None,
        "degraded_mode": False,
        "degradation_reasons": [],
        "function_hash_matches": [],
        "family_rag_candidates": [],
        "attck_case_candidates": [],
        "tool_artifact_matches": [],
    }

    mem_before = host_memory()
    t0 = time.time()
    result = await graph.ainvoke(state)
    seconds = round(time.time() - t0, 1)
    mem_after = host_memory()

    predicted = {t for t in predicted_from_result(result) if t and t != "NONE"}
    m = TTPAccuracyMetrics(predicted_ttps=predicted, ground_truth_ttps=truth)
    return {
        "seconds": seconds,
        "predicted": sorted(predicted),
        "n_predicted": len(predicted),
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "f1": round(m.f1, 4),
        "techniques_by_source": techniques_by_source(result),
        "degraded": bool(result.get("degraded_mode")),
        # *Why* it degraded, not just that it did. The first arm came back
        # degraded, and a pair whose two arms degrade for different reasons is
        # not measuring the sandbox report — it is measuring which analyst
        # happened to fail. Recorded per arm so the confound is checkable
        # instead of assumed away.
        "degradation_reasons": [str(x) for x in (result.get("degradation_reasons") or [])],
        "host_mem_before": mem_before,
        "host_mem_after": mem_after,
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


async def main_async(limit: int) -> int:
    slugs = available_fixture_slugs(GT_DIR)
    truth_by_sha: dict[str, set[str]] = {}
    reports: dict[str, dict[str, Any]] = {}

    # Family signature comes from the cohort manifest (MalwareBazaar), not from
    # the sandbox report — the report knows the file, not the family, and C5
    # resolves ground truth the same way so the two studies stay comparable.
    by_sha = {s["sha256"]: s for s in json.loads(COHORT.read_text())["samples"]}
    skipped = {"unverified_report": 0, "no_ground_truth": 0}

    for sha in sorted(p.stem for p in REPORTS_DIR.glob("*.json")):
        report = load_report(sha)
        if report is None:
            skipped["unverified_report"] += 1
            continue
        slug = resolve_fixture_slug((by_sha.get(sha) or {}).get("signature") or "", slugs)
        truth = load_ground_truth(slug, GT_DIR)[0] if slug else set()
        if not truth:
            skipped["no_ground_truth"] += 1
            continue
        reports[sha] = report
        truth_by_sha[sha] = truth

    print(
        f"skipped: {skipped['unverified_report']} unverified, "
        f"{skipped['no_ground_truth']} without ground truth",
        flush=True,
    )

    shas = sorted(reports)[: limit or None]
    ubiquitous = ubiquitous_domains(reports)
    print(f"cohort: {len(shas)} samples with a verified report and resolved ground truth")
    print(f"cohort-ubiquitous domains (the sandbox's own telephony): {len(ubiquitous)}", flush=True)

    # A failed arm stays in the checkpoint — it is data about the run — but it
    # does **not** count as done, so a resume retries it. Treating an error row
    # as complete would silently drop that sample from the paired study and the
    # only trace would be a smaller n that nothing explains.
    done: set[str] = set()
    if CHECKPOINT.exists():
        for line in CHECKPOINT.read_text().splitlines():
            try:
                row = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if "error" not in row and row.get("key"):
                done.add(row["key"])

    for i, sha in enumerate(shas, 1):
        for arm in ("dynamic", "static_only"):
            key = f"{sha}:{arm}"
            if key in done:
                continue
            if not restart_llama():
                print("  model server did not come back healthy — stopping", flush=True)
                return 1
            try:
                row = await run_arm(
                    sha, reports[sha] if arm == "dynamic" else None, truth_by_sha[sha]
                )
            except Exception as exc:  # noqa: BLE001 — a failed arm is data
                row = {"error": f"{type(exc).__name__}: {str(exc)[:160]}"}
            doms = sample_domains(reports[sha])
            row |= {
                "key": key,
                "sha256": sha,
                "arm": arm,
                "n_domains": len(doms),
                "ubiquitous_share": round(len(doms & ubiquitous) / len(doms), 4) if doms else None,
            }
            with CHECKPOINT.open("a") as fh:
                fh.write(json.dumps(row) + "\n")
            print(
                f"  [{i}/{len(shas)}] {sha[:12]} {arm:11s} "
                f"F1={row.get('f1', 'ERR')} n={row.get('n_predicted', '-')} "
                f"{row.get('seconds', '-')}s",
                flush=True,
            )

    return summarise()


def summarise() -> int:
    rows = [json.loads(line) for line in CHECKPOINT.read_text().splitlines()]
    by_sha: dict[str, dict[str, Any]] = {}
    for r in rows:
        by_sha.setdefault(r["sha256"], {})[r["arm"]] = r

    pairs = [
        (sha, a["dynamic"], a["static_only"])
        for sha, a in by_sha.items()
        if {"dynamic", "static_only"} <= a.keys()
        and "error" not in a["dynamic"]
        and "error" not in a["static_only"]
    ]
    print(f"\npairs: {len(by_sha)} seen, {len(pairs)} scoreable")
    if not pairs:
        print("no scoreable pairs")
        return 1

    # Below this many pairs the bootstrap resamples a handful of values and
    # returns an interval that looks tight because there is nothing to vary.
    # At n=1 it is the observation twice over and would print "excludes 0" —
    # a phrase that survives being copied into prose long after the n does.
    INFERENCE_FLOOR = 5

    deltas = {k: [d[k] - s[k] for _, d, s in pairs] for k in ("f1", "recall", "precision")}
    summary: dict[str, Any] = {"n_pairs": len(pairs), "inference_floor": INFERENCE_FLOOR}
    interim = len(pairs) < INFERENCE_FLOOR
    print(f"\npaired deltas (dynamic − static-only), n={len(pairs)}")
    if interim:
        print(
            f"  ** INTERIM: n < {INFERENCE_FLOOR}. The intervals below are degenerate and the "
            "sign of the mean is not a result. Reported so the run can be watched, not cited. **"
        )
    for k, vals in deltas.items():
        mean = sum(vals) / len(vals)
        lo, hi = bootstrap_ci(vals)
        summary[k] = {"mean": round(mean, 4), "ci95": [round(lo, 4), round(hi, 4)]}
        verdict = (
            "interim, no inference"
            if interim
            else ("includes 0" if lo <= 0 <= hi else "excludes 0")
        )
        print(f"  {k:10s} {mean:+.4f}   95% CI [{lo:+.4f}, {hi:+.4f}]   {verdict}")

    shares = [d["ubiquitous_share"] for _, d, _ in pairs if d.get("ubiquitous_share") is not None]
    if shares:
        shares.sort()
        summary["ubiquitous_share"] = {
            "min": shares[0],
            "median": shares[len(shares) // 2],
            "max": shares[-1],
        }
        print(
            f"\nshare of each sample's domains that every sample also has: "
            f"{shares[0]:.1%} / {shares[len(shares) // 2]:.1%} / {shares[-1]:.1%} (min/median/max)"
        )
        print("  the dynamic arm's network evidence is that constant — read the delta with it")

    # Degradation, read as a threat rather than a footnote. A pair whose arms
    # degraded for different reasons is not a clean contrast: whatever the delta
    # says, part of it is which analyst failed that hour.
    scored = [(d, s) for _, d, s in pairs]
    deg = {
        "dynamic": sum(1 for d, _ in scored if d.get("degraded")),
        "static_only": sum(1 for _, s in scored if s.get("degraded")),
        "both": sum(1 for d, s in scored if d.get("degraded") and s.get("degraded")),
    }
    recorded = [
        (d, s) for d, s in scored if "degradation_reasons" in d and "degradation_reasons" in s
    ]
    # Compared on *incidental* reasons only. The static-only arm always carries
    # "no sandbox report" — that is the manipulation, not a confound, and
    # counting it would mark 100% of pairs contaminated by construction.
    mismatched = sum(
        1
        for d, s in recorded
        if incidental_reasons(d["degradation_reasons"], "dynamic")
        != incidental_reasons(s["degradation_reasons"], "static_only")
    )
    summary["degraded"] = deg
    summary["reason_mismatch"] = {"pairs_with_reasons": len(recorded), "differing": mismatched}
    print(
        f"\ndegraded arms: dynamic {deg['dynamic']}/{len(pairs)}, "
        f"static-only {deg['static_only']}/{len(pairs)}, both {deg['both']}"
    )
    print(
        "  the static-only arm is *expected* to report degradation: it has no sandbox report "
        "because that is the treatment"
    )
    if recorded:
        print(
            f"  pairs differing in degradation the treatment does NOT explain: "
            f"{mismatched}/{len(recorded)}"
            f"{' — that share of the delta is not attributable' if mismatched else ''}"
        )
    reasons: dict[str, int] = {}
    for d, s in recorded:
        both = incidental_reasons(d["degradation_reasons"], "dynamic") | incidental_reasons(
            s["degradation_reasons"], "static_only"
        )
        for why in both:
            reasons[why] = reasons.get(why, 0) + 1
    if reasons:
        summary["incidental_degradation_reasons"] = reasons
        print("  incidental reasons (the treatment does not account for these):")
        for why, count in sorted(reasons.items(), key=lambda kv: -kv[1])[:6]:
            print(f"    {count:3d}  {why[:96]}")

    # Where the dynamic arm's extra techniques actually come from. If the two
    # analysts that consume the sandbox report contribute nothing while the
    # deterministic sigma layer contributes the difference, then this study's
    # treatment is a rule engine, not an LLM reading behaviour — and the paper
    # must say so rather than let "the dynamic path" imply the analysts.
    attributed = [(d, s) for _, d, s in pairs if d.get("techniques_by_source") is not None]
    if attributed:
        gained: dict[str, int] = {}
        credited: dict[str, int] = {}
        for d, s in attributed:
            extra = set(d["predicted"]) - set(s["predicted"])
            for name, tids in (d.get("techniques_by_source") or {}).items():
                if tids:
                    credited[name] = credited.get(name, 0) + 1
                if extra & set(tids):
                    gained[name] = gained.get(name, 0) + 1
        summary["attribution"] = {
            "pairs_attributed": len(attributed),
            "sources_that_claimed_anything": credited,
            "sources_carrying_the_dynamic_gain": gained,
        }
        print(
            f"\nattribution over {len(attributed)} pairs — "
            "which source claimed the extra techniques"
        )
        for name, count in sorted(gained.items(), key=lambda kv: -kv[1]):
            print(f"  {count:3d}  {name}")
        silent = sorted(n for n in ("dynamic", "network") if credited.get(n, 0) == 0)
        if silent:
            print(
                f"  sources that claimed nothing in any dynamic arm: {', '.join(silent)}"
                " — they hold the sandbox report and produce no claim"
            )

    distinct = len({tuple(d["predicted"]) for _, d, _ in pairs})
    summary["distinct_dynamic_outputs"] = distinct
    print(f"\noutput cardinality: {distinct} distinct technique sets across {len(pairs)} samples")

    # The agent budgets the arms actually ran under, read from the live config
    # rather than restated. A study that quietly throttled an analyst and did not
    # say so is indistinguishable, on disk, from one that did not.
    try:
        from maljan.core.config import get_settings

        cfg = get_settings()
        budgets: dict[str, Any] = {
            "react_agent_timeout": cfg.react_agent_timeout,
            "react_agent_timeout_overrides": dict(cfg.react_agent_timeout_overrides),
        }
    except Exception as exc:  # noqa: BLE001 — provenance is recorded or its absence is
        budgets = {"unavailable": f"{type(exc).__name__}"}

    OUT.write_text(
        json.dumps(
            {
                "schema": "dynamic-vs-static/v1",
                "seed": SEED,
                "agent_budgets": budgets,
                "summary": summary,
                "per_pair": [{"sha256": s, "dynamic": d, "static_only": st} for s, d, st in pairs],
            },
            indent=1,
        )
    )
    print(f"\nwrote {OUT.relative_to(_REPO_ROOT)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="C4 — dynamic vs static-only, paired.")
    ap.add_argument("--limit", type=int, default=0, help="Cap the sample count (0 = all).")
    ap.add_argument("--summarise-only", action="store_true", help="Score the checkpoint and stop.")
    args = ap.parse_args()
    if args.summarise_only:
        return summarise()
    # **No timeout override.** This harness previously lowered the static
    # analyst's cap from production's 1500 s to 600 s, copied from B6's harness
    # without being weighed. It was measured on the first arm and reconsidered:
    # the tighter cap kills the analyst's forced-synthesis fallback (466 s hard
    # cap instead of ~1165 s), which suppresses static evidence in **both** arms.
    # That does not bias a paired delta symmetrically — less static evidence
    # leaves the dynamic channel less to compete with, so a throttled run would
    # tend to overstate the very effect this study exists to measure. The run is
    # slower at production settings and the achieved n is smaller; the checkpoint
    # makes any n reportable, and an n that describes the deployed system is
    # worth more than a larger one that describes a variant of it.
    return asyncio.run(main_async(args.limit))


if __name__ == "__main__":
    raise SystemExit(main())
