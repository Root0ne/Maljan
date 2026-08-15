"""E.2 — negotiated multi-agent consensus vs a single agent, at equal token budget.

**This is the experiment the paper's shape depends on.** The literature's prior now
runs *against* our design: `arXiv:2604.02460` (Stanford) and `arXiv:2605.00914`
both find single agents match or beat multi-agent debate at equal budget, the
latter on 7–8B models — our scale — at 2.1–3.4x the tokens. Both scope that
result to **homogeneous** agents decomposing **one** context, and both name
heterogeneous evidence channels as the exception. Ours are heterogeneous
evidence channels. That is our defence, and it is a hypothesis until this runs.

`arXiv:2604.02460` §5.3 sharpens it further: under controlled degradation it
finds a **crossover** — single-agent leads at mild degradation, multi-agent wins
at heavy (alpha=0.7) — measured on Qwen3-30B-A3B, our own model class. So the
question is not *whether* an exception exists but **which side of the crossover
a malware pipeline sits on**.

Design taken from Bertalanič & Fortuna rather than invented here — three arms,
including their stochastic noise control:

  * **negotiated**  — K analysts, one heterogeneous evidence channel each, then a
    mediator call that reconciles their claims. Today's topology.
  * **single**      — one call, **all** channels concatenated, full budget.
  * **noise**       — negotiated, but one analyst is fed a channel from a
    *different sample*. If this scores like `negotiated`, the negotiation is
    aggregating rather than reconciling, and the mechanism is not doing the work
    we claim for it.

**Equal total budget** is the control the literature demands and §3.2 lacked:
`single` gets 1 call at B; `negotiated` and `noise` get K+1 calls at B/(K+1), so
the mediator is paid for out of the same budget. Token cost is reported either
way, because "wins at 3x the tokens" is not a win.

**Pre-registered hypothesis, written up whichever way it lands:** heterogeneous
evidence-channel decomposition survives the equal-budget control that homogeneous
debate fails. A negative result is published — the field's prior already points
that way, and a negative from us is the more useful contribution.

One design point worth stating because it is easy to get wrong. The fixture
bundles used by ``eval_view_decomposition`` annotate each artifact with
``[associated technique: T1234]``. That is fine there — it scores *grounding*.
It would be fatal here, where the metric is **accuracy against the fixture's
ground-truth technique set**: every arm would score perfectly by copying. So this
harness builds its own evidence from ``_ARTIFACTS`` below, in which each artifact
*implies* its technique without naming it, and asserts at startup that no
ground-truth id leaks into any channel.

Run:  uv run python tests/evaluation/eval_consensus_ablation.py [--repeats K] [--budget B] [--smoke]
Requires a live llama-server. Measurement tool, not a pytest test — the pure
scoring helpers are unit-tested in ``test_consensus_ablation_scoring.py``.
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Hashable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.core.config import get_settings
from maljan.core.container import ServiceContainer
from tests.evaluation import stats

_FIXTURE_DIR = _REPO_ROOT / "tests" / "evaluation" / "fixtures"
_OUT_FILE = _REPO_ROOT / "tests" / "evaluation" / "consensus_ablation.md"
_JSON_FILE = _REPO_ROOT / "tests" / "evaluation" / "consensus_ablation.json"
_DEFAULT_CHECKPOINT = Path("/tmp/consensus_ablation_checkpoint.jsonl")
_DEFAULT_BUDGET = 2400

# This harness and the two that import from it had no seed constant at all: the
# estimator hard-coded a golden-ratio constant in its own body and wrote no seed
# into the artifact, so every interval it published was unreproducible from its
# own file. Dated to the run that produced consensus_ablation.json.
SEED = 20260809

_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# Per-call wall-clock cap for eval runs. A legitimate 600-token answer takes
# ~15 s at ~40 tok/s, so this is 8x headroom and anything past it is a
# degenerate decode (§3.3) that should be skipped rather than waited on.
_CALL_TIMEOUT_S = 120

# The three heterogeneous evidence channels. Fixed at three so every arm's
# budget arithmetic is identical across samples, and chosen so that all five
# fixtures populate all three — an empty channel would hand `single` a free
# advantage by making `negotiated` pay B/(K+1) for a call with nothing to say.
# (That pathology is real and documented in the ledger as "manufactured false
# corroboration from a dataless analyst"; it is just not what E.2 is testing.)
CHANNELS = ("static", "dynamic", "network")

# technique id -> (channel, artifact text). The artifact must IMPLY the
# technique to a reader who knows ATT&CK, and must never name it — that is what
# makes this a measurement rather than a copying exercise.
_ARTIFACTS: dict[str, tuple[str, str]] = {
    # -- static: what is visible without running the sample -----------------
    "T1140": (
        "static",
        "XOR loop over a 0x2E00-byte .rdata blob with a rolling key; the "
        "decoded output begins with 'MZ' and a valid PE header",
    ),
    "T1547": (
        "static",
        "Writes HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater "
        "with the path of the dropped binary",
    ),
    "T1560": (
        "static",
        "Bundled miniz; files staged into a password-protected archive in %TEMP% "
        "before any upload occurs",
    ),
    "T1056": (
        "static",
        "Imports SetWindowsHookExW and GetAsyncKeyState; a buffer is flushed to "
        "%TEMP%\\kl.dat on a timer",
    ),
    "T1082": (
        "static",
        "Imports GetSystemInfo, GetComputerNameW and GetVolumeInformationW, all "
        "called from one initialisation routine",
    ),
    "T1091": (
        "static",
        "Embedded 'autorun.inf' string plus RegisterDeviceNotification and "
        "GetLogicalDrives imports",
    ),
    # -- dynamic: what the sandbox observed ---------------------------------
    "T1055": (
        "dynamic",
        "VirtualAllocEx, WriteProcessMemory and CreateRemoteThread issued "
        "against explorer.exe (PID 1234)",
    ),
    "T1059": ("dynamic", "Spawns cmd.exe /c powershell -nop -w hidden -enc <base64 blob>"),
    "T1486": (
        "dynamic",
        "CryptEncrypt applied to 12,400 files, each renamed with a .lckd "
        "suffix; a README is written to every touched directory",
    ),
    "T1489": ("dynamic", "net stop issued for MSSQLSERVER, SQLWriter and VeeamBackupSvc"),
    "T1490": (
        "dynamic",
        "vssadmin delete shadows /all /quiet followed by bcdedit /set recoveryenabled No",
    ),
    "T1003": (
        "dynamic",
        "Opens lsass.exe with PROCESS_VM_READ|PROCESS_QUERY_INFORMATION and "
        "calls MiniDumpWriteDump",
    ),
    "T1115": ("dynamic", "OpenClipboard and GetClipboardData polled on a 2 s interval"),
    "T1057": (
        "dynamic",
        "CreateToolhelp32Snapshot followed by a Process32First/Process32Next enumeration loop",
    ),
    "T1021": (
        "dynamic",
        "Authenticates an SMB session to \\\\WORKSTATION-07\\ADMIN$ and creates "
        "a service on the remote host",
    ),
    # -- network: what the capture showed -----------------------------------
    "T1071": (
        "network",
        "HTTPS POSTs every 60 s +/- 5 s jitter to cdn.example-c2.top, body "
        "length constant at 512 bytes",
    ),
    "T1105": (
        "network",
        "GET /update/stage2.bin returning 1.4 MB whose first two bytes are "
        "'MZ'; the body is then written to C:\\Users\\Public\\stage2.bin",
    ),
    "T1041": (
        "network",
        "A single POST /gate.php carrying a 4.2 MB multipart body to the same "
        "host used for periodic beaconing",
    ),
    "T1095": (
        "network",
        "Raw TCP to 185.220.101.47:8443 with custom length-prefixed framing and no TLS ClientHello",
    ),
    "T1190": (
        "network",
        "Outbound HTTP request to /cgi-bin/luci with shell metacharacters in the User-Agent header",
    ),
    "T1210": (
        "network",
        "SMBv1 TRANS2 requests with a malformed subcommand, swept across 10.0.0.0/24",
    ),
}


# ---------------------------------------------------------------------------
# Evidence construction (pure — unit-tested without an LLM)
# ---------------------------------------------------------------------------


def build_channels(technique_ids: list[str]) -> dict[str, str]:
    """Group a sample's ground-truth techniques into heterogeneous channels.

    Returns ``{channel: evidence_text}`` for every channel in :data:`CHANNELS`
    that has at least one artifact. The technique ids themselves never appear in
    the output — see the module docstring for why that matters.
    """
    grouped: dict[str, list[str]] = {c: [] for c in CHANNELS}
    for tid in technique_ids:
        entry = _ARTIFACTS.get(str(tid).upper())
        if entry is None:
            continue
        channel, artifact = entry
        grouped[channel].append(artifact)
    return {
        channel: "\n".join(f"- {a}" for a in artifacts)
        for channel, artifacts in grouped.items()
        if artifacts
    }


def leaked_ids(channels: dict[str, str]) -> list[str]:
    """Any ATT&CK id appearing in the evidence — must always be empty.

    A leak turns the accuracy metric into a copying test and would make every
    arm look perfect. Checked at startup rather than trusted.
    """
    found: list[str] = []
    for text in channels.values():
        found.extend(m.group(0).upper() for m in _TID_RE.finditer(text))
    return sorted(set(found))


def channel_prompt(channel: str) -> str:
    """The per-analyst instruction. One channel, no cross-channel speculation."""
    return (
        f"You are the {channel} analyst. Below is the {channel} evidence for one sample, "
        "and nothing else. Report the ATT&CK techniques this evidence supports. "
        "Cite the specific artifact behind each claim. Do not speculate about evidence "
        "you were not given."
    )


MEDIATOR_PROMPT = (
    "You are the mediator. Below are the claims of independent analysts, each of whom saw "
    "only one channel of evidence. Reconcile them into one final list of ATT&CK techniques "
    "for this sample. Keep a technique when its channel's artifact supports it; drop it when "
    "the cited artifact does not; and note where two channels corroborate the same technique. "
    "Do not add techniques no analyst raised."
)

SINGLE_PROMPT = (
    "You are the analyst. Below is the complete evidence for one sample across every channel. "
    "Report the ATT&CK techniques this evidence supports, citing the specific artifact behind "
    "each claim. Do not speculate about evidence you were not given."
)


def render_all_channels(channels: dict[str, str]) -> str:
    """The `single` arm's input: every channel, same content, one prompt."""
    return "\n\n".join(f"[{c} evidence]\n{channels[c]}" for c in CHANNELS if c in channels)


def swap_one_channel(
    channels: dict[str, str], donor: dict[str, str], victim: str
) -> dict[str, str]:
    """The noise arm: replace ``victim``'s evidence with the donor sample's.

    The analyst still speaks, still with confidence, and still under its own
    channel tag — which is precisely the condition under which a corroboration
    counter can be fooled. Falls back to the original when the donor has no such
    channel, so the arm never silently becomes a two-analyst run.
    """
    out = dict(channels)
    if victim in out and victim in donor:
        out[victim] = donor[victim]
    return out


# ---------------------------------------------------------------------------
# Scoring (pure — unit-tested without an LLM)
# ---------------------------------------------------------------------------


def extract_tids(text: str) -> list[str]:
    """Distinct ATT&CK ids cited in a model response, in order of appearance."""
    seen: list[str] = []
    for m in _TID_RE.finditer(text or ""):
        tid = m.group(0).upper()
        if tid not in seen:
            seen.append(tid)
    return seen


def prf(predicted: list[str], truth: list[str]) -> tuple[float, float, float]:
    """Precision, recall, F1 over technique-id sets.

    Empty prediction scores 0 precision rather than 1 — an arm that says nothing
    must not win the precision column, which is the degenerate strategy an
    equal-budget comparison would otherwise reward.
    """
    pset = {t.upper() for t in predicted if t.strip()}
    tset = {t.upper() for t in truth if t.strip()}
    if not tset:
        return (0.0, 0.0, 0.0)
    if not pset:
        return (0.0, 0.0, 0.0)
    hit = len(pset & tset)
    precision = hit / len(pset)
    recall = hit / len(tset)
    f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
    return (precision, recall, f1)


def invalid_id_rate(tids: list[str], is_valid: Any) -> float:
    """Fraction of cited ids that are not real ATT&CK techniques. 0.0 if none cited."""
    if not tids:
        return 0.0
    return sum(1 for t in tids if not is_valid(t)) / len(tids)


def per_call_budget(total_budget: int, n_calls: int) -> int:
    """Equal-budget split. At least 1 token, so a large K cannot silently zero an arm."""
    if n_calls <= 0:
        return max(1, total_budget)
    return max(1, total_budget // n_calls)


def mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def cluster_ci(
    values: list[float], clusters: list[Hashable], iters: int = 2000
) -> tuple[float, float]:
    """95% bootstrap CI for the mean, resampling **samples** rather than rows.

    The arms are 25 rows that are 5 samples repeated 5 times, so the row
    bootstrap this replaces estimated the uncertainty of the mean over *these
    five samples* rather than over the population they stand for. Measured
    afterwards: the intra-cluster correlation on the paired delta is 0.46, the
    design effect 2.8, and the published interval was 1.6 times too narrow.

    Kept as a named wrapper rather than inlined because three other harnesses
    import their estimator from this module and must keep getting the same one.
    """
    if len(values) < 2:
        return (0.0, 0.0)
    interval = stats.cluster_bootstrap_ci(values, clusters, iters=iters, seed=SEED)
    return (interval.lo, interval.hi)


def paired_delta(a: list[float], b: list[float]) -> list[float]:
    """Element-wise a-b over the common prefix. Arms are run on the same samples
    in the same order, so the paired comparison is the sensitive one."""
    return [x - y for x, y in zip(a, b, strict=False)]


@dataclass
class ArmScore:
    arm: str
    sample_id: str
    repeat: int
    precision: float
    recall: float
    f1: float
    invalid_id_rate: float
    n_predicted: int
    output_tokens: int
    calls: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score_from_dict(d: dict[str, Any]) -> ArmScore:
    return ArmScore(
        arm=str(d["arm"]),
        sample_id=str(d["sample_id"]),
        repeat=int(d["repeat"]),
        precision=float(d["precision"]),
        recall=float(d["recall"]),
        f1=float(d["f1"]),
        invalid_id_rate=float(d["invalid_id_rate"]),
        n_predicted=int(d["n_predicted"]),
        output_tokens=int(d["output_tokens"]),
        calls=int(d["calls"]),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def load_samples() -> list[tuple[str, list[str]]]:
    """(sample_id, ground-truth technique ids) for every fixture, sorted."""
    out: list[tuple[str, list[str]]] = []
    for path in sorted(_FIXTURE_DIR.glob("*.json")):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        tids = [str(t).upper() for t in (rec.get("technique_ids") or [])]
        if tids:
            out.append((str(rec.get("sample_id", path.stem)), tids))
    return out


# ---------------------------------------------------------------------------
# Arms (live LLM)
# ---------------------------------------------------------------------------


def bind_eval_llm(agent: Any, *, timeout_s: int = _CALL_TIMEOUT_S) -> None:
    """Configure an agent's LLM for evaluation. Applied identically to every arm.

    Two settings, and for the first one the *mechanism* is the whole point.

    **The timeout must be bound as a per-request kwarg, not assigned to
    ``request_timeout``.** ``ChatOpenAI`` builds its HTTP client at construction
    from ``request_timeout``, which this project's provider sets to **1800 s**
    (`llm/openai_provider.py`). Assigning the attribute afterwards does not
    rebuild that client, so the cap silently never applies. Learned the
    expensive way on 2026-08-09: a B1 call ran **14+ minutes with a "180 s" cap
    set** and never raised, because the real ceiling was still half an hour.
    ``bind(timeout=...)`` puts it in the request payload, which the OpenAI SDK
    honours per call — so a degenerate decode now surfaces as a skip.

    Second, ``enable_thinking=false``: otherwise this reasoning model spends the
    whole cap inside ``<think>``, which the server strips into
    ``reasoning_content``, leaving an empty answer (§3.6).

    **And ``extra_body`` is merged, not replaced — the third thing, learned on
    2026-08-15.** ``bind(extra_body=...)`` overrides the value the provider set at
    construction rather than adding to it. The provider puts everything a local
    llama.cpp server needs in there: the output cap under the key that server
    actually reads (``OUTPUT-CAP-01``), and the repetition penalty when one is
    configured. Passing a fresh dict here silently dropped all of it, so **every
    harness that calls this function was measuring a differently-configured
    system than production runs** — with the judge's 8,192-token ceiling removed,
    which is how a C3 call reached 30,155 generated tokens (§3.35) on a run whose
    whole purpose was to measure the capped condition.

    The failure was invisible because the two settings this function *does* apply
    were applied correctly. Nothing looked wrong; something else had gone missing.
    """
    try:
        # Resolve what the provider already put there. After a previous bind the
        # model is a RunnableBinding, so check its kwargs and its inner model
        # before falling back to nothing.
        existing: dict[str, Any] = {}
        for source in (
            getattr(agent.llm, "kwargs", {}) or {},
            {"extra_body": getattr(getattr(agent.llm, "bound", None), "extra_body", None)},
            {"extra_body": getattr(agent.llm, "extra_body", None)},
        ):
            candidate = source.get("extra_body")
            if isinstance(candidate, dict) and candidate:
                existing = dict(candidate)
                break

        chat_template_kwargs = dict(existing.get("chat_template_kwargs") or {})
        chat_template_kwargs["enable_thinking"] = False
        existing["chat_template_kwargs"] = chat_template_kwargs

        agent.llm = agent.llm.bind(timeout=timeout_s, extra_body=existing)
    except Exception as exc:  # noqa: BLE001 — a provider may reject either kwarg
        print(f"  WARNING: could not bind eval LLM settings ({exc}); running unbounded.")


def _estimate_output_tokens(text: str) -> int:
    """~4 chars/token, the same convention as ``token_ledger.estimate_tokens``."""
    return max(1, len(text) // 4) if text else 0


def run_single(agent: Any, channels: dict[str, str], budget: int) -> tuple[str, int, int]:
    """One full-budget call over all channels. Returns (text, tokens, calls)."""
    text = agent._invoke_view(SINGLE_PROMPT, render_all_channels(channels), budget)
    return text, _estimate_output_tokens(text), 1


def run_negotiated(agent: Any, channels: dict[str, str], budget: int) -> tuple[str, int, int]:
    """K channel analysts plus a mediator, all inside the same total budget."""
    present = [c for c in CHANNELS if c in channels]
    n_calls = len(present) + 1  # the mediator is paid for out of the same budget
    per_call = per_call_budget(budget, n_calls)

    transcripts: list[str] = []
    tokens = 0
    for channel in present:
        text = agent._invoke_view(channel_prompt(channel), channels[channel], per_call)
        tokens += _estimate_output_tokens(text)
        transcripts.append(f"[{channel} analyst]\n{text}")

    final = agent._invoke_view(MEDIATOR_PROMPT, "\n\n".join(transcripts), per_call)
    tokens += _estimate_output_tokens(final)
    return final, tokens, n_calls


def run_noise(
    agent: Any, channels: dict[str, str], donor: dict[str, str], victim: str, budget: int
) -> tuple[str, int, int]:
    """Negotiated, with one analyst fed another sample's evidence."""
    return run_negotiated(agent, swap_one_channel(channels, donor, victim), budget)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def arm_block(arm: str, scores: list[ArmScore]) -> list[str]:
    if not scores:
        return [f"## {arm}", "", "_no samples_", ""]

    # Five samples, five repeats each. The cluster is the sample.
    clusters: list[Hashable] = [s.sample_id for s in scores]

    def _row(label: str, xs: list[float], fmt: str = ".3f") -> str:
        lo, hi = cluster_ci(xs, clusters)
        return f"| {label} | {mean(xs):{fmt}} | [{lo:{fmt}}, {hi:{fmt}}] |"

    calls = scores[0].calls
    return [
        f"## {arm}  (n={len(scores)} rows over {len(set(clusters))} samples, calls/sample={calls})",
        "",
        "| metric | mean | 95% bootstrap CI |",
        "|---|---|---|",
        _row("precision", [s.precision for s in scores]),
        _row("recall", [s.recall for s in scores]),
        _row("F1", [s.f1 for s in scores]),
        _row("invalid technique-id rate", [s.invalid_id_rate for s in scores]),
        _row("techniques predicted", [float(s.n_predicted) for s in scores], ".2f"),
        _row("output tokens (est.)", [float(s.output_tokens) for s in scores], ".0f"),
        "",
    ]


def completeness_block(
    scores: list[ArmScore], arms: tuple[str, ...], expected_per_arm: int
) -> list[str]:
    """Per-arm generation loss, and whether it is differential.

    This is not bookkeeping. A per-call timeout hits a 4-call arm roughly four
    times as often as a 1-call arm, so `negotiated` and `noise` lose generations
    that `single` keeps — and the ones they lose are the *hard* samples, the
    degenerate decodes. Left unstated, that is survivorship bias flattering the
    multi-call arms in their marginal tables.

    Two things follow and both are said out loud. The **paired** comparisons are
    safe by construction, because they only pair generations present in both
    arms. The **marginal** tables are not: they are computed over different
    sample sets whenever loss is differential.

    The loss is also a *result*. An arm that needs four calls to produce one
    answer fails whenever any one of them does, which is a real operational
    property of the topology — the same channel §1.7.1 measured as completion
    under a time budget.
    """
    counts = {arm: sum(1 for s in scores if s.arm == arm) for arm in arms}
    lost = {arm: expected_per_arm - n for arm, n in counts.items()}
    lines = [
        "## Generation completeness",
        "",
        "| arm | completed | lost | calls/generation |",
        "|---|---|---|---|",
    ]
    for arm in arms:
        calls = next((s.calls for s in scores if s.arm == arm), 0)
        lines.append(f"| {arm} | {counts[arm]}/{expected_per_arm} | {lost[arm]} | {calls} |")
    lines.append("")
    if len(set(lost.values())) > 1:
        worst = max(lost, key=lambda a: lost[a])
        lines += [
            f"**Loss is differential — `{worst}` lost the most ({lost[worst]}).** A per-call",
            "timeout hits a multi-call arm proportionally more often, and the generations it",
            "removes are the degenerate ones. The **paired** comparisons below are unaffected",
            "(they pair only generations present in both arms); the **marginal** tables above",
            "are computed over different sample sets and should be read with that in mind.",
            "The loss itself is a property of the topology, not only of the harness.",
            "",
        ]
    else:
        lines += ["Loss is equal across arms; the marginal tables are directly comparable.", ""]
    return lines


def paired_block(scores: list[ArmScore], left: str, right: str) -> list[str]:
    """Paired F1 delta at the cluster level, with what the design could have seen.

    Every arm saw the same samples in the same order, so the paired comparison is
    the sensitive one — but the pairs are not independent: five samples, five
    repeats each. Three quantities are reported together because any one of them
    alone misleads:

    * the **cluster bootstrap interval**, which is the honest width;
    * the **exact sign-flip p**, because the bootstrap p returns ~0 whenever the
      five cluster means happen to share a sign, whatever the effect size;
    * the **minimum detectable effect**, because a null from a design that could
      only have seen effects above 0.22 F1 says nothing about smaller ones, and
      reading it as equivalence is the error this block exists to prevent.
    """
    by_key = {(s.arm, s.sample_id, s.repeat): s for s in scores}
    keys = sorted({(k[1], k[2]) for k in by_key if k[0] == left})
    matched = [(sid, r) for sid, r in keys if (right, sid, r) in by_key]
    if len(matched) < 2:
        return [f"### {left} - {right}", "", "_insufficient paired observations_", ""]
    deltas = paired_delta(
        [by_key[(left, sid, r)].f1 for sid, r in matched],
        [by_key[(right, sid, r)].f1 for sid, r in matched],
    )
    clusters: list[Hashable] = [sid for sid, _ in matched]
    res = stats.paired_cluster_result(deltas, clusters, seed=SEED)

    wins = sum(1 for d in deltas if d > 0)
    losses = sum(1 for d in deltas if d < 0)
    ties = len(deltas) - wins - losses
    iv = res.interval
    verdict = "CI excludes 0" if iv.excludes(0.0) else "**CI includes 0 — no separation**"
    detectable = (
        "the observed effect is above this design's resolution"
        if abs(res.delta) >= res.mde_t
        else "**the observed effect is below this design's resolution**"
    )
    return [
        f"### {left} - {right}  (paired, n={len(deltas)} rows over {res.structure.k} samples)",
        "",
        f"- mean F1 delta **{res.delta:+.3f}**, 95% cluster CI "
        f"[{iv.lo:+.3f}, {iv.hi:+.3f}] — {verdict}",
        f"- exact cluster sign-flip p = {res.p_exact:.4f} "
        f"(the smallest this design can reach is {res.p_floor:.4f})",
        f"- minimum detectable effect at 80% power: {res.mde_t:.3f} F1 — {detectable}",
        f"- ICC {res.structure.icc:.3f}, design effect {res.structure.design_effect:.2f}, "
        f"effective n {res.structure.effective_n:.1f}",
        f"- sign test: {left} wins {wins}, {right} wins {losses}, ties {ties}",
        "",
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main_async(repeats: int, budget: int, smoke: bool, checkpoint: Path) -> None:
    from maljan.memory.attck_validator import ATTCKValidator

    samples = load_samples()
    if not samples:
        print("No fixtures found — aborting.", flush=True)
        return

    # Build every sample's channels up front, and refuse to run on a leak.
    built = [(sid, tids, build_channels(tids)) for sid, tids in samples]
    for sid, tids, channels in built:
        leaks = leaked_ids(channels)
        if leaks:
            print(f"ABORT: sample {sid} leaks ground-truth ids into evidence: {leaks}", flush=True)
            return
        missing = [t for t in tids if t.upper() not in _ARTIFACTS]
        if missing:
            print(f"ABORT: sample {sid} has techniques with no artifact: {missing}", flush=True)
            return

    if smoke:
        built = built[:1]
        repeats = 1

    try:
        validator = ATTCKValidator.get_instance()
        is_valid = validator.validate_ttp_id
    except Exception as exc:  # noqa: BLE001
        print(f"ATT&CK validator unavailable ({exc}); invalid-id rate disabled.", flush=True)

        def is_valid(_tid: str) -> bool:
            return True

    arms = ("single", "negotiated", "noise")
    print(
        f"{len(built)} sample(s), arms={list(arms)}, repeats={repeats}, budget={budget}.",
        flush=True,
    )

    scores: list[ArmScore] = []
    done: set[str] = set()
    if checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                done.add(rec["key"])
                scores.append(score_from_dict(rec))
        print(f"Resume: {len(done)} generations in {checkpoint}.", flush=True)

    container = ServiceContainer(get_settings(), mock=False)
    agent = container.get_agent("static")
    bind_eval_llm(agent)

    def _record(
        arm: str, sid: str, r: int, text: str, truth: list[str], tokens: int, calls: int
    ) -> None:
        tids = extract_tids(text)
        p, rc, f1 = prf(tids, truth)
        sc = ArmScore(
            arm=arm,
            sample_id=sid,
            repeat=r,
            precision=p,
            recall=rc,
            f1=f1,
            invalid_id_rate=invalid_id_rate(tids, is_valid),
            n_predicted=len(tids),
            output_tokens=tokens,
            calls=calls,
        )
        scores.append(sc)
        with checkpoint.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"key": f"{arm}:{sid}:{r}", **sc.to_dict()}) + "\n")
        print(f"  {arm}:{sid}:{r} P={p:.2f} R={rc:.2f} F1={f1:.2f} tok~{tokens}", flush=True)

    for idx, (sid, truth, channels) in enumerate(built):
        # The noise arm's donor is the next sample, wrapping — deterministic, and
        # never the sample itself.
        donor = built[(idx + 1) % len(built)][2]
        for r in range(repeats):
            for arm in arms:
                if f"{arm}:{sid}:{r}" in done:
                    continue
                try:
                    if arm == "single":
                        text, tokens, calls = run_single(agent, channels, budget)
                    elif arm == "negotiated":
                        text, tokens, calls = run_negotiated(agent, channels, budget)
                    else:
                        text, tokens, calls = run_noise(agent, channels, donor, CHANNELS[0], budget)
                except Exception as exc:  # noqa: BLE001 — one bad decode must not kill the batch
                    print(f"  SKIP {arm}:{sid}:{r}: {type(exc).__name__}: {exc}", flush=True)
                    continue
                _record(arm, sid, r, text, truth, tokens, calls)

    lines = [
        "# E.2 — negotiated consensus vs single agent, equal token budget",
        "",
        f"- Total output budget B = {budget} per sample per arm; `negotiated`/`noise` split it",
        "  across K channel analysts **plus the mediator**, so the mediator is not free.",
        "- Evidence is split into heterogeneous channels (static / dynamic / network) and never",
        "  names a technique id — the metric is accuracy against the fixture ground truth.",
        "- `noise` is Bertalanič & Fortuna's stochastic control: one analyst gets another",
        "  sample's evidence. If `noise` scores like `negotiated`, the negotiation is",
        "  aggregating rather than reconciling.",
        "",
    ]
    lines += completeness_block(scores, arms, len(built) * repeats)
    for arm in arms:
        lines += arm_block(arm, [s for s in scores if s.arm == arm])
    lines += ["## Paired comparisons", ""]
    lines += paired_block(scores, "negotiated", "single")
    lines += paired_block(scores, "negotiated", "noise")

    report = "\n".join(lines)
    print("\n" + report, flush=True)
    try:
        _OUT_FILE.write_text(report + "\n", encoding="utf-8")
        _JSON_FILE.write_text(
            json.dumps([s.to_dict() for s in scores], indent=2) + "\n", encoding="utf-8"
        )
        print(f"\nWrote {_OUT_FILE} and {_JSON_FILE}", flush=True)
    except OSError as exc:
        print(f"Could not write report: {exc}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="E.2 consensus ablation at equal token budget.")
    ap.add_argument("--repeats", type=int, default=5, help="Generations per (sample, arm).")
    ap.add_argument("--budget", type=int, default=_DEFAULT_BUDGET, help="Total output budget B.")
    ap.add_argument("--smoke", action="store_true", help="One sample, one repeat.")
    ap.add_argument("--checkpoint", type=Path, default=_DEFAULT_CHECKPOINT)
    args = ap.parse_args()
    main_async(args.repeats, args.budget, args.smoke, args.checkpoint)


if __name__ == "__main__":
    main()
