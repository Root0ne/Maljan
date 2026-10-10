"""The written checklist a rehearsal run is held to, and the comparison of repeated runs.

A run is described by one plain record (:class:`RunRecord`), built the same
way from the running stack (``scripts/rehearsal/run.py``) or from an in-process
pipeline (``scripts/rehearsal/inprocess.py``), so both are judged by the same
checks. Every check fails closed: what it cannot confirm is a failure, never a
pass.

* the job completed (``deadline_hit``: it ended at its deadline as a failed
  job with the reason said);
* the model refused no request — a 400 here is a 400 the paid API would send;
* every model call was one the stub recognised: none answered as ``other``,
  every composer request naming its section;
* the product's own connection test passed against the stub;
* every stage of the profile in force started, ran and finished, none failed;
* every analyst the profile names answered with at least one claim in force;
* each of the composer's sixteen sections is written, or marked not written
  by a degradation reason, or excused by the product itself (its own bundling
  finds the section's evidence empty) or by the script (a section the stub
  leaves empty on purpose because the sample holds nothing for it);
* the narrative came from a model answer;
* the run summary's token totals are the provider-reported usage call for
  call, no call is unreported, and its spend equals that usage priced from
  the vendored table; every answered call, and every broken stream whose
  prompt usage was reported, has one per-call usage record whose charge is
  that usage priced, a broken stream's estimated output the only part that
  may differ, and the job's usage totals (stack runs) are those records;
* the window the product sized each model with (the run summary's
  analysts' window and each output cap's derivation) is the window the stub
  serves it, never a fallback;
* the STIX bundles and the markdown are rendered;
* no claim is lost: every claim the stub's analysts wrote is in an answer in
  force or recorded as dropped, and every claim in force is discussed in the
  report's body (by its label or its words), not only listed as undiscussed;
* the settings in force are the ones configured (refused when nothing is
  configured to compare);
* the judge stated the verdict;
* the run finished inside its deadline by a margin;
* the scenario's fault really happened, so a fault run cannot pass vacuously.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# Every section the composer writes, in its order, and where the stored report holds it.
SECTION_PLACES: dict[str, tuple[str, ...]] = {
    "introduction": ("intro_background",),
    "execution_flow": ("technical_analysis", "execution_flow"),
    "packing_obfuscation": ("technical_analysis", "packing_obfuscation"),
    "string_resolution": ("technical_analysis", "string_resolution"),
    "discovery": ("technical_analysis", "discovery"),
    "persistence_detail": ("technical_analysis", "persistence_detail"),
    "evasion_antiforensics": ("technical_analysis", "evasion_antiforensics"),
    "command_and_control": ("technical_analysis", "command_and_control"),
    "payloads": ("technical_analysis", "payloads"),
    "configuration": ("technical_analysis", "configuration"),
    "host_identifiers": ("technical_analysis", "host_identifiers"),
    "commands": ("technical_analysis", "commands"),
    "encryption_scheme": ("technical_analysis", "encryption_scheme"),
    "cli_flags": ("technical_analysis", "cli_flags"),
    "ransom_note": ("technical_analysis", "ransom_note"),
    "communications": ("c2_channels",),
}
COMPOSED: tuple[str, ...] = tuple(SECTION_PLACES)

# What the rehearsal sample's report holds, measured on the default profile:
# the sections it writes with content, the two the stub leaves empty because
# the sample holds nothing for them, and the four whose evidence the product's
# own bundling finds empty. A section may be excused only from its own list,
# and in a run with no fault every section of the first list is written.
WRITTEN_SECTIONS = frozenset(
    {
        "introduction",
        "execution_flow",
        "string_resolution",
        "command_and_control",
        "payloads",
        "configuration",
        "host_identifiers",
        "commands",
        "cli_flags",
        "communications",
    }
)
EMPTY_ON_PURPOSE = frozenset({"encryption_scheme", "ransom_note"})
EVIDENCE_EMPTY = frozenset(
    {"packing_obfuscation", "discovery", "persistence_detail", "evasion_antiforensics"}
)
# The scenarios with no fault in the model's answers: every section of
# ``WRITTEN_SECTIONS`` is written in them, never marked.
CLEAN_SCENARIOS = frozenset(
    {"normal", "cross_loop", "long_loop", "slow_model", "redacted_thinking"}
)
# The sections a fault scenario's fault can keep from being written, which
# may then be marked not written. Every other section of ``WRITTEN_SECTIONS``
# is written in the scenario too: a fault on a section's first call is asked
# again, and a fault on another role's call never reaches it. An answer cut
# at its cap with only thinking is not asked again in the same form, so the
# cut reaches every section the composer is asked for. Measured on both wires.
FAULT_REACHES: dict[str, frozenset[str]] = {
    "cut_at_cap": WRITTEN_SECTIONS | EMPTY_ON_PURPOSE,
}

# The stub's roles, by the agent whose model, effort and budget they spend.
ROLE_GROUPS: dict[str, set[str]] = {
    "static": {"analyst", "revision"},
    "analyst": {"analyst", "revision"},
    "judge": {"judge", "technique_question"},
    "mediator": {"mediator", "mediator_extract"},
    "reporter": {"narrative", "composer"},
}

# The report fields the report models write: the body a claim is discussed in.
BODY_FIELDS = (
    "executive_summary",
    "key_findings",
    "capabilities_narrative",
    "defensive_recommendations",
    "intro_background",
    "technical_analysis",
    "c2_channels",
)

# The share of a run's deadline it must finish inside.
DEADLINE_MARGIN_SHARE = 0.2
# The fault whose streamed answer breaks off before it ends. No answer
# reached the client, so it is no call; on the Anthropic wire its
# ``message_start`` had already reported the prompt's usage, and the provider
# bills that prompt: the product charges it as a failed attempt, the output
# it never received estimated.
_BROKEN = "stream_error"
# The relative difference a recorded charge may have from the stub's usage
# priced here: rounding of the same table's prices, nothing more.
_PRICE_TOLERANCE = 0.005


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class RunRecord:
    """Everything a run's checks read."""

    scenario: str
    job_status: str
    api: str = ""
    job_error: str = ""
    verdict: str = ""
    run_summary: dict[str, Any] = field(default_factory=dict)
    malware_report: dict[str, Any] = field(default_factory=dict)
    markdown: str = ""
    stix_bundle: dict[str, Any] = field(default_factory=dict)
    stix_extended: dict[str, Any] = field(default_factory=dict)
    claims_in_force: dict[str, list[str]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    stub_log: list[dict[str, Any]] = field(default_factory=list)
    expected: dict[str, Any] = field(default_factory=dict)
    scenario_params: dict[str, Any] = field(default_factory=dict)
    # The profile's stages, each with the agents it names; empty reads the run summary's.
    required_stages: dict[str, list[str]] = field(default_factory=dict)
    # The sections the product's own bundling finds empty; ``None`` when not known.
    empty_evidence_sections: list[str] | None = None
    # The connection test's outcome, where the run asked one.
    probe: dict[str, Any] = field(default_factory=dict)
    # What a stack rehearsal changed on the stack: each setting before and
    # during it, and the tool servers it took away or withheld keys from.
    gate: dict[str, Any] = field(default_factory=dict)
    # The stored report's own note that it was kept from a run that did not
    # finish; empty on a completed run's report and where no report was stored.
    incomplete_reason: str = ""
    # The job's usage totals as ``GET /jobs/{id}/usage`` answered them (stack
    # runs); empty where the run was not read from the API.
    usage_totals: dict[str, Any] = field(default_factory=dict)
    elapsed_s: float = 0.0


def _get(holder: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(holder, dict):
            return None
        holder = holder.get(key)
    return holder


def _has_content(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            _has_content(v)
            for k, v in value.items()
            if k not in ("evidence_refs", "evidence_ref", "title")
        )
    if isinstance(value, list):
        return any(_has_content(v) for v in value)
    return value not in (None, "", False)


def _degradations(record: RunRecord) -> list[str]:
    reasons = list(record.run_summary.get("degradation_reasons") or [])
    reasons += list(record.malware_report.get("degradation_reasons") or [])
    return [str(r) for r in reasons]


def _answered(record: RunRecord) -> list[dict[str, Any]]:
    return [e for e in record.stub_log if e.get("status") == 200]


def section_statuses(record: RunRecord) -> dict[str, str]:
    """Each composer section's status; any status starting ``LOST`` fails the run."""
    reasons = _degradations(record)
    asked: dict[str, list[dict[str, Any]]] = {}
    for entry in record.stub_log:
        if entry.get("role") == "composer" and entry.get("section"):
            asked.setdefault(str(entry["section"]), []).append(entry)
    empty = set(record.empty_evidence_sections or [])
    statuses: dict[str, str] = {}
    for section, place in SECTION_PLACES.items():
        mine = asked.get(section, [])
        if _has_content(_get(record.malware_report, place)):
            statuses[section] = "written"
        elif any(f"'{section}'" in r or f"{section} section" in r for r in reasons):
            statuses[section] = "marked not written"
        elif not mine and section in empty and section in EVIDENCE_EMPTY:
            statuses[section] = "not asked: the product finds its evidence empty"
        elif not mine and section in empty:
            statuses[section] = "LOST: excused as evidence-empty, but the sample's report has some"
        elif (
            mine
            and mine[-1].get("status") == 200
            and mine[-1].get("deliberately_empty")
            and section in EMPTY_ON_PURPOSE
        ):
            statuses[section] = "answered empty on purpose: the sample holds nothing for it"
        elif mine and mine[-1].get("deliberately_empty"):
            statuses[section] = "LOST: left empty, but the sample holds a value for it"
        elif not mine:
            statuses[section] = "LOST: never asked, and nothing says why"
        else:
            statuses[section] = "LOST: asked and answered, missing from the report unmarked"
    return statuses


# ----------------------------------------------------------------------- checks


# The worker's own job timeout, named in the reason a job it stopped carries.
JOB_TIMEOUT_SETTING = "core.job_timeout"


def stopped_by_the_worker(record: RunRecord) -> bool:
    """Whether the run's deadline is the worker's job timeout rather than the runner's own."""
    return record.scenario_params.get("deadline_by") == JOB_TIMEOUT_SETTING


def _check_job(record: RunRecord) -> Check:
    if record.scenario == "deadline_hit" and stopped_by_the_worker(record):
        ok = record.job_status in ("failed", "stopped") and (
            JOB_TIMEOUT_SETTING in record.job_error
        )
        return Check(
            f"job stopped by {JOB_TIMEOUT_SETTING} as a failed job",
            ok,
            f"job status {record.job_status}: {record.job_error or 'no reason given'}",
        )
    if record.scenario == "deadline_hit":
        said = record.job_error.lower()
        ok = record.job_status == "failed" and (
            "deadline" in said or "timeout" in said or "timed out" in said
        )
        return Check(
            "job ended at its deadline as a failed job",
            ok,
            f"job status {record.job_status}: {record.job_error or 'no reason given'}",
        )
    ok = record.job_status == "completed"
    detail = f"job status {record.job_status}"
    if record.job_error:
        detail += f": {record.job_error}"
    return Check("job completed", ok, detail)


def _check_refusals(record: RunRecord) -> Check:
    refused = [e for e in record.stub_log if e.get("refused")]
    if not record.stub_log:
        return Check("the model refused no request", False, "no model call was logged")
    if refused:
        rows = "; ".join(
            f"call {e.get('n')} ({e.get('role')}): {e['refused']}" for e in refused[:5]
        )
        return Check("the model refused no request", False, f"{len(refused)} refused: {rows}")
    return Check("the model refused no request", True, f"{len(record.stub_log)} calls taken")


def _check_recognised(record: RunRecord) -> Check:
    other = [e for e in record.stub_log if e.get("role") == "other"]
    unnamed = [e for e in record.stub_log if e.get("role") == "composer" and not e.get("section")]
    problems = []
    if other:
        problems.append(
            f"{len(other)} call(s) no role script recognised (calls {[e['n'] for e in other][:8]})"
        )
    if unnamed:
        problems.append(f"{len(unnamed)} composer call(s) naming no section")
    roles = Counter(str(e.get("role")) for e in record.stub_log)
    detail = "; ".join(problems) or ", ".join(f"{n} {r}" for r, n in sorted(roles.items()))
    return Check("every model call recognised", not problems, detail)


def _check_probe(record: RunRecord) -> Check:
    if not record.probe:
        return Check("the connection test passed", False, "no connection test was run")
    ok = bool(record.probe.get("ok"))
    return Check("the connection test passed", ok, str(record.probe.get("detail") or "")[:300])


def _required(record: RunRecord) -> dict[str, list[str]]:
    """The profile's stages as the settings in force name them; never read off the run itself."""
    return record.required_stages


def _check_stages(record: RunRecord) -> Check:
    required = _required(record)
    stages = {str(s.get("key")): s for s in record.run_summary.get("stages") or []}
    started = [e.get("stage") for e in record.events if e.get("type") == "stage_started"]
    finished = [e.get("stage") for e in record.events if e.get("type") == "stage_finished"]
    problems = []
    if not required:
        problems.append("the profile's stages are not known from the settings in force")
    for key in required:
        row = stages.get(key)
        if row is None:
            problems.append(f"{key}: not in the run summary")
        elif not row.get("ran"):
            problems.append(f"{key}: skipped ({row.get('reason') or 'no reason'})")
        elif row.get("failure"):
            problems.append(f"{key}: failed")
        elif key not in started or key not in finished:
            problems.append(f"{key}: no stage_started/stage_finished pair")
    detail = "; ".join(problems) or f"{len(required)} stages ran: {', '.join(required)}"
    return Check("every stage of the profile ran", not problems, detail)


def _check_analysts(record: RunRecord) -> Check:
    required = _required(record)
    stages = {str(s.get("key")): s for s in record.run_summary.get("stages") or []}
    analysts = [
        agent
        for key, agents in required.items()
        if (stages.get(key) or {}).get("kind", "analysis") == "analysis" and key not in ("debate",)
        for agent in agents
        if agent not in ("judge", "reporter")
    ]
    failed = {str(a) for a in record.run_summary.get("failed_analysts") or []}
    problems = []
    if not analysts:
        problems.append("the profile names no analyst")
    for agent in analysts:
        if agent in failed:
            problems.append(f"{agent}: failed")
        elif agent not in record.claims_in_force:
            problems.append(f"{agent}: never answered")
        elif not record.claims_in_force[agent]:
            problems.append(f"{agent}: answered with no claim")
    detail = "; ".join(problems) or ", ".join(
        f"{a} ({len(record.claims_in_force[a])} claims)" for a in analysts
    )
    return Check("every analyst answered", not problems, detail)


def _check_sections(record: RunRecord) -> Check:
    statuses = section_statuses(record)
    lost = [f"{s} ({status})" for s, status in statuses.items() if status.startswith("LOST")]
    if record.scenario in CLEAN_SCENARIOS:
        lost += [
            f"{s} (not written in a run with no fault: {statuses[s]})"
            for s in sorted(WRITTEN_SECTIONS)
            if statuses[s] != "written"
        ]
    else:
        # A section lost is already named; one marked must be one the fault reaches.
        reaches = FAULT_REACHES.get(record.scenario, frozenset())
        lost += [
            f"{s} ({status}, which the {record.scenario} fault cannot cause)"
            for s, status in statuses.items()
            if not status.startswith("LOST")
            and s not in reaches
            and (s in WRITTEN_SECTIONS and status != "written" or status == "marked not written")
        ]
    counts = Counter(status.split(":")[0] for status in statuses.values())
    detail = ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))
    if lost:
        detail = f"{'; '.join(lost)} — {detail}"
    return Check("every report section written or accounted for", not lost, detail)


def _check_narrative(record: RunRecord) -> Check:
    summary = str(record.malware_report.get("executive_summary") or "").strip()
    calls = [e for e in record.stub_log if e.get("role") == "narrative"]
    marked = [r for r in _degradations(record) if "narrative" in r.lower()]
    problems = []
    if not summary:
        problems.append("no executive summary")
    if marked:
        problems.append(f"degraded: {marked[0]}")
    if not calls:
        problems.append("the narrative model was never asked")
    else:
        last = calls[-1]
        if last.get("status") != 200 or not (last.get("text_chars") or last.get("tool_calls")):
            problems.append("the narrative model's last answer was not a written answer")
    detail = "; ".join(problems) or f"written by the model, {len(summary)} characters"
    return Check("narrative written by the model", not problems, detail)


def _price_rows() -> dict[str, Any]:
    from maljan.core.spend import table_prices

    return table_prices()


def _billed(record: RunRecord) -> list[dict[str, Any]]:
    """The calls the model answered whole: each one a call the run must count and charge."""
    return [e for e in _answered(record) if e.get("fault") != _BROKEN]


def _broken_and_reported(record: RunRecord) -> list[dict[str, Any]]:
    """The broken streams whose prompt usage the stub reported before the break."""
    return [
        e
        for e in _answered(record)
        if e.get("fault") == _BROKEN and e.get("api") == "anthropic" and e.get("stream")
    ]


def _stub_cost(
    entry: dict[str, Any],
    rows: dict[str, Any],
    *,
    prompt_only: bool = False,
    output: int | None = None,
) -> float:
    """What one stub call's reported usage costs at the vendored prices; ``-1`` when unpriced.

    ``output`` prices that many output tokens in place of the reported ones.
    """
    price = rows.get(str(entry.get("model") or "").lower())
    if price is None:
        return -1.0
    when = datetime.fromtimestamp(float(entry.get("at") or 0), tz=UTC)
    usage = {
        "input_tokens": int(entry.get("input_tokens") or 0),
        "cached_input_tokens": int(entry.get("cache_read_tokens") or 0),
        "cache_write_input_tokens": int(entry.get("cache_write_5m_tokens") or 0)
        + int(entry.get("cache_write_1h_tokens") or 0),
        "cache_write_1h_input_tokens": int(entry.get("cache_write_1h_tokens") or 0),
        "output_tokens": 0
        if prompt_only
        else int(entry.get("output_tokens") or 0)
        if output is None
        else int(output),
    }
    return float(price.at(when).cost(usage))


def priced_usage(record: RunRecord) -> tuple[float, list[str]]:
    """What the stub's reported usage costs at the vendored prices, and the models unpriced.

    Every call answered whole, at its whole usage, and every broken stream
    that reported its prompt's usage, at that prompt alone: the output part
    of a broken stream is the product's estimate and is added from its record.
    """
    rows = _price_rows()
    total = 0.0
    unpriced: list[str] = []
    for entry, prompt_only in [(e, False) for e in _billed(record)] + [
        (e, True) for e in _broken_and_reported(record)
    ]:
        cost = _stub_cost(entry, rows, prompt_only=prompt_only)
        if cost < 0:
            model = str(entry.get("model") or "").lower()
            if model not in unpriced:
                unpriced.append(model)
            continue
        total += cost
    return total, unpriced


def usage_records(record: RunRecord) -> list[dict[str, Any]]:
    """The run's per-call usage records (``model_usage`` events), retries decided left out."""
    from maljan.core.token_ledger import RETRY_RECORD

    out = []
    for event in record.events:
        if str(event.get("type")) != "model_usage":
            continue
        data = event.get("data")
        row = dict(data) if isinstance(data, dict) else dict(event)
        if str(row.get("call") or "") != RETRY_RECORD:
            out.append(row)
    return out


def _figure(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _close(a: float, b: float) -> bool:
    return abs(a - b) <= 1e-9 + _PRICE_TOLERANCE * max(abs(a), abs(b))


def _take(rows: list[dict[str, Any]], key: tuple[int, ...], key_of: Any) -> dict[str, Any] | None:
    for index, row in enumerate(rows):
        if key_of(row) == key:
            return rows.pop(index)
    return None


def _record_problems(record: RunRecord) -> tuple[list[str], float]:
    """Each per-call record held to the stub call it records; and the estimated part summed.

    One record for every call answered whole, carrying that call's usage and
    a charge equal to it priced from the vendored table; one failed-attempt
    record for every broken stream whose prompt usage was reported, carrying
    that prompt's usage and a charge whose part beyond the prompt priced is
    its stated output estimate (``estimated_part`` ``output``) and nothing
    else. No other record, and no record without a charge.
    """
    from maljan.core.spend import ESTIMATED_OUTPUT
    from maljan.llm.transient import FAILED_ATTEMPT_CALL

    rows = _price_rows()
    problems: list[str] = []
    estimated = 0.0
    records = usage_records(record)
    calls = [r for r in records if str(r.get("call") or "") != FAILED_ATTEMPT_CALL]
    failed = [r for r in records if str(r.get("call") or "") == FAILED_ATTEMPT_CALL]
    billed = _billed(record)
    broken = _broken_and_reported(record)
    if len(calls) != len(billed):
        problems.append(
            f"{len(calls)} per-call usage record(s), the model answered {len(billed)} call(s)"
        )
    if len(failed) != len(broken):
        problems.append(
            f"{len(failed)} failed-attempt record(s), {len(broken)} broken stream(s) "
            "reported their prompt's usage"
        )

    def record_key(row: dict[str, Any]) -> tuple[int, ...]:
        return (
            int(row.get("input_tokens") or 0),
            int(row.get("output_tokens") or 0),
            int(row.get("cached_input_tokens") or 0),
        )

    def prompt_key(row: dict[str, Any]) -> tuple[int, ...]:
        return (int(row.get("input_tokens") or 0), int(row.get("cached_input_tokens") or 0))

    unmatched = list(calls)
    for entry in billed:
        key = (
            int(entry.get("input_tokens") or 0),
            int(entry.get("output_tokens") or 0),
            int(entry.get("cache_read_tokens") or 0),
        )
        row = _take(unmatched, key, record_key)
        label = f"call {entry.get('n', '?')} ({entry.get('role', '')})"
        if row is None:
            problems.append(f"{label}: no usage record carries its reported usage {key}")
            continue
        charged = _figure(row.get("priced_usd"))
        cost = _stub_cost(entry, rows)
        if charged is None:
            problems.append(f"{label}: its usage record carries no charge")
        elif cost >= 0 and not _close(charged, cost):
            problems.append(
                f"{label}: charged {charged:.8f} USD, its reported usage priced {cost:.8f} USD"
            )
        if row.get("estimated_part") or _figure(row.get("estimated_usd")):
            problems.append(f"{label}: charged by estimate though its usage was reported")
    unmatched_failed = list(failed)
    for entry in broken:
        prompt_of = (int(entry.get("input_tokens") or 0), int(entry.get("cache_read_tokens") or 0))
        row = _take(unmatched_failed, prompt_of, prompt_key)
        label = f"broken call {entry.get('n', '?')} ({entry.get('role', '')})"
        if row is None:
            problems.append(
                f"{label}: no failed-attempt record carries its reported prompt {prompt_of}"
            )
            continue
        charged = _figure(row.get("priced_usd"))
        by_estimate = _figure(row.get("estimated_usd"))
        prompt = _stub_cost(entry, rows, prompt_only=True)
        if charged is None or by_estimate is None:
            problems.append(f"{label}: its record carries no charge or no estimated part")
            continue
        if str(row.get("estimated_part") or "") != ESTIMATED_OUTPUT:
            problems.append(
                f"{label}: estimated part {row.get('estimated_part')!r}, "
                f"only {ESTIMATED_OUTPUT!r} may be estimated"
            )
        # The most an output can cost: the request's own cap, at the output rate
        # of the prompt's tier.
        cap = int(entry.get("max_tokens") or 0)
        whole = _stub_cost(entry, rows, output=cap) if cap > 0 else -1.0
        ceiling = whole - prompt if whole >= 0 and prompt >= 0 else None
        if by_estimate < 0 or by_estimate > charged:
            problems.append(f"{label}: estimated {by_estimate:.8f} of {charged:.8f} USD")
        elif ceiling is None:
            problems.append(f"{label}: no output cap to bound its estimated output by")
        elif by_estimate > ceiling and not _close(by_estimate, ceiling):
            problems.append(
                f"{label}: estimated output {by_estimate:.8f} USD, more than its cap of {cap} "
                f"tokens costs ({ceiling:.8f} USD)"
            )
        elif prompt >= 0 and not _close(charged - by_estimate, prompt):
            problems.append(
                f"{label}: charged {charged - by_estimate:.8f} USD beyond its estimate, "
                f"its reported prompt priced {prompt:.8f} USD"
            )
        estimated += by_estimate
    for row in unmatched + unmatched_failed:
        problems.append(
            f"a usage record no answered or charged call accounts for: {row.get('call')!r} "
            f"by {row.get('agent')!r}, {record_key(row)}"
        )
    return problems, estimated


def _check_tokens(record: RunRecord) -> Check:
    summary = record.run_summary
    tokens = summary.get("tokens") or {}
    if not summary or not tokens:
        return Check("tokens and spend as the provider reported them", False, "no token totals")
    calls = int(tokens.get("llm_calls") or 0)
    unreported = int(tokens.get("unreported_calls") or 0)
    sent = int(tokens.get("input_tokens") or 0)
    got = int(tokens.get("output_tokens") or 0)
    billed = _billed(record)
    problems = []
    if unreported:
        problems.append(f"{unreported} call(s) unreported")
    if calls != len(billed):
        problems.append(f"{calls} calls counted, the model answered {len(billed)}")
    stub_in = sum(int(e.get("input_tokens") or 0) for e in billed)
    stub_out = sum(int(e.get("output_tokens") or 0) for e in billed)
    if (sent, got) != (stub_in, stub_out):
        problems.append(
            f"totals {sent} in / {got} out, the provider reported {stub_in} in / {stub_out} out"
        )
    usd, unpriced = priced_usage(record)
    if unpriced:
        problems.append(f"no vendored price for {', '.join(unpriced)}")
    per_call, estimated = _record_problems(record)
    problems += per_call
    owed = usd + estimated
    recorded = sum(_figure(r.get("priced_usd")) or 0.0 for r in usage_records(record))
    spend = summary.get("spend")
    spent_said = ""
    if isinstance(spend, dict) and spend.get("spent_usd") is not None:
        spent = float(spend.get("spent_usd") or 0.0)
        if abs(spent - owed) > 1e-6 + _PRICE_TOLERANCE * max(owed, spent):
            problems.append(f"spend {spent:.6f} USD, the usage priced comes to {owed:.6f} USD")
        if abs(spent - recorded) > 1e-6 + _PRICE_TOLERANCE * max(recorded, spent):
            problems.append(
                f"spend {spent:.6f} USD, the per-call records charged {recorded:.6f} USD"
            )
        said_estimate = float(spend.get("estimated_usd") or 0.0)
        if abs(said_estimate - estimated) > 1e-6:
            problems.append(
                f"spend estimated {said_estimate:.6f} USD, the records' output estimates "
                f"come to {estimated:.6f} USD"
            )
        spent_said = f", spend {spent:.6f} USD"
        if estimated:
            spent_said += f" of which {estimated:.6f} USD is the estimated output of broken streams"
    else:
        problems.append("the run summary carries no spend to compare with the usage priced")
    problems += _totals_problems(record, recorded)
    detail = "; ".join(problems) or (
        f"{calls} calls, {sent} input and {got} output tokens, {owed:.6f} USD priced{spent_said}"
    )
    return Check("tokens and spend as the provider reported them", not problems, detail)


def _totals_problems(record: RunRecord, recorded: float) -> list[str]:
    """``GET /jobs/{id}/usage``, where the run was read from the API, held to the records."""
    totals = record.usage_totals
    if not totals:
        return []
    if totals.get("error"):
        return [f"the job's usage totals could not be read: {totals['error']}"]
    problems = []
    held = totals.get("spend")
    spend: dict[str, Any] = held if isinstance(held, dict) else {}
    said = _figure(spend.get("spent_usd"))
    if said is None or abs(said - recorded) > 1e-6 + _PRICE_TOLERANCE * max(said, recorded):
        problems.append(f"the job's usage totals say {said} USD, the records {recorded:.6f} USD")
    if int(spend.get("repriced_calls") or 0):
        problems.append(f"the job's usage totals repriced {spend['repriced_calls']} call(s)")
    if int(totals.get("calls") or 0) != len(_billed(record)):
        problems.append(
            f"the job's usage totals count {totals.get('calls')} call(s), "
            f"the model answered {len(_billed(record))}"
        )
    return problems


# The model group whose model each agent of the run summary's output caps runs on.
_AGENT_GROUP = {
    "static": "static",
    "dynamic": "static",
    "network": "static",
    "judge": "judge",
    "mediator": "mediator",
    "reporter": "reporter",
}
# The run summary's word for a window nothing reported (``context_window.FALLBACK``).
_FALLBACK_SOURCE = "fallback"
_WINDOW_SAID = re.compile(r"(\d+)-token context window \((\w+)\)")
_NO_WINDOW_SAID = "no window was learned"
# Every way the product states where a cap came from (``context_window.derived_reply``
# and the reporter's budget): a window, no window, an operator's number, a
# declared maximum, the hosted fallback. A derivation saying none of them is
# not read as a pass.
_CAP_SAID = (
    "-token context window (",
    _NO_WINDOW_SAID,
    " is set to ",
    "declared maximum output of ",
    "the documented fallback of ",
)
# The operator's own tool-answer cap, under which the product consults no window.
_OWN_TOOL_CAP = "settings.preprocessing.max_tool_output_chars"


def _check_window(record: RunRecord) -> Check:
    """The window the product sized each model with is the window the stub serves it.

    Read from the run summary: the analysts' window (``truncation.context_window``,
    its tokens and where they were learned) and each agent's output cap
    derivation. A window the product fell back to, or one other than the
    stub's documented or named window, sizes the paid run's prompts and caps
    for a model that does not exist.
    """
    name = "window in force as the provider serves it"
    served = {
        str(k).lower(): int(v)
        for k, v in (record.scenario_params.get("served_windows") or {}).items()
    }
    if not served:
        return Check(name, False, "the windows the stub served were not recorded")
    problems: list[str] = []

    def model_of(group: str) -> str:
        configured = str(record.expected.get(f"model.{group}") or "").lower()
        if configured in served:
            return configured
        # Nothing configured to compare: the model the group's calls carried.
        carried = Counter(
            str(e.get("model") or "").lower()
            for e in record.stub_log
            if e.get("role") in ROLE_GROUPS.get(group, set())
        )
        return carried.most_common(1)[0][0] if carried else ""

    analyst = model_of("static")
    truncation = record.run_summary.get("truncation") or {}
    window = truncation.get("context_window") if isinstance(truncation, dict) else None
    said = ""
    if not isinstance(window, dict) or not window:
        if not record.expected.get(_OWN_TOOL_CAP):
            problems.append("the run summary records no window the analysts were sized with")
    else:
        tokens = int(window.get("tokens") or 0)
        source = str(window.get("source") or "")
        wanted = served.get(analyst)
        said = f"{analyst} sized at {tokens} tokens ({source})"
        if source == _FALLBACK_SOURCE:
            problems.append(
                f"the analysts' window is the {tokens}-token fallback "
                f"({window.get('detail') or 'nothing reported one'}); the stub serves "
                f"{analyst or 'their model'} {wanted if wanted else 'an unrecorded window'}"
            )
        elif wanted is None:
            problems.append(f"no window was recorded as served to {analyst or 'the analysts'}")
        elif tokens != wanted:
            problems.append(
                f"the analysts' window is {tokens} tokens ({source}); the stub serves "
                f"{analyst} {wanted}"
            )
    generation = record.run_summary.get("generation")
    caps = generation.get("output_caps") if isinstance(generation, dict) else None
    unlearned: list[str] = []
    if not isinstance(caps, dict) or not caps:
        problems.append("the run summary records no output caps")
        caps = {}
    for agent in sorted(caps, key=str):
        entry = caps[agent]
        # The cap itself is the structured field; only the window it was
        # derived from is read from the sentence, which names it in no field.
        cap = entry.get("tokens") if isinstance(entry, dict) else None
        derivation = entry.get("derivation") if isinstance(entry, dict) else None
        if not isinstance(cap, int) or isinstance(cap, bool) or not isinstance(derivation, str):
            problems.append(f"{agent}'s output cap cannot be read: {entry!r}")
            continue
        group = _AGENT_GROUP.get(str(agent))
        if group is None and record.expected.get(f"model.{agent}"):
            group = str(agent)
        if group is None:
            problems.append(
                f"{agent} is an agent the window check does not know (its cap: {derivation!r})"
            )
            continue
        capped = model_of(group)
        if capped not in served:
            problems.append(
                f"no window was recorded as served to {capped or 'the model'} of {agent} "
                f"(its cap: {derivation!r})"
            )
            continue
        if cap >= served[capped]:
            # The cap the model was built with must leave the prompt room in
            # the window the provider serves it.
            problems.append(
                f"{agent}'s output cap of {cap} tokens does not fit inside the "
                f"{served[capped]}-token window the stub serves {capped}"
            )
        # The sentence must state the cap the field holds ("derived: 8192 tokens — …").
        if not re.search(rf"(?<!\d){cap} tokens\b", derivation) or not any(
            said in derivation for said in _CAP_SAID
        ):
            problems.append(f"{agent}'s output cap derivation cannot be read: {derivation!r}")
            continue
        if _NO_WINDOW_SAID in derivation:
            unlearned.append(str(agent))
            continue
        found = _WINDOW_SAID.search(derivation)
        if not found:
            continue
        tokens, source = int(found.group(1)), found.group(2)
        if source == _FALLBACK_SOURCE:
            unlearned.append(str(agent))
        elif tokens != served[capped]:
            problems.append(
                f"{agent}'s output cap was derived from a {tokens}-token window ({source}); "
                f"the stub serves {capped} {served[capped]}"
            )
    if unlearned:
        problems.append(f"output caps derived from no window: {', '.join(unlearned)}")
    detail = "; ".join(problems) or (
        f"{said or 'the operator set the tool-answer cap'}; every output cap from the served "
        "window or a declared maximum"
    )
    return Check(name, not problems, detail)


def _check_rendered(record: RunRecord) -> Check:
    problems = []
    for name, bundle in (("judge", record.stix_bundle), ("extended", record.stix_extended)):
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            problems.append(f"the {name} STIX bundle is missing")
        elif not bundle.get("objects"):
            problems.append(f"the {name} STIX bundle holds no object")
    markdown = record.markdown or ""
    if not markdown.strip():
        problems.append("no markdown")
    elif record.verdict and record.verdict not in markdown:
        problems.append(f"the markdown does not state the verdict {record.verdict}")
    detail = "; ".join(problems) or (
        f"judge bundle {len(record.stix_bundle.get('objects') or [])} objects, extended "
        f"{len(record.stix_extended.get('objects') or [])}, markdown {len(markdown)} characters"
    )
    return Check("STIX and markdown rendered", not problems, detail)


def _normal(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().rstrip(".").lower()


def _body_text(record: RunRecord) -> str:
    return _normal(
        json.dumps(
            {k: record.malware_report.get(k) for k in BODY_FIELDS}, ensure_ascii=False, default=str
        )
    )


def _dropped_text(record: RunRecord) -> str:
    negotiation = record.run_summary.get("negotiation") or {}
    validation = record.run_summary.get("validation") or {}
    rows = [str(r) for r in negotiation.get("dropped_claims") or []]
    rows += [json.dumps(r, ensure_ascii=False) for r in validation.get("retry_drops") or []]
    return _normal(" ".join(rows))


def _check_claims(record: RunRecord) -> Check:
    if not record.claims_in_force:
        return Check("no claim lost on the way to the report", False, "no answer in force")
    problems = []
    in_force = {_normal(c) for claims in record.claims_in_force.values() for c in claims}
    dropped = _dropped_text(record)
    for entry in _answered(record):
        if entry.get("answer") not in ("final", "revision"):
            continue
        for claim in entry.get("claims") or []:
            text = _normal(claim)
            if text and text not in in_force and text not in dropped:
                problems.append(
                    f"written by the model, then neither in force nor dropped: {claim[:70]}"
                )
    body = _body_text(record)
    total = 0
    for agent, claims in record.claims_in_force.items():
        for number, claim in enumerate(claims, 1):
            total += 1
            label = f"{agent} claim {number}"
            if label in body or (_normal(claim) and _normal(claim) in body):
                continue
            problems.append(f"not discussed in the report's body: [{label}] {claim[:70]}")
    detail = "; ".join(dict.fromkeys(problems)) or (
        f"all {total} claims in force are discussed in the report's body"
    )
    return Check("no claim lost on the way to the report", not problems, detail)


def _check_settings(record: RunRecord) -> Check:
    expected = record.expected or {}
    if not expected:
        return Check("settings in force as configured", False, "nothing configured to compare")
    problems = []
    seen = []
    log = _answered(record)
    for key, want in sorted(expected.items()):
        group, _, name = key.partition(".")
        if group in ("model", "effort", "max_tokens") and name:
            roles = ROLE_GROUPS.get(name, set())
            field_name = {"model": "model", "effort": "effort", "max_tokens": "max_tokens"}[group]
            found = {e.get(field_name) for e in log if e.get("role") in roles}
            if not found:
                problems.append(f"{key}: no {name} call was made")
            elif found != {want}:
                problems.append(
                    f"{key}: expected {want!r}, requests carried {sorted(found, key=str)}"
                )
            else:
                seen.append(key)
        elif key == "effort":
            efforts = {e.get("effort") for e in log}
            if efforts != {want}:
                problems.append(f"effort: expected {want!r}, requests carried {sorted(efforts)}")
            else:
                seen.append(key)
        elif key in ("max_steps", "timeout_s"):
            budget = record.run_summary.get("budget") or {}
            values = {agent: (row or {}).get(key) for agent, row in budget.items()}
            wrong = {a: v for a, v in values.items() if v != want}
            if not values or wrong:
                problems.append(f"{key}: expected {want}, the run's budget says {values}")
            else:
                seen.append(key)
        elif group == "settings" and name:
            snapshot = record.run_summary.get("settings_snapshot")
            if not isinstance(snapshot, dict):
                problems.append(f"{key}: the run summary carries no settings snapshot")
            elif snapshot.get(name) != want:
                problems.append(f"{key}: expected {want!r}, the run used {snapshot.get(name)!r}")
            else:
                seen.append(key)
        else:
            problems.append(f"{key}: not a setting this checklist can read")
    detail = "; ".join(problems) or f"{len(seen)} setting(s) as configured: {', '.join(seen)}"
    return Check("settings in force as configured", not problems, detail)


def _check_verdict(record: RunRecord) -> Check:
    reading = str(record.run_summary.get("verdict_reading") or "")
    return Check(
        "verdict stated by the judge",
        reading == "stated",
        f"verdict {record.verdict or 'none'}, read as {reading or 'nothing'}",
    )


def _check_deadline(record: RunRecord) -> Check:
    deadline = record.scenario_params.get("job_timeout_s")
    if not deadline:
        return Check("finished inside its deadline", True, "no deadline configured")
    margin = float(deadline) - record.elapsed_s
    ok = margin >= DEADLINE_MARGIN_SHARE * float(deadline)
    return Check(
        "finished inside its deadline",
        ok,
        f"{record.elapsed_s:.1f}s of a {float(deadline):.0f}s deadline, margin {margin:.1f}s "
        f"(at least {DEADLINE_MARGIN_SHARE:.0%} required)",
    )


def _check_scenario(record: RunRecord) -> Check:
    """The fault the scenario names really reached the pipeline."""
    from scripts.rehearsal.roles import SCENARIO_WIRES

    log = record.stub_log
    scenario = record.scenario
    name = f"the {scenario} scenario happened"
    if not log:
        return Check(name, False, "no stub log")
    faulted = [e for e in log if e.get("fault")]
    roles = Counter(str(e.get("role")) for e in log)
    wires = SCENARIO_WIRES.get(scenario)
    if wires is not None and record.api and record.api not in wires:
        ok = not faulted
        return Check(name, ok, f"not applicable to the {record.api} wire: run as normal")
    if scenario in ("normal", "cross_loop"):
        problems = []
        if faulted:
            problems.append(f"{len(faulted)} faulted calls in a scenario with none")
        if scenario == "cross_loop":
            analyst_last = max(
                (e["n"] for e in log if e.get("role") in ("analyst", "revision")), default=0
            )
            late = [
                e
                for e in log
                if e.get("role") in ("narrative", "composer")
                and e["n"] > analyst_last
                and e.get("status") == 200
            ]
            if not late:
                problems.append("no report-stage call answered after the analysts' calls")
        detail = "; ".join(problems) or f"{len(log)} calls: " + ", ".join(
            f"{n} {role}" for role, n in sorted(roles.items())
        )
        return Check(name, not problems, detail)
    if scenario == "redacted_thinking":
        thought = [e for e in log if e.get("status") == 200 and e.get("redacted")]
        return Check(name, bool(thought), f"{len(thought)} answers carried redacted thinking")
    if scenario == "long_loop":
        steps = [
            int((row or {}).get("steps_used") or 0)
            for row in (record.run_summary.get("budget") or {}).values()
        ]
        want = int(record.scenario_params.get("loop_steps") or 0)
        ok = bool(steps) and (not want or max(steps) >= want)
        return Check(name, ok, f"analyst loop steps {steps}, asked for {want or 'many'}")
    stage = str(record.scenario_params.get("deadline_in") or "")
    if scenario == "deadline_hit" and stage:
        return _check_deadline_in(record, name, stage)
    if scenario in ("slow_model", "deadline_hit"):
        delay = float(record.scenario_params.get("slow_seconds") or 0)
        slow = [e for e in log if float(e.get("delay") or 0) >= delay > 0]
        ok = delay > 0 and len(slow) == len(log) and record.elapsed_s >= delay
        return Check(
            name,
            ok,
            f"{len(slow)} of {len(log)} calls waited {delay:.1f}s; {record.elapsed_s:.1f}s elapsed",
        )
    if not faulted:
        return Check(name, False, "no call was faulted")
    hit = sorted({str(e.get("role")) for e in faulted})
    detail = f"{len(faulted)} faulted first calls of {', '.join(hit)}"
    return Check(name, True, detail)


def _check_deadline_in(record: RunRecord, name: str, stage: str) -> Check:
    """The deadline aimed at ``stage`` landed there: only its calls were held, the last one too."""
    roles = set(record.scenario_params.get("slow_roles") or [])
    delay = float(record.scenario_params.get("slow_seconds") or 0)
    log = [e for e in record.stub_log if e.get("role")]
    held = [e for e in log if e.get("role") in roles]
    others = [e for e in log if e.get("role") not in roles]
    problems = []
    if not roles or delay <= 0:
        problems.append(f"no call of the {stage} stage was set to be held")
    if not held:
        problems.append(f"the run never reached the {stage} stage")
    if any(float(e.get("delay") or 0) < delay for e in held):
        problems.append(f"a {stage} call was not held")
    if any(float(e.get("delay") or 0) > 0 for e in others):
        problems.append(f"a call outside the {stage} stage was held")
    last = str(log[-1].get("role")) if log else "none"
    if log and last not in roles:
        problems.append(f"the last call was {last}, outside the {stage} stage")
    detail = "; ".join(problems) or (
        f"the deadline landed in the {stage} stage: {len(held)} {stage} call(s) held "
        f"{delay:.0f}s, the last call ({last}) among them; {len(others)} other call(s) "
        "not held"
    )
    return Check(name, not problems, detail)


CHECKS = (
    _check_job,
    _check_refusals,
    _check_recognised,
    _check_probe,
    _check_stages,
    _check_analysts,
    _check_sections,
    _check_narrative,
    _check_tokens,
    _check_window,
    _check_rendered,
    _check_claims,
    _check_settings,
    _check_verdict,
    _check_deadline,
    _check_scenario,
)


def _usage_problems(record: RunRecord) -> list[str]:
    """What the stopped run did not keep of what it spent: its spend, and its token totals.

    The per-call usage events stand for both, one for every answered call. A
    run none of whose calls was answered spent nothing and counts no tokens:
    its run summary then holds a spend record and no token totals, as the
    product writes it.
    """
    answered = [e for e in record.stub_log if e.get("status") == 200 and not e.get("waiting")]
    usage_events = sum(1 for e in record.events if str(e.get("type")) == "model_usage")
    if answered and usage_events >= len(answered):
        return []
    tokens = record.run_summary.get("tokens")
    spend = record.run_summary.get("spend")
    problems = []
    if not (isinstance(spend, dict) and spend.get("spent_usd") is not None):
        problems.append("no spend was kept")
    calls = int(tokens.get("llm_calls") or 0) if isinstance(tokens, dict) else 0
    if answered and calls <= 0:
        problems.append(f"no token totals were kept for {len(answered)} answered call(s)")
    return problems


def _check_kept(record: RunRecord) -> Check:
    """A job the worker stopped keeps what it produced: its run summary and a partial report."""
    problems = []
    if JOB_TIMEOUT_SETTING not in record.incomplete_reason:
        problems.append(
            f"the stored report's incomplete reason is {record.incomplete_reason or 'missing'!r}"
        )
    if not record.run_summary:
        problems.append("no run summary was stored")
    problems += _usage_problems(record)
    if not record.markdown.strip():
        problems.append("no partial report renders")
    return Check(
        "the stopped run kept its run summary and a partial report",
        not problems,
        "; ".join(problems)
        or f"incomplete reason: {record.incomplete_reason}; "
        f"{len(record.run_summary.get('stages') or [])} stages in the run summary",
    )


# What a run whose deadline fired is held to: the in-process run has no report
# to check; a job the worker's own job timeout stopped must have kept one.
DEADLINE_CHECKS = (_check_job, _check_refusals, _check_recognised, _check_probe, _check_scenario)
WORKER_DEADLINE_CHECKS = (*DEADLINE_CHECKS, _check_kept)


def check_run(record: RunRecord) -> list[Check]:
    """Every check of the checklist over one run."""
    if record.scenario != "deadline_hit":
        checks = CHECKS
    elif stopped_by_the_worker(record):
        checks = WORKER_DEADLINE_CHECKS
    else:
        checks = DEADLINE_CHECKS
    return [check(record) for check in checks]


def signature(record: RunRecord, checks: list[Check]) -> dict[str, Any]:
    """What two runs of one scenario must share: structure and results, not timings or ids."""
    stages = [(s.get("key"), bool(s.get("ran"))) for s in record.run_summary.get("stages") or []]
    headings = [line.strip() for line in record.markdown.splitlines() if line.startswith("#")]
    return {
        "verdict": record.verdict,
        "verdict_reading": record.run_summary.get("verdict_reading"),
        "stages": stages,
        "sections": section_statuses(record),
        "claims": {agent: len(claims) for agent, claims in sorted(record.claims_in_force.items())},
        "judge_objects": dict(
            sorted(Counter(o.get("type") for o in record.stix_bundle.get("objects") or []).items())
        ),
        "extended_objects": dict(
            sorted(
                Counter(o.get("type") for o in record.stix_extended.get("objects") or []).items()
            )
        ),
        "markdown_headings": headings,
        "model_calls": dict(sorted(Counter(str(e.get("role")) for e in record.stub_log).items())),
        "checks": {c.name: c.ok for c in checks},
    }


def compare(signatures: list[dict[str, Any]]) -> list[str]:
    """Every way a later run differs from the first; empty when all are identical."""
    if len(signatures) < 2:
        return []
    first = signatures[0]
    differences = []
    for index, other in enumerate(signatures[1:], 2):
        for key in first:
            if first[key] != other.get(key):
                differences.append(
                    f"run {index} differs from run 1 in {key}: {other.get(key)!r} != {first[key]!r}"
                )
    return differences


def as_markdown(record: RunRecord, checks: list[Check]) -> str:
    """One run's result as a short markdown page."""
    passed = all(c.ok for c in checks)
    lines = [
        f"# Rehearsal: {record.scenario} ({record.api or 'unknown wire'})",
        "",
        f"Result: **{'PASS' if passed else 'FAIL'}** — verdict {record.verdict or 'none'}, "
        f"{record.elapsed_s:.1f}s, {len(record.stub_log)} model calls.",
        "",
        "| Check | Result | Found |",
        "|---|---|---|",
    ]
    for c in checks:
        lines.append(f"| {c.name} | {'pass' if c.ok else 'FAIL'} | {c.detail.replace('|', '/')} |")
    lines += ["", "## Report sections", ""]
    for section, status in section_statuses(record).items():
        lines.append(f"- {section}: {status}")
    if record.gate:
        lines += ["", "## Changed on the stack for the rehearsal", ""]
        for key, row in (record.gate.get("settings") or {}).items():
            lines.append(f"- {key}: {row.get('before')!r} -> {row.get('rehearsed')!r}")
        for key in record.gate.get("servers_disabled") or []:
            lines.append(f"- tool server {key}: disabled (its tool definitions were not sent)")
        for key in record.gate.get("servers_with_keys_withheld") or []:
            lines.append(f"- tool server {key}: reputation keys withheld (offline answers)")
    lines += ["", "## Observed", ""]
    for key, value in observations(record).items():
        lines.append(f"- {key}: {json.dumps(value, ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def observations(record: RunRecord) -> dict[str, Any]:
    """What a run did that no check judges: rounds, retries, degradations, calls, cost, time.

    These are the numbers a change meant to save time or calls moves, so two
    rehearsals before and after it can be compared.
    """
    negotiation = record.run_summary.get("negotiation") or {}
    validation = record.run_summary.get("validation") or {}
    roles = Counter(str(e.get("role")) for e in record.stub_log)
    deadline = record.scenario_params.get("job_timeout_s")
    try:
        usd, _unpriced = priced_usage(record)
    except Exception:  # noqa: BLE001 — an observation never fails a run
        usd = None
    return {
        "elapsed_s": round(record.elapsed_s, 2),
        "deadline_margin_s": round(float(deadline) - record.elapsed_s, 2) if deadline else None,
        "model_calls_by_role": dict(sorted(roles.items())),
        "faulted_calls": sum(1 for e in record.stub_log if e.get("fault")),
        "refused_calls": sum(1 for e in record.stub_log if e.get("refused")),
        "output_tokens": sum(int(e.get("output_tokens") or 0) for e in record.stub_log),
        "cache_read_tokens": sum(int(e.get("cache_read_tokens") or 0) for e in record.stub_log),
        "cache_write_tokens": sum(
            int(e.get("cache_write_5m_tokens") or 0) + int(e.get("cache_write_1h_tokens") or 0)
            for e in record.stub_log
        ),
        "usd_priced": None if usd is None else round(usd, 6),
        "negotiation_rounds": negotiation.get("rounds_completed"),
        "termination_reason": negotiation.get("termination_reason"),
        "validation_retries": validation.get("retries"),
        "validation_codes": validation.get("by_code") or {},
        "degradation_reasons": _degradations(record)[:20],
    }


def as_json(record: RunRecord, checks: list[Check]) -> dict[str, Any]:
    """One run's result as JSON: the checks, the signature, what it did, the stub's call log."""
    return {
        "scenario": record.scenario,
        "api": record.api,
        "passed": all(c.ok for c in checks),
        "verdict": record.verdict,
        "elapsed_s": round(record.elapsed_s, 2),
        "incomplete_reason": record.incomplete_reason,
        "checks": [asdict(c) for c in checks],
        "signature": signature(record, checks),
        "observations": observations(record),
        "gate": record.gate,
        "stub_log": record.stub_log,
    }
