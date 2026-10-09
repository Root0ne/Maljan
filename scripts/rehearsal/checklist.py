"""The written checklist a rehearsal run is held to, and the comparison of repeated runs.

A run is described by one plain record (:class:`RunRecord`), built the same
way from the running stack (``scripts/rehearsal/run.py``) or from an in-process
pipeline (``scripts/rehearsal/inprocess.py``), so both are judged by the same
checks:

* the job completed;
* every stage that started finished, and none failed;
* every analyst answered: none failed or was lost to an error;
* every one of the composer's sections is written, or explicitly accounted
  for: marked not written by a degradation reason, answered empty by the
  model, or never asked because its evidence was empty — never lost between
  an answer and the report;
* the narrative is written or marked;
* the run summary is present and its token totals are the provider-reported
  usage, call for call;
* the STIX bundles and the markdown are rendered;
* no claim of an answer in force is missing from the report;
* the settings in force are the ones configured (model per role, effort,
  output caps, step and time limits, any settings-snapshot key);
* the verdict was stated by the judge;
* the scenario's fault really happened, so a fault run cannot pass vacuously.

Each check is a :class:`Check` with a sentence saying what was found.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

# Every section the composer writes, and where the stored report holds it.
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

# The stub's roles, by the agent whose budget and model they spend.
ROLE_AGENTS: dict[str, str] = {
    "mediator": "mediator",
    "judge": "judge",
    "technique_question": "judge",
    "narrative": "reporter",
    "composer": "reporter",
}

# Stages a default profile runs, in order.
DEFAULT_STAGES = ("triage_pack", "analysis", "debate", "verdict", "report")


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


def section_statuses(record: RunRecord) -> dict[str, str]:
    """Each composer section's status: written, marked, answered empty, not asked, or lost."""
    reasons = _degradations(record)
    asked: dict[str, list[dict[str, Any]]] = {}
    for entry in record.stub_log:
        if entry.get("role") == "composer" and entry.get("section"):
            asked.setdefault(str(entry["section"]), []).append(entry)
    statuses: dict[str, str] = {}
    for section, place in SECTION_PLACES.items():
        if _has_content(_get(record.malware_report, place)):
            statuses[section] = "written"
        elif any(f"'{section}'" in r or f"{section} section" in r for r in reasons):
            statuses[section] = "marked not written"
        elif not record.stub_log:
            statuses[section] = "not written (no stub log to say why)"
        elif section not in asked:
            statuses[section] = "not asked (no evidence for it)"
        else:
            last = asked[section][-1]
            if last.get("status") == 200 and last.get("content") is False:
                statuses[section] = "answered empty"
            else:
                statuses[section] = "lost"
    return statuses


def _check_job(record: RunRecord) -> Check:
    ok = record.job_status == "completed"
    detail = f"job status {record.job_status}"
    if record.job_error:
        detail += f": {record.job_error}"
    return Check("job completed", ok, detail)


def _check_stages(record: RunRecord) -> Check:
    started = [e.get("stage") for e in record.events if e.get("type") == "stage_started"]
    finished = [e.get("stage") for e in record.events if e.get("type") == "stage_finished"]
    stages = record.run_summary.get("stages") or []
    failed = [s.get("key") for s in stages if s.get("failure")]
    unfinished = [s for s in started if s not in finished]
    problems = []
    if not started:
        problems.append("no stage_started event")
    if unfinished:
        problems.append(f"started and never finished: {', '.join(map(str, unfinished))}")
    if failed:
        problems.append(f"failed: {', '.join(map(str, failed))}")
    if not stages:
        problems.append("the run summary lists no stage")
    ran = [
        f"{s.get('key')}{'' if s.get('ran') else ' (skipped: ' + str(s.get('reason')) + ')'}"
        for s in stages
    ]
    detail = "; ".join(problems) if problems else f"{len(stages)} stages: {', '.join(ran)}"
    return Check("every stage started and finished", not problems, detail)


def _check_sections(record: RunRecord) -> Check:
    statuses = section_statuses(record)
    lost = [s for s, status in statuses.items() if status == "lost"]
    counts = Counter(statuses.values())
    detail = ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))
    if lost:
        detail = f"lost between answer and report: {', '.join(lost)}; {detail}"
    return Check("every report section written or accounted for", not lost, detail)


def _check_narrative(record: RunRecord) -> Check:
    summary = str(record.malware_report.get("executive_summary") or "").strip()
    if summary:
        return Check("narrative written or marked", True, f"{len(summary)} characters")
    marked = [r for r in _degradations(record) if "narrative" in r.lower()]
    if marked:
        return Check("narrative written or marked", True, f"marked: {marked[0]}")
    return Check("narrative written or marked", False, "no executive summary and no mark")


def _check_tokens(record: RunRecord) -> Check:
    summary = record.run_summary
    tokens = summary.get("tokens") or {}
    if not summary or not tokens:
        return Check("run summary and token totals", False, "no run summary or no token totals")
    calls = int(tokens.get("llm_calls") or 0)
    sent = int(tokens.get("input_tokens") or 0)
    got = int(tokens.get("output_tokens") or 0)
    problems = []
    if calls <= 0 or sent <= 0 or got <= 0:
        problems.append(f"empty totals ({calls} calls, {sent} in, {got} out)")
    answered = [e for e in record.stub_log if e.get("status") == 200]
    if record.stub_log:
        unreported = int(tokens.get("unreported_calls") or 0)
        if calls + unreported != len(answered):
            problems.append(
                f"{calls} calls counted (+{unreported} unreported), the model answered "
                f"{len(answered)}"
            )
        elif not unreported:
            stub_in = sum(int(e.get("input_tokens") or 0) for e in answered)
            stub_out = sum(int(e.get("output_tokens") or 0) for e in answered)
            if (sent, got) != (stub_in, stub_out):
                problems.append(
                    f"totals {sent} in / {got} out, the provider reported "
                    f"{stub_in} in / {stub_out} out"
                )
    detail = "; ".join(problems) or f"{calls} calls, {sent} input and {got} output tokens"
    return Check("run summary and token totals", not problems, detail)


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


def _check_claims(record: RunRecord) -> Check:
    if not record.claims_in_force:
        return Check("no claim lost on the way to the report", False, "no answer in force")
    held = _normal(json.dumps(record.malware_report, ensure_ascii=False))
    held += " " + _normal(record.markdown)
    missing = []
    total = 0
    for agent, claims in record.claims_in_force.items():
        for claim in claims:
            total += 1
            text = _normal(claim)
            escaped = _normal(json.dumps(claim, ensure_ascii=False)[1:-1])
            if text and text not in held and escaped not in held:
                missing.append(f"{agent}: {claim[:80]}")
    detail = f"all {total} claims are in the report" if not missing else "; ".join(missing)
    return Check("no claim lost on the way to the report", not missing, detail)


def _roles_of(agent: str) -> set[str]:
    if agent in ("judge", "reporter", "mediator"):
        return {role for role, owner in ROLE_AGENTS.items() if owner == agent}
    return {"analyst", "revision"}


def _check_settings(record: RunRecord) -> Check:
    expected = record.expected or {}
    if not expected:
        return Check("settings in force as configured", True, "nothing configured to compare")
    problems = []
    seen = []
    log = [e for e in record.stub_log if e.get("status") == 200]
    for key, want in sorted(expected.items()):
        if key.startswith("model."):
            roles = _roles_of(key.split(".", 1)[1])
            models = {e.get("model") for e in log if e.get("role") in roles}
            if models != {want}:
                problems.append(f"{key}: expected {want}, the model was asked as {sorted(models)}")
            else:
                seen.append(key)
        elif key == "effort":
            efforts = {e.get("effort") for e in log}
            if efforts != {want}:
                problems.append(f"effort: expected {want!r}, requests carried {sorted(efforts)}")
            else:
                seen.append(key)
        elif key.startswith("max_tokens."):
            roles = _roles_of(key.split(".", 1)[1])
            caps = {e.get("max_tokens") for e in log if e.get("role") in roles}
            if caps != {want}:
                problems.append(f"{key}: expected {want}, requests carried {sorted(caps, key=str)}")
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
        elif key.startswith("settings."):
            snapshot = record.run_summary.get("settings_snapshot")
            if not isinstance(snapshot, dict):
                problems.append(f"{key}: the run summary carries no settings snapshot")
                continue
            name = key.split(".", 1)[1]
            if snapshot.get(name) != want:
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


def _check_scenario(record: RunRecord) -> Check:
    """The fault the scenario names really reached the pipeline, and the run went on."""
    log = record.stub_log
    scenario = record.scenario
    name = f"the {scenario} scenario happened"
    if not log:
        return Check(name, scenario == "normal", "no stub log")
    faulted = [e for e in log if e.get("fault")]
    roles = Counter(str(e.get("role")) for e in log)
    if scenario in ("normal", "cross_loop"):
        problems = []
        if faulted:
            problems.append(f"{len(faulted)} faulted calls in a scenario with none")
        if scenario == "cross_loop":
            analyst_last = max(
                (e["n"] for e in log if e.get("role") in ("analyst", "revision")), default=0
            )
            report_calls = [e for e in log if e.get("role") in ("narrative", "composer")]
            late = [e for e in report_calls if e["n"] > analyst_last and e.get("status") == 200]
            if not late:
                problems.append("no report-stage call answered after the analysts' calls")
        detail = "; ".join(problems) or f"{len(log)} calls: " + ", ".join(
            f"{n} {role}" for role, n in sorted(roles.items())
        )
        return Check(name, not problems, detail)
    if scenario == "long_loop":
        steps = [
            int((row or {}).get("steps_used") or 0)
            for row in (record.run_summary.get("budget") or {}).values()
        ]
        want = int(record.scenario_params.get("loop_steps") or 0)
        ok = bool(steps) and (not want or max(steps) >= want)
        return Check(name, ok, f"analyst loop steps {steps}, asked for {want or 'many'}")
    if scenario == "slow_model":
        delay = float(record.scenario_params.get("slow_seconds") or 0)
        floor = delay * len([e for e in log if e.get("status") == 200])
        ok = record.elapsed_s >= floor * 0.9
        return Check(name, ok, f"{record.elapsed_s:.1f}s elapsed, at least {floor:.1f}s expected")
    if not faulted:
        return Check(name, False, "no call was faulted")
    hit = sorted({str(e.get("role")) for e in faulted})
    answered_later = sorted(
        {
            str(e.get("role"))
            for e in log
            if e.get("status") == 200 and not e.get("fault") and str(e.get("role")) in hit
        }
    )
    # A server error is retried by the client, so every role it hit must be
    # answered afterwards. Any other fault is the model's answer, which the
    # pipeline asks again or records; the other checks say which.
    unanswered = sorted(set(hit) - set(answered_later))
    ok = not unanswered if scenario == "server_error_once" else True
    detail = (
        f"faulted the first call of {', '.join(hit)}; answered afterwards: "
        f"{', '.join(answered_later) or 'none'}"
    )
    if unanswered and scenario == "server_error_once":
        detail += f"; never answered after the error: {', '.join(unanswered)}"
    return Check(name, ok, detail)


def _check_analysts(record: RunRecord) -> Check:
    """Every analyst the run started answered: none failed and none was lost to an error."""
    failed = [str(a) for a in record.run_summary.get("failed_analysts") or []]
    stats = record.run_summary.get("agent_stats") or []
    named = [str(s.get("agent_id")) for s in stats if isinstance(s, dict)]
    if failed:
        return Check("every analyst answered", False, f"failed: {', '.join(failed)}")
    return Check(
        "every analyst answered",
        True,
        f"{len(named)} analyst(s): {', '.join(named)}" if named else "no analyst failed",
    )


CHECKS = (
    _check_job,
    _check_stages,
    _check_analysts,
    _check_sections,
    _check_narrative,
    _check_tokens,
    _check_rendered,
    _check_claims,
    _check_settings,
    _check_verdict,
    _check_scenario,
)


def check_run(record: RunRecord) -> list[Check]:
    """Every check of the checklist over one run."""
    return [check(record) for check in CHECKS]


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
        f"# Rehearsal: {record.scenario}",
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
    lines += ["", "## Observed", ""]
    for key, value in observations(record).items():
        lines.append(f"- {key}: {json.dumps(value, ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def observations(record: RunRecord) -> dict[str, Any]:
    """What a run did that no check judges: rounds, retries, degradations, calls and time.

    These are the numbers a change meant to save time or calls moves, so two
    rehearsals before and after it can be compared.
    """
    negotiation = record.run_summary.get("negotiation") or {}
    validation = record.run_summary.get("validation") or {}
    roles = Counter(str(e.get("role")) for e in record.stub_log)
    busy = sorted((str(e.get("role")), int(e.get("output_tokens") or 0)) for e in record.stub_log)
    deadline = record.scenario_params.get("job_timeout_s")
    return {
        "elapsed_s": round(record.elapsed_s, 2),
        # How far inside the job's deadline the run finished, where one is known.
        "deadline_margin_s": round(float(deadline) - record.elapsed_s, 2) if deadline else None,
        "model_calls_by_role": dict(sorted(roles.items())),
        "faulted_calls": sum(1 for e in record.stub_log if e.get("fault")),
        "output_tokens": sum(tokens for _role, tokens in busy),
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
        "passed": all(c.ok for c in checks),
        "verdict": record.verdict,
        "elapsed_s": round(record.elapsed_s, 2),
        "checks": [asdict(c) for c in checks],
        "signature": signature(record, checks),
        "observations": observations(record),
        "stub_log": record.stub_log,
    }
