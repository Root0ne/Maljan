"""A replay record and a comparison, as text for a terminal.

Codes, entry ids and counts. A finding's words and a claim's text are in the
record only when the replay was asked for them (``--show-text``), and are
printed only then.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from scripts.replay.record import errors


def _codes(codes: Mapping[str, int] | None) -> str:
    return ", ".join(f"{code} {count}" for code, count in sorted((codes or {}).items())) or "none"


def _flag_line(flag: Mapping[str, Any]) -> str:
    parts = [str(flag.get("code") or "")]
    for key in ("path", "subject"):
        if flag.get(key):
            parts.append(str(flag[key]))
    for marker, said in (
        ("advisory", "advisory"),
        ("settled", "settled by the parse"),
        ("answered", "answered"),
    ):
        if flag.get(marker):
            parts.append(said)
    if flag.get("asked") is False:
        parts.append("not shown to its producer")
    if flag.get("entries"):
        parts.append(", ".join(str(e) for e in flag["entries"]))
    if flag.get("arguments"):
        parts.append("argument " + ", ".join(str(a) for a in flag["arguments"]))
    line = " | ".join(parts)
    if flag.get("claim"):
        line += f"\n        claim: {flag['claim']}"
    if flag.get("message"):
        line += f"\n        said: {flag['message']}"
    if flag.get("values"):
        line += f"\n        values: {flag['values']}"
    return line


def render_record(record: Mapping[str, Any]) -> str:
    """One run's replay as text; a part that raised comes first."""
    lines: list[str] = [f"Replay of {record.get('run')}"]
    for row in errors(record):
        lines.append(f"  ERROR: {row.get('part')} raised: {row.get('why')}")
    rules = record.get("rules") or {}
    lines.append(f"  rules from: {rules.get('tree', 'unknown')}")
    stored = record.get("stored") or {}
    if stored:
        lines.append(
            f"  stored run: {len(stored.get('files') or {})} file(s), unchanged "
            "(each digested before and after the replay)"
        )
    env = record.get("environment") or {}
    if env:
        lines.append(
            f"  network {env.get('network')}; ATT&CK from {env.get('attck')}; "
            f"{len(env.get('settings_from_run') or [])} setting(s) from the run's snapshot"
        )
        if env.get("settings_refused"):
            lines.append(f"  settings this tree refused: {', '.join(env['settings_refused'])}")
        if env.get("doors_this_tree_lacks"):
            lines.append(f"  doors this tree lacks: {', '.join(env['doors_this_tree_lacks'])}")

    lines.append("")
    lines.append("Analysts")
    for agent, entry in (record.get("analysts") or {}).items():
        answers = entry.get("answers") or []
        replayed = [a for a in answers if a.get("replayed")]
        lines.append(f"  {agent}: {len(replayed)} of {len(answers)} stored answer(s) replayed")
        for answer in replayed:
            lines.append(
                f"    {answer.get('answer')} ({answer.get('source')}): "
                f"{answer.get('claims')} claim(s); {_codes(answer.get('codes'))}"
            )
        in_force = entry.get("in_force") or {}
        if in_force.get("replayed") is False:
            lines.append(f"    claims in force: not replayed ({in_force.get('why')})")
        elif in_force:
            lines.append(
                f"    claims in force: {in_force.get('claims')} claim(s); "
                f"{_codes(in_force.get('codes'))}"
            )
            for key, said in (
                ("not_valid", "technique ids marked not valid"),
                ("kept_after_absence_question", "kept after the absence question"),
            ):
                if in_force.get(key):
                    lines.append(f"      {said}: {', '.join(in_force[key])}")

    def _part(title: str, key: str, extra: str = "") -> None:
        part = record.get(key) or {}
        if part.get("replayed") is False:
            lines.append(f"{title}: not replayed ({part.get('why')})")
        else:
            lines.append(f"{title}: {extra}{_codes(part.get('codes'))}")

    lines.append("")
    judge = record.get("judge") or {}
    _part(
        "Judge",
        "judge",
        f"{judge.get('objects', 0)} object(s), {judge.get('indicators_dropped', 0)} "
        "indicator(s) it would drop; "
        if judge.get("replayed")
        else "",
    )
    _part("Narrative", "narrative")
    composer = record.get("composer") or {}
    written = len(composer.get("sections") or {})
    not_written = composer.get("not_written") or []
    _part(
        "Composer",
        "composer",
        f"{written} section(s) replayed"
        + (f", not written in the stored report: {', '.join(not_written)}" if not_written else "")
        + "; "
        if composer.get("replayed")
        else "",
    )
    tool = record.get("tool") or {}
    _part("Tool calls", "tool", f"{tool.get('calls', 0)} call(s); " if tool.get("replayed") else "")
    _part("Report linter", "fp_linter")

    report = record.get("report") or {}
    if report.get("replayed"):
        techniques = report.get("techniques") or {}
        published = [t for t, row in techniques.items() if row.get("published")]
        indicators = report.get("indicators") or {}
        yes = [
            k for k, row in indicators.items() if str(row.get("published") or "").startswith("yes")
        ]
        lines.append(
            f"Report: {report.get('verdict')}, severity {report.get('severity')}, category "
            f"{report.get('category')}, confidence {report.get('confidence')}; "
            f"{len(report.get('sections') or [])} section(s); {len(published)} of "
            f"{len(techniques)} technique(s) published; {len(yes)} of {len(indicators)} "
            "indicator(s) published"
        )
        lines.append(
            "  exported techniques: "
            + (", ".join(report.get("export", {}).get("attack_patterns") or []) or "none")
        )
        unpublished = {
            t: row.get("why") for t, row in techniques.items() if not row.get("published")
        }
        for tid, why in unpublished.items():
            lines.append(f"  not published: {tid} ({why})")
        if "detection_rules" in report:
            lines.append(
                f"  detection rules drafted: {_codes(report.get('detection_rules'))}; "
                f"{report.get('detection_rules_not_compiled', 0)} not compiled"
            )
        uncovered = report.get("claims_not_discussed")
        if uncovered is not None:
            listed = "; ".join(
                f"{agent} {', '.join(str(n) for n in numbers)}"
                for agent, numbers in uncovered.items()
            )
            lines.append(
                "  claims in force the body does not discuss: "
                f"{sum(len(n) for n in uncovered.values())}" + (f" ({listed})" if listed else "")
            )
    else:
        lines.append(f"Report: not replayed ({report.get('why')})")
    corroboration = (record.get("corroboration") or {}).get("techniques") or {}
    if corroboration:
        agreed = [t for t, row in corroboration.items() if row.get("corroborated")]
        lines.append(
            f"Corroboration: {len(corroboration)} technique(s), {len(agreed)} corroborated"
            + (f" ({', '.join(agreed)})" if agreed else "")
        )

    totals = record.get("totals") or {}
    codes = sorted({code for part in totals.values() for code in part})
    if codes:
        lines.append("")
        lines.append("Codes, by producer")
        for code in codes:
            counts = ", ".join(
                f"{part.replace('_', ' ')} {totals[part][code]}"
                for part in totals
                if code in totals[part]
            )
            lines.append(f"  {code}: {counts}")

    flagged = _flags(record)
    if flagged:
        lines.append("")
        lines.append("Findings")
        for where, flags in flagged:
            lines.append(f"  {where}")
            lines.extend(f"    {_flag_line(flag)}" for flag in flags)

    not_replayed = record.get("not_replayed") or []
    if not_replayed:
        lines.append("")
        lines.append("Not replayed")
        lines.extend(
            f"  {row['part']}: {row['why']}" + (" [raised]" if row.get("error") else "")
            for row in not_replayed
        )
    return "\n".join(lines)


def _flags(record: Mapping[str, Any]) -> list[tuple[str, Sequence[Mapping[str, Any]]]]:
    out: list[tuple[str, Sequence[Mapping[str, Any]]]] = []
    for agent, entry in (record.get("analysts") or {}).items():
        for answer in entry.get("answers") or []:
            if answer.get("flags"):
                out.append((f"analyst {agent}, {answer.get('answer')}", answer["flags"]))
        in_force = entry.get("in_force") or {}
        if in_force.get("flags"):
            out.append((f"analyst {agent}, claims in force", in_force["flags"]))
    for part in ("judge", "narrative", "tool", "fp_linter"):
        flags = (record.get(part) or {}).get("flags") or []
        if flags:
            out.append((part, flags))
    for section, entry in ((record.get("composer") or {}).get("sections") or {}).items():
        if entry.get("flags"):
            out.append((f"composer {section}", entry["flags"]))
    return out


def render_diff(diff: Mapping[str, Any], ref_a: str, ref_b: str) -> str:
    """Every difference between two refs' replays of one run, as text.

    A part that raised in either tree comes first: the comparison is then not
    a decision, and "no difference" is said only when every part replayed in
    both trees.
    """
    lines = [f"Compare {diff.get('run')}: A = {ref_a}, B = {ref_b}"]
    raised = diff.get("errors") or {}
    for side, ref in (("a", ref_a), ("b", ref_b)):
        for row in raised.get(side) or []:
            lines.append(
                f"  ERROR under {side.upper()} ({ref}): {row.get('part')} raised: {row.get('why')}"
            )
    if raised.get("a") or raised.get("b"):
        lines.append(
            "  A part that raised is not a decision: this comparison is incomplete (status 2)."
        )
    schema = diff.get("schema") or {}
    if schema:
        lines.append(
            f"  The records are of schema {schema.get('a')} (A) and {schema.get('b')} (B): only "
            "what both define is compared."
        )
    if not any(key not in ("run", "errors", "schema") for key in diff):
        if not (raised.get("a") or raised.get("b")):
            lines.append("  no difference: both refs decide the same over this run")
        else:
            lines.append("  the parts that replayed in both trees decide the same")
        return "\n".join(lines)
    for key, title in (
        ("codes_gained", "Codes in B, not in A"),
        ("codes_lost", "Codes in A, not in B"),
    ):
        rows = diff.get(key) or []
        if rows:
            lines.append(f"  {title}:")
            for row in rows:
                where = " | ".join(
                    str(row[k]) for k in ("part", "owner", "path", "subject") if row.get(k)
                )
                lines.append(f"    {row['code']} x{row['count']}: {where}")
    for key, title in (
        ("totals", "Counts by producer and code"),
        ("answers", "Claims each answer parsed into"),
        ("corroboration", "Corroboration"),
        ("not_replayed", "Parts not replayed"),
        ("replayed", "Parts replayed"),
    ):
        if diff.get(key):
            lines.append(f"  {title}:")
            lines.extend(f"    {line}" for line in _nested(diff[key]))
    report = diff.get("report") or {}
    if report:
        lines.append("  Report:")
        lines.extend(f"    {line}" for line in _nested(report))
    return "\n".join(lines)


def _nested(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, Mapping):
        if set(value) == {"a", "b"}:
            return [f"{prefix}A {value['a']!r} -> B {value['b']!r}"]
        out: list[str] = []
        for key, inner in value.items():
            label = f"{prefix}{key}"
            if isinstance(inner, Mapping | list) and inner:
                if isinstance(inner, Mapping) and set(inner) == {"a", "b"}:
                    out.append(f"{label}: A {inner['a']!r} -> B {inner['b']!r}")
                else:
                    out.append(f"{label}:")
                    out.extend(f"  {line}" for line in _nested(inner))
            else:
                out.append(f"{label}: {inner!r}")
        return out
    if isinstance(value, list):
        return [line for item in value for line in _nested(item, prefix)]
    return [f"{prefix}{value!r}"]
