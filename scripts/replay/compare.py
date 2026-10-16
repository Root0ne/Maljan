"""The same stored runs replayed under two git refs, and every difference between the records.

Each ref is replayed with its own harness over its own rules. Its tree is
written out of the repository's object store into a directory of the replay's
own (``git archive``, :func:`materialise`): ``pyproject.toml`` (the project
root the rules' data readers look for), the ``src`` tree, the ``data`` tables
without ``data/samples``, and ``scripts/replay``. That tree's own
``scripts/replay/run.py`` then replays the runs in a process of its own, with
that tree first on the import path and the same read-only and cache guards
(:func:`replay_under`), and the record says which tree it imported its rules
from, which is checked. No working tree is read for the rules, and none is
written. A ref from before the replay tool has no harness to replay with: it
cannot be compared (:class:`PredatesTheReplay`). A ref's replay can be given a
time limit; one stopped at it is named (:class:`RefTimedOut`).

:func:`diff_records` names every difference between two records of one run:
the codes each producer gained or lost, per claim (the flag's path and
subject); the claims each answer parsed into and the notes the claims in force
carry; the published techniques and the reasons for the unpublished ones; each
indicator's publish answer; the report's values; the judge's drops; the
settings and guards each tree refused or lacked; corroboration per technique;
and the parts one side could replay and the other could not. The values are
compared value-free (``scripts.replay.record``), so a record made with the
text compares with one made without it.

Two records of different schemas are compared on what both define, and every
part only one of them defines is listed under ``not_compared``: the
comparison is then partial. A part that raised in either tree is listed under
``errors``. Either way the comparison is not a decision, and the command ends
with status 2.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess  # nosec B404 — git and the replay itself, argument lists only
import sys
import tarfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.replay.guard import ATTCK_CACHE_VARIABLE
from scripts.replay.record import (
    BOOKKEEPING_KEYS,
    answer_head,
    digest,
    errors,
    schema_of,
    value_free_subject,
)

# What a ref's replay is made of: the project root marker, the rules, the
# tables they read, and the harness that replays them. ``data/samples`` is
# left out: a sample is never copied.
ARCHIVED_PATHS: tuple[str, ...] = (
    "pyproject.toml",
    "src",
    "data",
    ":(exclude)data/samples",
    "scripts/replay",
)
# The harness a ref replays with; a ref without it predates the replay tool.
HARNESS = "scripts/replay/run.py"
# The schema from which a record's values are value-free.
VALUE_FREE_SCHEMA = 3


class CompareError(RuntimeError):
    """A ref could not be written out or replayed."""


class PredatesTheReplay(CompareError):
    """A ref from before the replay tool: it has no harness to replay its rules with."""


class RefTimedOut(CompareError):
    """A ref's replay did not finish within the time it was given, and was stopped."""


def _git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        said = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise CompareError(f"git {args[0]} failed: {said[-1] if said else done.returncode}")
    return done.stdout


def resolve(repo: Path, ref: str) -> str:
    """The commit ``ref`` names, as a full hash."""
    return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()


def has_harness(repo: Path, commit: str) -> bool:
    """Whether ``commit`` carries the replay harness."""
    done = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        ["git", "-C", str(repo), "cat-file", "-e", f"{commit}:{HARNESS}"],
        capture_output=True,
        check=False,
    )
    return done.returncode == 0


def materialise(repo: Path, ref: str, into: Path) -> Path:
    """Write ``ref``'s replay into ``into`` from the object store; return the tree's root."""
    commit = resolve(repo, ref)
    if not has_harness(repo, commit):
        raise PredatesTheReplay(
            f"{ref} predates the replay tool (it has no {HARNESS}): it cannot be compared"
        )
    archive = _git(repo, "archive", "--format=tar", commit, "--", *ARCHIVED_PATHS)
    if into.exists():
        # A tree an earlier comparison left: a module this ref does not have
        # must not stay importable beside the ones it does.
        shutil.rmtree(into)
    into.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(into, filter="data")  # nosec B202 — our own archive, the data filter
    if not (into / "src" / "maljan").is_dir() or not (into / "pyproject.toml").is_file():
        raise CompareError(f"{ref} has no src/maljan tree or no pyproject.toml")
    return into


def replay_under(
    tree: Path,
    runs: Sequence[Path],
    out: Path,
    *,
    show_text: bool = False,
    timeout: float | None = None,
) -> list[dict[str, Any]]:
    """The replay of each of ``runs`` by ``tree``'s own harness over its own rules.

    The harness ends with status 2 when a part raised and still writes its
    record, which says which part; no record at all is a harness that failed.
    ``timeout`` is how many seconds the harness is given (none by default); one
    that is still running then is stopped (:class:`RefTimedOut`). The ATT&CK
    cache variable points at a directory of the comparison's own before the
    harness starts, whatever the harness does with it.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(tree / "src"), str(tree)])
    cache = out.with_name(f"{out.stem}-attck")
    cache.mkdir(parents=True, exist_ok=True)
    env[ATTCK_CACHE_VARIABLE] = str(cache.resolve())
    if out.exists():
        out.unlink()
    command = [
        sys.executable,
        str(tree / HARNESS),
        *(str(Path(run).resolve()) for run in runs),
        "--json",
        str(out.resolve()),
        "--quiet",
    ]
    if show_text:
        command.append("--show-text")
    try:
        done = subprocess.run(  # nosec B603 — the replay itself, an argument list
            command, env=env, cwd=tree, capture_output=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise RefTimedOut(
            f"the replay under {tree} did not finish within {timeout:g} s and was stopped"
        ) from exc
    if done.returncode not in (0, 2) or not out.is_file():
        said = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise CompareError(
            f"the replay under {tree} wrote no record: {said[-1] if said else done.returncode}"
        )
    records = json.loads(out.read_text(encoding="utf-8"))
    records = records if isinstance(records, list) else [records]
    expected = str((tree / "src").resolve().parent)
    for record in records:
        imported = str((record.get("rules") or {}).get("tree") or "")
        if Path(imported).resolve() != Path(expected):
            raise CompareError(
                f"the replay under {tree} imported its rules from {imported or 'nowhere'}"
            )
    return records


# ---------------------------------------------------------------------------
# The differences
# ---------------------------------------------------------------------------


def _flag_key(part: str, owner: str, flag: Mapping[str, Any]) -> tuple[str, ...]:
    """A finding's key, its subject and the path that writes it value-free."""
    subject = str(flag.get("subject") or "")
    shown = value_free_subject(subject)
    path = str(flag.get("path") or "")
    if subject and shown != subject:
        path = path.replace(subject, shown)
    return (part, owner, path, shown, str(flag.get("code") or ""))


def flag_keys(record: Mapping[str, Any]) -> Counter[tuple[str, ...]]:
    """Every finding of a record, keyed by producer, answer, claim and code, counted."""
    out: Counter[tuple[str, ...]] = Counter()
    for agent, entry in (record.get("analysts") or {}).items():
        for answer in entry.get("answers") or []:
            owner = f"{agent} {answer.get('answer', '')}"
            for flag in answer.get("flags") or []:
                out[_flag_key("analyst answer", owner, flag)] += 1
        for flag in (entry.get("in_force") or {}).get("flags") or []:
            out[_flag_key("claims in force", agent, flag)] += 1
    for part in ("judge", "narrative", "tool", "fp_linter"):
        for flag in (record.get(part) or {}).get("flags") or []:
            owner = ",".join(flag.get("entries") or []) if part == "tool" else ""
            out[_flag_key(part, owner, flag)] += 1
    for section, entry in ((record.get("composer") or {}).get("sections") or {}).items():
        for flag in entry.get("flags") or []:
            out[_flag_key("composer", section, flag)] += 1
    return out


def _keyed(rows: Iterable[tuple[tuple[str, ...], int]]) -> list[dict[str, Any]]:
    names = ("part", "owner", "path", "subject", "code")
    return [
        {**{n: v for n, v in zip(names, key, strict=True) if v}, "count": count}
        for key, count in sorted(rows)
    ]


def _changed(a: Any, b: Any) -> dict[str, Any] | None:
    return None if a == b else {"a": a, "b": b}


def _mapping_diff(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    """Keys only in ``a``, only in ``b``, and changed values, of two flat mappings."""
    out: dict[str, Any] = {}
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    changed = {k: {"a": a[k], "b": b[k]} for k in sorted(set(a) & set(b)) if a[k] != b[k]}
    if only_a:
        out["only_a"] = {k: a[k] for k in only_a}
    if only_b:
        out["only_b"] = {k: b[k] for k in only_b}
    if changed:
        out["changed"] = changed
    return out


# What an answer's shape and the notes on the claims in force are, by the
# schema that first records each.
_SHAPE_KEYS: tuple[tuple[str, int], ...] = (("claims", 1), ("findings", 1))
_NOTE_KEYS: tuple[tuple[str, int], ...] = (
    ("claims", 1),
    ("findings", 1),
    ("not_valid", 2),
    ("kept_after_absence_question", 2),
)


def _answer_shapes(record: Mapping[str, Any], schema: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for agent, entry in (record.get("analysts") or {}).items():
        for answer in entry.get("answers") or []:
            key = f"{agent} {answer.get('answer', '')} ({answer.get('source', '')})"
            out[key] = (
                {k: answer.get(k) for k, since in _SHAPE_KEYS if since <= schema}
                if answer.get("replayed")
                else {"replayed": False}
            )
        in_force = entry.get("in_force") or {}
        if in_force:
            out[f"{agent} claims in force"] = {
                k: in_force.get(k) for k, since in _NOTE_KEYS if since <= schema
            }
    return out


def _defined(record: Mapping[str, Any], schema: int) -> set[str]:
    """The parts a record defines, by name: its parts, its report's values and its notes.

    The record's own bookkeeping and the text fields (``*_text``) are never
    compared, so they are not among them.
    """
    names = {key for key in record if key not in BOOKKEEPING_KEYS}
    report = record.get("report")
    if isinstance(report, dict):
        names.update(f"report.{key}" for key in report if not key.endswith("_text"))
    for key, since in _NOTE_KEYS:
        if since <= schema and any(
            key in (entry.get("in_force") or {})
            for entry in (record.get("analysts") or {}).values()
        ):
            names.add(f"claims in force: {key}")
    return names


def _has_reasons(record: Mapping[str, Any]) -> bool:
    techniques = (record.get("report") or {}).get("techniques") or {}
    return any(isinstance(row, dict) and "why" in row for row in techniques.values())


def _common(
    a: Mapping[str, Any], b: Mapping[str, Any], schema_a: int, schema_b: int
) -> tuple[dict[str, Any], dict[str, Any], dict[str, list[str]]]:
    """The two records cut to what both define, and the parts left uncompared.

    ``a`` and ``b`` list the parts only that record defines. ``differently``
    lists the parts both define in forms that cannot be compared: before the
    value-free schema, the reason beside an unpublished technique was the
    judge's words when the record was made with the text, and the record does
    not say whether it was.
    """
    keys = set(a) & set(b)
    a2 = {k: a[k] for k in keys}
    b2 = {k: b[k] for k in keys}
    report_a, report_b = a2.get("report"), b2.get("report")
    if isinstance(report_a, dict) and isinstance(report_b, dict):
        both = set(report_a) & set(report_b)
        a2["report"] = {k: report_a[k] for k in both}
        b2["report"] = {k: report_b[k] for k in both}
    defined_a, defined_b = _defined(a, schema_a), _defined(b, schema_b)
    not_compared = {
        "a": sorted(defined_a - defined_b),
        "b": sorted(defined_b - defined_a),
        "differently": [],
    }
    if min(schema_a, schema_b) < VALUE_FREE_SCHEMA and (_has_reasons(a) or _has_reasons(b)):
        not_compared["differently"].append("report.techniques: why")
    return a2, b2, not_compared


def _free_indicators(indicators: Mapping[str, Any]) -> dict[str, Any]:
    """The IOC rows' value-free answers: the head and a digest of the whole answer."""
    out: dict[str, Any] = {}
    for key, row in indicators.items():
        if not isinstance(row, dict):
            continue
        said = str(row.get("published") or "")
        head = answer_head(said) or said
        answer = row.get("answer")
        if answer is None and said and said != head:
            # A record from before the value-free schema kept the whole answer.
            answer = digest(said)
        out[str(key)] = {"kind": row.get("kind"), "published": head or None, "answer": answer}
    return out


def _free_category(category: Any) -> str | None:
    said = str(category or "")
    if not said:
        return None
    return said if said.startswith("sha256:") else f"sha256:{digest(said)}"


def _free_techniques(techniques: Mapping[str, Any], with_why: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for tid, row in techniques.items():
        if not isinstance(row, dict):
            continue
        out[str(tid)] = {
            k: row[k] for k in ("published", "why") if k in row and (with_why or k != "why")
        }
    return out


def diff_records(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    """Every difference between two replay records of one stored run."""
    out: dict[str, Any] = {"run": a.get("run")}
    errors_a, errors_b = errors(a), errors(b)
    if errors_a or errors_b:
        out["errors"] = {"a": errors_a, "b": errors_b}
    schema_a, schema_b = schema_of(a), schema_of(b)
    schema = min(schema_a, schema_b)
    if schema_a != schema_b:
        out["schema"] = {"a": schema_a, "b": schema_b}
        a, b, not_compared = _common(a, b, schema_a, schema_b)
        if any(not_compared.values()):
            out["not_compared"] = {key: rows for key, rows in not_compared.items() if rows}
    keys_a, keys_b = flag_keys(a), flag_keys(b)
    gained = _keyed((k, c) for k, c in (keys_b - keys_a).items())
    lost = _keyed((k, c) for k, c in (keys_a - keys_b).items())
    if gained:
        out["codes_gained"] = gained
    if lost:
        out["codes_lost"] = lost
    totals = _mapping_diff(
        {
            f"{part} {code}": count
            for part, codes in (a.get("totals") or {}).items()
            for code, count in codes.items()
        },
        {
            f"{part} {code}": count
            for part, codes in (b.get("totals") or {}).items()
            for code, count in codes.items()
        },
    )
    if totals:
        out["totals"] = totals
    shapes = _mapping_diff(_answer_shapes(a, schema), _answer_shapes(b, schema))
    if shapes:
        out["answers"] = shapes
    report_a, report_b = a.get("report") or {}, b.get("report") or {}
    report: dict[str, Any] = {}
    for key in (
        "replayed",
        "verdict",
        "severity",
        "category",
        "confidence",
        "degraded",
        "degradation",
        "persistence",
        "claims_not_discussed",
        "detection_rules",
        "detection_rules_not_compiled",
    ):
        if key in report_a or key in report_b:
            value_a, value_b = report_a.get(key), report_b.get(key)
            if key == "category":
                value_a, value_b = _free_category(value_a), _free_category(value_b)
            changed = _changed(value_a, value_b)
            if changed:
                report[key] = changed
    sections_a, sections_b = report_a.get("sections") or [], report_b.get("sections") or []
    if sections_a != sections_b:
        held_a, held_b = set(sections_a), set(sections_b)
        report["sections"] = {
            "only_a": [s for s in sections_a if s not in held_b],
            "only_b": [s for s in sections_b if s not in held_a],
            "order_changed": [s for s in sections_a if s in held_b]
            != [s for s in sections_b if s in held_a],
        }
    with_why = schema >= VALUE_FREE_SCHEMA
    techniques = _mapping_diff(
        _free_techniques(report_a.get("techniques") or {}, with_why),
        _free_techniques(report_b.get("techniques") or {}, with_why),
    )
    if techniques:
        report["techniques"] = techniques
    indicators = _mapping_diff(
        _free_indicators(report_a.get("indicators") or {}),
        _free_indicators(report_b.get("indicators") or {}),
    )
    if indicators:
        report["indicators"] = indicators
    export_a, export_b = report_a.get("export") or {}, report_b.get("export") or {}
    patterns_a = set(export_a.get("attack_patterns") or [])
    patterns_b = set(export_b.get("attack_patterns") or [])
    if patterns_a != patterns_b:
        report["exported_techniques"] = {
            "only_a": sorted(patterns_a - patterns_b),
            "only_b": sorted(patterns_b - patterns_a),
        }
    objects = _mapping_diff(export_a.get("objects") or {}, export_b.get("objects") or {})
    if objects:
        report["exported_objects"] = objects
    if report:
        out["report"] = report
    judge: dict[str, Any] = {}
    for key in ("objects", "indicators_dropped"):
        changed = _changed((a.get("judge") or {}).get(key), (b.get("judge") or {}).get(key))
        if changed and ("judge" in a or "judge" in b):
            judge[key] = changed
    if judge:
        out["judge"] = judge
    environment: dict[str, Any] = {}
    env_a, env_b = a.get("environment") or {}, b.get("environment") or {}
    refused = _mapping_diff(
        env_a.get("settings_refused") or {}, env_b.get("settings_refused") or {}
    )
    if refused:
        environment["settings_refused"] = refused
    lacking_a = set(env_a.get("doors_this_tree_lacks") or [])
    lacking_b = set(env_b.get("doors_this_tree_lacks") or [])
    if lacking_a != lacking_b:
        environment["doors_this_tree_lacks"] = {
            "only_a": sorted(lacking_a - lacking_b),
            "only_b": sorted(lacking_b - lacking_a),
        }
    if environment:
        out["environment"] = environment
    corroboration = _mapping_diff(
        (a.get("corroboration") or {}).get("techniques") or {},
        (b.get("corroboration") or {}).get("techniques") or {},
    )
    if corroboration:
        out["corroboration"] = corroboration
    parts_a = {(row["part"], row["why"]) for row in a.get("not_replayed") or []}
    parts_b = {(row["part"], row["why"]) for row in b.get("not_replayed") or []}
    if parts_a != parts_b:
        out["not_replayed"] = {
            "only_a": [{"part": p, "why": w} for p, w in sorted(parts_a - parts_b)],
            "only_b": [{"part": p, "why": w} for p, w in sorted(parts_b - parts_a)],
        }
    for part in ("judge", "narrative", "composer", "tool", "fp_linter", "corroboration"):
        if part in a or part in b:
            replayed = _changed(
                (a.get(part) or {}).get("replayed"), (b.get(part) or {}).get("replayed")
            )
            if replayed:
                out.setdefault("replayed", {})[part] = replayed
    return out


# The keys of a diff that say how the comparison went rather than what differs.
_NOT_A_DIFFERENCE = frozenset({"run", "errors", "schema", "not_compared"})


def differs(diff: Mapping[str, Any]) -> bool:
    """Whether a diff names any difference between what the two refs decide."""
    return any(key not in _NOT_A_DIFFERENCE for key in diff)


def has_errors(diff: Mapping[str, Any]) -> bool:
    """Whether a part raised in either tree: the comparison is then not a decision."""
    found = diff.get("errors") or {}
    return bool(found.get("a") or found.get("b"))


def is_partial(diff: Mapping[str, Any]) -> bool:
    """Whether a part was left uncompared: a part not compared is not a decision either."""
    return any((diff.get("not_compared") or {}).values())
