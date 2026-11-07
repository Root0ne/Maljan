"""Rule engines as tools: YARA over bytes, Sigma over events, capa over code.

What is deliberately *not* here is the part the pipeline layers used to add on
top of these engines — a platform pre-filter, a confidence floor, and the
conversion of every hit into a claim of its own. A tool has no need of any of
it: an agent asking "what fired" wants every rule that fired, on its own terms,
and gets to decide what a Windows-only rule hitting a Linux sample means.

Rule corpora are loaded once per path and kept for the process lifetime — a
sidecar answers many calls and recompiling a few hundred YARA rules per call
is the difference between a tool that is usable in a loop and one that is not.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from malspark.core.logger import logger
from malspark.core.paths import get_project_root, host_paths_masked, resolve_data

# The corpora the pipeline itself ships. ``ruleset="default"`` means these; any
# other value is taken as a path, resolved against the repository root the same
# way every other data path is.
DEFAULT_YARA_RULES = "data/yara_ttp_rules.yaml"
DEFAULT_SIGMA_RULES = "data/sigma_rules"
DEFAULT_CAPA_RULES = "data/capa-rules"
DEFAULT_CAPA_SIGNATURES = "data/capa-signatures"

# How much of a matched string is worth returning. A YARA rule can match a
# multi-megabyte run, and hex-encoding it would put the whole sample in the
# tool's answer.
_MAX_MATCH_BYTES = 64

_CACHE_LOCK = threading.Lock()
# By path: the layer and the corpus's stamp when it was read (``_stamp``).
_YARA_CACHE: dict[str, tuple[int | None, Any]] = {}
_SIGMA_CACHE: dict[str, tuple[int | None, Any]] = {}


def _stamp(path: Path) -> int | None:
    """When the corpus at ``path`` last changed, ``None`` while there is none."""
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def _cached(
    cache: dict[str, tuple[int | None, Any]], path: Path, count: Callable[[Any], int]
) -> Any:
    """The layer kept for ``path``, or ``None`` when it has to be read (again).

    A layer that loaded rules is kept for the process's lifetime, as before.
    One that loaded none is kept only while the corpus is as it was read, so
    the warning its load logs is said once per change of the corpus, and one
    put in place later is read without a restart. ``count`` counts a layer's
    rules.

    "As it was read" is the corpus path's own modification time (``_stamp``),
    following a link: it changes when the path appears or goes, when a file
    corpus is rewritten, and when an entry is added to or removed from a
    directory corpus's top level. A file added or edited only inside a
    subdirectory of an existing directory leaves it as it was, so that corpus
    is read again only after a restart or ``reset_rule_caches``.
    """
    with _CACHE_LOCK:
        held = cache.get(str(path))
    if held is None:
        return None
    stamp, layer = held
    return layer if count(layer) or stamp == _stamp(path) else None


def _keep(
    cache: dict[str, tuple[int | None, Any]], path: Path, stamp: int | None, layer: Any
) -> None:
    with _CACHE_LOCK:
        cache[str(path)] = (stamp, layer)


# The environment names that override where "default" points. This is the whole
# configuration surface for the rule corpora now: the sidecar that runs these
# tools is handed them in ``core.mcp.servers.analysis.env``, so an operator with
# their own rules points the server at them and nothing in the library reads
# ``Settings`` to find a rule file. capa's is handed to a sidecar of this
# repository from the core setting its data declaration names
# (``tools.sidecar_needs.handed_env``), so the server reads the operator's rules.
YARA_RULES_ENV = "MALSPARK_YARA_RULES_DIR"
SIGMA_RULES_ENV = "MALSPARK_SIGMA_RULES_DIR"
CAPA_RULES_ENV = "MALSPARK_CAPA_RULES_DIR"


def corpus_roots() -> tuple[Path, ...]:
    """Where a rule corpus may live: the shipped ``data`` tree, and the operator's own.

    The operator's are whatever the two environment names point at, because
    those are set on the server rather than passed to it — the same
    distinction ``resolve_data`` draws when it leaves an absolute path alone.

    Exported for the tool server, which holds a model-chosen ``ruleset`` to
    them. An in-process caller passes its own corpus and is not held to
    anything: the trust boundary is the server, not this module.
    """
    roots = [resolve_data("data")]
    for env_var in (YARA_RULES_ENV, SIGMA_RULES_ENV):
        override = os.environ.get(env_var, "").strip()
        if override:
            roots.append(resolve_data(override))
    return tuple(roots)


def _not_loaded(
    tool: str,
    path: Path,
    corpus: str,
    *,
    chosen: bool = False,
    unread: list[dict[str, str]] | None = None,
    files: int = 0,
) -> dict[str, Any]:
    """The answer of a rule engine that loaded no rule: it did not run.

    An empty corpus scans nothing, and "0 hits" from it reads as a sample no
    rule matched. It is a failure with the code a missing library has
    (``missing_dependency``), so the run that called it is degraded and the
    check before a job names the same path (``sidecar_needs``), with the
    declared data path's remedy (``capabilities.Requirement.remedy``).
    ``corpus`` is the attribute of ``sidecar_needs`` that declares it.
    ``unread`` are the corpus's files that could not be read, of ``files``
    in all: the answer names them (``files_not_loaded``) and says that none
    could be read, or that the rest held no rule, rather than that the corpus
    is missing.
    ``chosen`` is a ruleset the caller named in place of the corpus (a model's
    ``ruleset`` argument): its own argument, not the host, is what to change.
    """
    from malspark.tools import sidecar_needs
    from malspark.tools.errors import BAD_ARGUMENT, MISSING_DEPENDENCY, tool_error

    need = getattr(sidecar_needs, corpus)
    # Inside the project the path is shown from its root, which is how the
    # check before a job names it; one outside is named by what named it, as
    # the check does (``Requirement.installed``): the host's layout is not
    # the reader's.
    try:
        shown = Path(os.path.abspath(path)).relative_to(get_project_root()).as_posix()
    except ValueError:
        overridden = bool(need.override and os.environ.get(need.override, "").strip())
        named = need.override if overridden else need.setting or need.override
        shown = "the ruleset named" if chosen else f"the path {named} names"
    message = f"no rule was loaded from {shown}, which is missing or holds none, so no rule was run"
    if unread:
        said = (
            f"none of its {files} rule files could be read"
            if len(unread) >= files
            else f"{len(unread)} of its {files} rule files could not be read and the rest hold "
            "no rule"
        )
        message = f"no rule was loaded from {shown}: {said}, so no rule was run"
    if chosen:
        answer = tool_error(
            BAD_ARGUMENT,
            message,
            tool=tool,
            remediation="name a ruleset that holds rules, or 'default' for the platform's corpus",
        )
    else:
        answer = tool_error(MISSING_DEPENDENCY, message, tool=tool, remediation=need.remedy)
    if unread:
        answer["files_not_loaded"] = list(unread)
    return answer


def _resolve_ruleset(ruleset: str, default: str, env_var: str = "") -> Path:
    """The corpus path for a ``ruleset`` argument.

    ``"default"`` means the environment's corpus when one is set, otherwise the
    one the pipeline ships. Any other value is a path, resolved against the
    repository root the same way every other data path is.
    """
    if ruleset not in ("", "default"):
        return resolve_data(ruleset)
    override = os.environ.get(env_var, "").strip() if env_var else ""
    return resolve_data(override or default)


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------


def _yara_layer(ruleset: str) -> Any:
    """The compiled layer for one corpus, built once per path (``_cached``).

    A corpus is one rule file, or a directory whose ``*.yml`` and ``*.yaml``
    files are read in name order, as the override's name says it may be: each
    file's rules are parsed, joined and compiled once. A file of a directory
    that cannot be read is skipped with a warning naming it, and named in the
    scan's answer (``files_not_loaded``): an operator's one malformed file
    costs that file's rules, not every other file's, and is never silent. A
    lone file that cannot be read raises, as before, and the scan says so.
    """
    path = _resolve_ruleset(ruleset, DEFAULT_YARA_RULES, YARA_RULES_ENV)
    cached = _cached(_YARA_CACHE, path, lambda layer: len(layer._rules))
    if cached is not None:
        return cached
    from malspark.analysis.yara_layer import YaraLayer

    stamp = _stamp(path)
    skipped: list[dict[str, str]] = []
    if path.is_file():
        layer = YaraLayer.from_yaml(path)
    elif path.is_dir():
        parsed = []
        for rule_file in _rule_files(path):
            try:
                parsed.extend(YaraLayer.rules_from_yaml(rule_file))
            except Exception as exc:  # noqa: BLE001 — one bad file costs that file only
                said = host_paths_masked(f"{type(exc).__name__}: {exc}")
                logger.warning("yara_scan: rule file %s not loaded (%s)", rule_file.name, said)
                skipped.append({"file": rule_file.relative_to(path).as_posix(), "error": said})
        layer = YaraLayer(rules=parsed)
    else:
        layer = YaraLayer(rules=[])
    layer.files_not_loaded = skipped
    _keep(_YARA_CACHE, path, stamp, layer)
    return layer


def _rule_files(path: Path) -> list[Path]:
    """The rule files of a directory corpus, in name order; none for anything else."""
    if not path.is_dir():
        return []
    return sorted([*path.rglob("*.yml"), *path.rglob("*.yaml")])


def reset_rule_caches() -> None:
    """Drop the compiled corpora. For tests and for a rule-file reload."""
    with _CACHE_LOCK:
        _YARA_CACHE.clear()
        _SIGMA_CACHE.clear()


def yara_scan(
    path: str | None = None,
    text: str | None = None,
    ruleset: str = "default",
    timeout_s: int = 60,
) -> dict[str, Any]:
    """Every rule in the corpus that fires on the bytes, with where it fired.

    Exactly one of ``path`` and ``text`` is the target. ``filtered`` is always
    zero and is reported anyway: the pipeline's own YARA layer drops
    platform-incompatible rules before scanning and reports how many, and a
    caller comparing the two needs to see that this tool dropped none.
    """
    if (path is None) == (text is None):
        return {"error": "give exactly one of path and text", "tool": "yara_scan"}
    if path is not None:
        target = Path(path)
        if not target.is_file():
            return {"error": f"no such file: {path}", "tool": "yara_scan"}
        data = target.read_bytes()
    else:
        data = (text or "").encode("utf-8", errors="replace")

    try:
        layer = _yara_layer(ruleset)
    except Exception as exc:  # noqa: BLE001 — a bad corpus is an answer, not a crash
        return {
            "error": f"ruleset load failed: {type(exc).__name__}: {exc}",
            "tool": "yara_scan",
        }
    rule_count = len(getattr(layer, "_rules", []) or [])
    if not rule_count:
        corpus = _resolve_ruleset(ruleset, DEFAULT_YARA_RULES, YARA_RULES_ENV)
        unread = list(getattr(layer, "files_not_loaded", None) or [])
        return _not_loaded(
            "yara_scan",
            corpus,
            "YARA_RULES",
            chosen=ruleset not in ("", "default"),
            unread=unread,
            files=len(_rule_files(corpus)) if unread else 0,
        )
    compiled = getattr(layer, "_yara_rules", None)
    answer: dict[str, Any] = {"rule_count": rule_count, "filtered": 0}
    skipped = getattr(layer, "files_not_loaded", None)
    if skipped:
        answer["files_not_loaded"] = list(skipped)
    if compiled is not None:
        try:
            hits = compiled.match(data=data, timeout=max(1, int(timeout_s)))
        except Exception as exc:  # noqa: BLE001 — the engine's failure is stated, not hidden
            logger.warning("yara_scan: native scan failed (%s); literal fallback used.", exc)
            answer["native_error"] = f"{type(exc).__name__}: {exc}"
        else:
            native: dict[str, Any] = {
                "matches": _yara_native_matches(layer, hits),
                "engine": "yara",
                **answer,
            }
            # A nocase string or an import hash the engine folds by a broken
            # locale was not checked as written: say so beside the answer.
            from malspark.core.ctype_locale import yara_case_folding_problem

            problem = yara_case_folding_problem()
            if problem:
                native["engine_note"] = problem
            return native
    # The literal fallback reads each rule's strings, not its condition: a
    # rule it does not list was not checked by the YARA engine, and an
    # engine failure (a timeout among them) is named in ``native_error``
    # rather than passed off as the engine's own empty answer.
    answer["engine"] = "literal_fallback"
    answer["engine_note"] = LITERAL_FALLBACK_NOTE
    return {"matches": _yara_regex_matches(layer, data), **answer}


# What an answer from the literal fallback says about what it checked.
LITERAL_FALLBACK_NOTE = (
    "the YARA engine did not scan: each rule's literal strings were searched instead, "
    "so a rule's condition was not checked and a rule not listed is not shown absent"
)


def _yara_native_matches(layer: Any, hits: Any) -> list[dict[str, Any]]:
    """yara-python's own match objects, flattened to plain rows."""
    id_map: dict[str, str] = getattr(layer, "_yara_id_map", {}) or {}
    rows: list[dict[str, Any]] = []
    for hit in hits:
        strings: list[dict[str, Any]] = []
        for string_match in hit.strings:
            for instance in getattr(string_match, "instances", []) or []:
                blob = bytes(getattr(instance, "matched_data", b"") or b"")
                strings.append(
                    {
                        "offset": int(getattr(instance, "offset", 0) or 0),
                        "identifier": str(string_match.identifier),
                        "data_hex": blob[:_MAX_MATCH_BYTES].hex(),
                        # The match's own length, so a hex cut at the bound
                        # reads as the first bytes of a longer match.
                        "length": len(blob),
                    }
                )
        rows.append(
            {
                "rule": id_map.get(hit.rule, hit.rule),
                "namespace": str(getattr(hit, "namespace", "default")),
                "tags": [str(t) for t in (getattr(hit, "tags", []) or [])],
                "meta": {str(k): v for k, v in (getattr(hit, "meta", {}) or {}).items()},
                "strings": strings,
            }
        )
    return rows


def _identifier_for(rule: Any, pattern: str) -> str:
    """The identifier the compiled engine gives this string of this rule."""
    patterns = list(getattr(rule, "patterns", ()) or ())
    if pattern in patterns:
        return str(patterns.index(pattern))
    group = list(getattr(rule, "all_of", ()) or ())
    return f"a{group.index(pattern)}" if pattern in group else "0"


def _yara_regex_matches(layer: Any, data: bytes) -> list[dict[str, Any]]:
    """The regex fallback the layer keeps for a box without yara-python.

    Reports the same row shape, offsets included: the fallback searches the
    same bytes, so it knows where each literal was found even though it never
    compiled a YARA rule. Each offset is a byte offset into ``data`` and each
    ``data_hex`` the bytes found there: the bytes are decoded with every
    undecodable byte kept as one escaped character, so the text maps back to
    the bytes exactly. A replacement character used to stand for one or more
    bytes, and the offsets were character indices that drifted from the file.
    """
    decoded = data.decode("utf-8", errors="surrogateescape")
    rows: list[dict[str, Any]] = []
    for rule in getattr(layer, "_rules", []) or []:
        rule_id = rule.id
        # Which strings count is the layer's answer, not a second copy of the
        # rule kept here: a together-group fires only whole, and a copy that
        # did not know that could not fire the pair form at all. What this
        # function adds is where each of them was found.
        fired = layer.literal_matches(rule, decoded)
        strings: list[dict[str, Any]] = []
        for pattern in fired:
            # The byte offset is carried from match to match, so each match
            # encodes only the text since the one before it.
            chars = 0
            at = 0
            for match in re.finditer(re.escape(pattern), decoded, re.IGNORECASE):
                at += len(decoded[chars : match.start()].encode("utf-8", "surrogateescape"))
                chars = match.start()
                raw = match.group().encode("utf-8", "surrogateescape")
                strings.append(
                    {
                        "offset": at,
                        "identifier": f"${_identifier_for(rule, pattern)}",
                        "data_hex": raw[:_MAX_MATCH_BYTES].hex(),
                        "length": len(raw),
                    }
                )
        if not strings:
            continue
        rows.append(
            {
                "rule": rule_id,
                "namespace": "default",
                "tags": [],
                "meta": {
                    "technique_id": getattr(rule, "technique_id", ""),
                    "description": getattr(rule, "description", ""),
                },
                "strings": strings,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------


def _sigma_layer(ruleset: str) -> Any:
    """The layer for one corpus, built once per path (``_cached``)."""
    path = _resolve_ruleset(ruleset, DEFAULT_SIGMA_RULES, SIGMA_RULES_ENV)
    cached = _cached(_SIGMA_CACHE, path, lambda layer: int(layer.rule_count))
    if cached is not None:
        return cached
    from malspark.analysis.sigma_layer import SigmaLayer

    stamp = _stamp(path)
    layer = SigmaLayer.from_rules_dir(path)
    _keep(_SIGMA_CACHE, path, stamp, layer)
    return layer


def _sigma_not_loaded(layer: Any, ruleset: str, tool: str) -> dict[str, Any] | None:
    """The answer for a Sigma corpus that loaded no rule, else ``None`` (``_not_loaded``)."""
    if int(getattr(layer, "rule_count", 0)):
        return None
    path = _resolve_ruleset(ruleset, DEFAULT_SIGMA_RULES, SIGMA_RULES_ENV)
    return _not_loaded(tool, path, "SIGMA_RULES", chosen=ruleset not in ("", "default"))


def sigma_match(events: list[dict[str, Any]], ruleset: str = "default") -> dict[str, Any]:
    """Every Sigma rule in the corpus that matches one of the events.

    No platform pre-filter: a rule declaring ``product: windows`` is evaluated
    against the events it is given, and the row says which product it declared
    so the caller can discount it themselves.
    """
    if not isinstance(events, list):
        return {"error": "events must be a list of objects", "tool": "sigma_match"}
    try:
        layer = _sigma_layer(ruleset)
    except Exception as exc:  # noqa: BLE001
        return {
            "error": f"ruleset load failed: {type(exc).__name__}: {exc}",
            "tool": "sigma_match",
        }
    absent = _sigma_not_loaded(layer, ruleset, "sigma_match")
    if absent is not None:
        return absent
    normalised = [
        {str(k): str(v) for k, v in row.items()} for row in events if isinstance(row, dict)
    ]
    return _sigma_result(layer, layer.scan(normalised))


def _sigma_result(layer: Any, scan: Any) -> dict[str, Any]:
    """The tool's answer for one scan.

    A rule the corpus carries that raises while being evaluated (a value whose
    regex does not compile, a condition pySigma cannot parse) is skipped and
    counted, and the scan continues with the rest of the corpus.
    """
    rows: list[dict[str, Any]] = []
    for _position, rule, matched in scan.hits:
        logsource = rule.logsource
        rows.append(
            {
                "rule": str(rule.id) if rule.id else "unknown",
                "title": str(rule.title),
                "level": str(rule.level.name).lower() if rule.level else "",
                "logsource": {
                    "product": str(logsource.product or "") if logsource else "",
                    "category": str(logsource.category or "") if logsource else "",
                    "service": str(logsource.service or "") if logsource else "",
                },
                "tags": [str(tag) for tag in rule.tags],
                "matched_fields": matched,
            }
        )
    if scan.rule_errors:
        logger.warning(
            "sigma_match: %d of %d rules could not be evaluated; the scan used the rest.",
            scan.rule_errors,
            int(getattr(layer, "rule_count", 0)),
        )
    result = {
        "matches": rows,
        "rule_count": int(getattr(layer, "rule_count", 0)),
        "rule_errors": scan.rule_errors,
    }
    return result


def sandbox_events(report: dict[str, Any] | None) -> list[dict[str, str]]:
    """The sandbox report's document as Sysmon-shaped events, ready for ``sigma_match``.

    ``report`` is the neutral sandbox report's document
    (``schemas.sandbox_document``), whichever sandbox produced it.

    Kept next to ``sigma_match`` rather than inside the sandbox tools: the
    event shape exists to satisfy Sigma's field vocabulary, so the two move
    together or a rule stops matching for a reason nobody can find.
    """
    from malspark.analysis.sigma_layer import build_events_from_sandbox

    return build_events_from_sandbox(report)


def _runs(indices: list[int]) -> list[list[int]]:
    """Ascending positions as ``[first, last]`` runs of consecutive ones."""
    runs: list[list[int]] = []
    for index in indices:
        if runs and index == runs[-1][1] + 1:
            runs[-1][1] = index
        else:
            runs.append([index, index])
    return runs


def sigma_match_sandbox(report: dict[str, Any] | None, ruleset: str = "default") -> dict[str, Any]:
    """``sigma_match`` over the events derived from a sandbox report.

    The events are read as what the sandbox collected
    (``sigma_layer.SandboxEvents.contexts``): a rule meets only the events of
    its logsource category, and fires only where its condition is true. The
    answer says what could not be decided: ``not_evaluable`` gives, for the
    events (by position, as ``[first, last]`` runs) alike in it, how many
    rules that did not fire ended unknown on each and the fields that made
    them so (a field not collected, or ``"<field> path"`` where the image has
    no path); ``no_events_of`` counts, per logsource the report holds no
    events of, the rules not run.
    """
    from malspark.analysis.sigma_layer import NOT_EVALUABLE, read_sandbox_events

    read = read_sandbox_events(report)
    events = read.events
    try:
        layer = _sigma_layer(ruleset)
    except Exception as exc:  # noqa: BLE001
        return {
            "error": f"ruleset load failed: {type(exc).__name__}: {exc}",
            "tool": "sigma_match",
            "event_count": len(events),
        }
    absent = _sigma_not_loaded(layer, ruleset, "sigma_match_sandbox")
    if absent is not None:
        return {**absent, "event_count": len(events)}
    scan = layer.scan([dict(event) for event in events], contexts=read.contexts())
    result = _sigma_result(layer, scan)
    result["event_count"] = len(events)
    if scan.not_evaluable:
        # Events alike in what was undecided share one row, their positions as
        # [first, last] runs: complete, and as long as the distinct shapes.
        shapes: dict[tuple[int, tuple[tuple[str, int], ...]], list[int]] = {}
        distinct: set[int] = set()
        for index in sorted(scan.not_evaluable):
            held = scan.not_evaluable[index]
            fields: dict[str, int] = {}
            for position, names in held:
                distinct.add(position)
                for name in names:
                    fields[name] = fields.get(name, 0) + 1
            shapes.setdefault((len(held), tuple(sorted(fields.items()))), []).append(index)
        rows = [
            {"events": _runs(indices), "rules": count, "fields": dict(fields_held)}
            for (count, fields_held), indices in shapes.items()
        ]
        result["not_evaluable"] = {"note": NOT_EVALUABLE, "rules": len(distinct), "rows": rows}
    if scan.no_events_of:
        result["no_events_of"] = dict(sorted(scan.no_events_of.items()))
    return result


# ---------------------------------------------------------------------------
# capa
# ---------------------------------------------------------------------------


def capa(
    path: str,
    timeout_s: int | None = None,
    backend: str = "auto",
    rules_dir: str = "default",
    signatures_dir: str = DEFAULT_CAPA_SIGNATURES,
    scratch: str | Path | None = None,
) -> dict[str, Any]:
    """The capabilities capa finds, each with its ATT&CK and MBC metadata.

    capa runs in a child process of its own with the caller's budget, exactly
    as the provider runs it (``capa_yara.run_capa_document``; ``None``, the
    default, is no wall clock of its own): vivisect's disassembly loop has no
    cancellation point, so a thread-based timeout can report an overrun while
    the work keeps running. A child process can actually be killed, and on
    expiry this one is. It gets none of this process's environment.
    ``scratch`` is the directory the run's own directory goes in, which the
    triage pack opens in its job's staging directory; the sidecar passes none
    and joins its own job directory.

    ``library_functions`` names the functions capa's signatures identified as
    library code, or says why none were looked for (``capa_library_functions``);
    an empty ``signatures_dir`` runs without library identification.
    ``rules_dir="default"``, as the sidecar passes, is the environment's corpus
    when one is set (``CAPA_RULES_ENV``), else the one the pipeline fetches; an
    empty one names no path, as the check before a job says of it.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "capa"}
    if not rules_dir.strip():
        return {"error": "no capa rules directory is named", "tool": "capa"}
    rules = _resolve_ruleset(rules_dir, DEFAULT_CAPA_RULES, CAPA_RULES_ENV)
    if not rules.is_dir() or not any(rules.rglob("*.yml")):
        return _not_loaded("capa", rules, "CAPA_RULES")

    from malspark.providers.static.capa_yara import (
        _BACKEND_NAMES,
        run_capa_document,
        signatures_argument,
    )

    backend_name = _BACKEND_NAMES.get(backend, "BACKEND_VIV")
    document = run_capa_document(
        sample_path=str(target),
        rules_dir=str(rules),
        signatures_dir=signatures_argument(signatures_dir),
        backend_name=backend_name,
        timeout_seconds=None if timeout_s is None else max(1, int(timeout_s)),
        scratch=scratch,
    )
    if document is None:
        return {
            "error": (
                "capa produced no result within its budget, or its worker exited without an "
                "answer (the server log says which)"
            ),
            "tool": "capa",
        }
    return {
        "capabilities": _capa_capabilities(document),
        "meta": _capa_meta(document),
        "function_starts": capa_function_starts(document),
        "library_functions": capa_library_functions(document),
    }


def _capa_capabilities(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a capa ResultDocument's rule map into one row per rule.

    ``addresses`` is where each match is, in capa's order, so a reader can
    take a rule to the function, basic block or instruction that matched it:
    an address inside the image as its offset from the image base capa
    analysed at, which is the number a disassembler that loaded the file
    elsewhere agrees with (FLOSS's ``function_rva`` is the same kind of
    number). A match with no address — a file-scope rule — has none listed.
    """
    base = _capa_base_address(document)
    rows: list[dict[str, Any]] = []
    for rule in (document.get("rules") or {}).values():
        if not isinstance(rule, dict):
            continue
        meta = rule.get("meta") or {}
        scopes = rule.get("matches") or []
        addresses: list[str] = []
        for match in scopes:
            located = match[0] if isinstance(match, list | tuple) and match else None
            where = _capa_address(located, base)
            if where and where not in addresses:
                addresses.append(where)
        rows.append(
            {
                "namespace": str(meta.get("namespace") or ""),
                "rule": str(meta.get("name") or ""),
                "attck": [_capa_attck(entry) for entry in (meta.get("attack") or [])],
                "mbc": [_capa_mbc(entry) for entry in (meta.get("mbc") or [])],
                "match_count": len(scopes),
                "addresses": addresses,
            }
        )
    rows.sort(key=lambda r: (r["namespace"], r["rule"]))
    return rows


def capa_function_starts(document: dict[str, Any]) -> list[str]:
    """The start of every function capa analysed or identified as library code.

    Read from the document's feature counts, which list each function capa
    matched rules in, and then from its library functions: a function capa's
    signatures identify as library code is matched against no rule and left
    out of the counts, and without its start the function before it would
    seem to run on over it. Each start is its offset from the image base, kept
    only when it is inside the image and capa names the base, so it is the
    number a disassembler agrees with; the list says where functions start,
    not where they end, in address order.
    """
    base = _capa_base_address(document)
    if base is None:
        return []
    analysis = (document.get("meta") or {}).get("analysis") or {}
    counts = analysis.get("feature_counts") or {}
    starts: list[str] = []
    seen: set[str] = set()
    for row in [*(counts.get("functions") or []), *(analysis.get("library_functions") or [])]:
        address = row.get("address") if isinstance(row, dict) else None
        where = _capa_address(address, base)
        if where and where.startswith("0x") and where not in seen:
            seen.add(where)
            starts.append(where)
    return sorted(starts, key=lambda start: int(start, 16))


# What a library function's address says when capa's address for it is not a
# place in the image (a .NET token, no address at all), as the model reads it.
LIBRARY_FUNCTION_NOT_IN_IMAGE = "no: not a place in the image"


def capa_library_functions(document: dict[str, Any]) -> list[dict[str, str]] | str:
    """The functions capa's signatures identified as library code, or why none were looked for.

    Each is its start (as ``capa_function_starts`` gives it) and the name its
    signature gives it, so a reader can leave runtime and library code unread.
    An empty list means capa looked and found none. When it did not look (no
    signature directory, or capa loads no signatures for this format and
    backend), the reason stands in place of the list, so its absence is never
    read as "none".
    """
    from malspark.providers.static.capa_child import LIBRARY_FUNCTIONS_UNSTATED, NOT_IDENTIFIED_KEY

    if NOT_IDENTIFIED_KEY not in document:
        return LIBRARY_FUNCTIONS_UNSTATED
    not_identified = document[NOT_IDENTIFIED_KEY]
    if not_identified is not None:
        return str(not_identified)
    base = _capa_base_address(document)
    analysis = (document.get("meta") or {}).get("analysis") or {}
    found: list[dict[str, str]] = []
    for row in analysis.get("library_functions") or []:
        if not isinstance(row, dict):
            continue
        where = _capa_address(row.get("address"), base)
        found.append(
            {
                "address": where or LIBRARY_FUNCTION_NOT_IN_IMAGE,
                "name": str(row.get("name") or ""),
            }
        )
    return found


def _capa_base_address(document: dict[str, Any]) -> int | None:
    """The image base capa analysed at, when its document names one."""
    analysis = (document.get("meta") or {}).get("analysis") or {}
    base = analysis.get("base_address")
    if isinstance(base, dict) and base.get("type") == "absolute":
        value = base.get("value")
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    return None


def _capa_address(address: Any, base: int | None) -> str | None:
    """One match's address as a reader takes it to a disassembler, or ``None``.

    capa writes an address as ``{"type": ..., "value": ...}``. An absolute
    one is given as its offset from the image base when capa names the base
    (the offset is what a disassembler agrees with) and marked ``va`` when it
    does not; a file offset is marked ``file``; a relative one is already an
    offset. Any other kind — no address, a .NET token, a process or a thread
    of a dynamic analysis — is not a place in the image and is left out.
    """
    if not isinstance(address, dict):
        return None
    kind = address.get("type")
    value = address.get("value")
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    if kind == "absolute":
        if base is not None and value >= base:
            return hex(value - base)
        return f"va {hex(value)}"
    if kind == "relative":
        return hex(value)
    if kind == "file":
        return f"file {hex(value)}"
    return None


def _capa_attck(entry: Any) -> str:
    """``Defense Evasion::Obfuscated Files or Information [T1027]`` from a dict."""
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return str(entry)
    tid = entry.get("id") or ""
    parts = [str(p) for p in (entry.get("parts") or []) if p]
    tactic = str(entry.get("tactic") or "")
    label = "::".join([p for p in [tactic, *parts] if p])
    return f"{label} [{tid}]" if tid else label


def _capa_mbc(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return str(entry)
    mid = entry.get("id") or ""
    parts = [str(p) for p in (entry.get("parts") or []) if p]
    label = "::".join([str(entry.get("objective") or ""), *parts]).strip(":")
    return f"{label} [{mid}]" if mid else label


def _capa_meta(document: dict[str, Any]) -> dict[str, Any]:
    meta = document.get("meta") or {}
    analysis = meta.get("analysis") or {}
    sample = meta.get("sample") or {}
    return {
        "capa_version": str(meta.get("version") or ""),
        "format": str(analysis.get("format") or ""),
        "arch": str(analysis.get("arch") or ""),
        "os": str(analysis.get("os") or ""),
        "rule_count": len(document.get("rules") or {}),
        "sha256": str(sample.get("sha256") or ""),
    }
