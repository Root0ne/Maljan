"""Rule engines as tools: YARA over bytes, Sigma over events, capa over code.

What is deliberately *not* here is the part the pipeline layers add on top of
these engines — the platform pre-filter, the confidence floor, the conversion
into a synthetic ``AgentISR``. Those exist because the cascade needs a
comparable number from every layer. A tool has no such need: an agent asking
"what fired" wants every rule that fired, on its own terms, and gets to decide
what a Windows-only rule hitting a Linux sample means.

Rule corpora are loaded once per path and kept for the process lifetime — a
sidecar answers many calls and recompiling a few hundred YARA rules per call
is the difference between a tool that is usable in a loop and one that is not.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.core.paths import resolve_data

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
_YARA_CACHE: dict[str, Any] = {}
_SIGMA_CACHE: dict[str, Any] = {}


def _resolve_ruleset(ruleset: str, default: str) -> Path:
    return resolve_data(default if ruleset in ("", "default") else ruleset)


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------


def _yara_layer(ruleset: str) -> Any:
    """The compiled layer for one corpus, built once per path."""
    path = _resolve_ruleset(ruleset, DEFAULT_YARA_RULES)
    key = str(path)
    with _CACHE_LOCK:
        cached = _YARA_CACHE.get(key)
        if cached is not None:
            return cached
    from maljan.analysis.yara_layer import YaraLayer

    layer = YaraLayer.from_yaml(path) if path.is_file() else YaraLayer(rules=[])
    with _CACHE_LOCK:
        _YARA_CACHE[key] = layer
    return layer


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
    compiled = getattr(layer, "_yara_rules", None)
    if compiled is not None:
        matches = _yara_native_matches(compiled, layer, data, timeout_s)
    else:
        matches = _yara_regex_matches(layer, data)
    return {"matches": matches, "rule_count": rule_count, "filtered": 0}


def _yara_native_matches(
    compiled: Any, layer: Any, data: bytes, timeout_s: int
) -> list[dict[str, Any]]:
    """yara-python's own match objects, flattened to plain rows."""
    try:
        hits = compiled.match(data=data, timeout=max(1, int(timeout_s)))
    except Exception as exc:  # noqa: BLE001
        logger.warning("yara_scan: native scan failed (%s); falling back to regex.", exc)
        return _yara_regex_matches(layer, data)
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


def _yara_regex_matches(layer: Any, data: bytes) -> list[dict[str, Any]]:
    """The regex fallback the layer keeps for a box without yara-python.

    Reports the same row shape, offsets included: the fallback searches the
    same bytes, so it knows where each literal was found even though it never
    compiled a YARA rule.
    """
    compiled: dict[str, list[Any]] = getattr(layer, "_compiled", {}) or {}
    rules_by_id = {rule.id: rule for rule in getattr(layer, "_rules", []) or []}
    decoded = data.decode("utf-8", errors="replace")
    rows: list[dict[str, Any]] = []
    for rule_id, patterns in compiled.items():
        rule = rules_by_id.get(rule_id)
        strings: list[dict[str, Any]] = []
        for index, pattern in enumerate(patterns):
            for match in pattern.finditer(decoded):
                strings.append(
                    {
                        "offset": match.start(),
                        "identifier": f"${index}",
                        "data_hex": match.group()
                        .encode("utf-8", errors="replace")[:_MAX_MATCH_BYTES]
                        .hex(),
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
    path = _resolve_ruleset(ruleset, DEFAULT_SIGMA_RULES)
    key = str(path)
    with _CACHE_LOCK:
        cached = _SIGMA_CACHE.get(key)
        if cached is not None:
            return cached
    from maljan.analysis.sigma_layer import SigmaLayer

    layer = SigmaLayer.from_rules_dir(path)
    with _CACHE_LOCK:
        _SIGMA_CACHE[key] = layer
    return layer


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
    normalised = [
        {str(k): str(v) for k, v in row.items()} for row in events if isinstance(row, dict)
    ]
    rows: list[dict[str, Any]] = []
    for rule, evaluator in getattr(layer, "_evaluators", []) or []:
        for event in normalised:
            # A rule the corpus carries with no parseable detection block
            # raises inside pySigma rather than evaluating to "no match". One
            # such rule must not take the whole corpus down with it, so the
            # rule is skipped and the scan continues.
            try:
                matched = evaluator.evaluate(event, strict=True)
            except Exception as exc:  # noqa: BLE001
                logger.debug("sigma_match: rule %s could not be evaluated (%s).", rule.id, exc)
                break
            if matched is None:
                continue
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
            break  # a rule fires at most once per batch
    return {"matches": rows, "rule_count": int(getattr(layer, "rule_count", 0))}


def sandbox_events(report: dict[str, Any] | None) -> list[dict[str, str]]:
    """The sandbox report as Sysmon-shaped events, ready for ``sigma_match``.

    Kept next to ``sigma_match`` rather than inside the sandbox tools: the
    event shape exists to satisfy Sigma's field vocabulary, so the two move
    together or a rule stops matching for a reason nobody can find.
    """
    from maljan.analysis.sigma_layer import build_events_from_sandbox

    return build_events_from_sandbox(report)


def sigma_match_sandbox(report: dict[str, Any] | None, ruleset: str = "default") -> dict[str, Any]:
    """``sigma_match`` over the events derived from a sandbox report."""
    events = sandbox_events(report)
    result = sigma_match([dict(event) for event in events], ruleset=ruleset)
    result["event_count"] = len(events)
    return result


# ---------------------------------------------------------------------------
# capa
# ---------------------------------------------------------------------------


def capa(
    path: str,
    timeout_s: int = 300,
    backend: str = "auto",
    rules_dir: str = DEFAULT_CAPA_RULES,
    signatures_dir: str = DEFAULT_CAPA_SIGNATURES,
) -> dict[str, Any]:
    """The capabilities capa finds, each with its ATT&CK and MBC metadata.

    capa runs in a spawned subprocess with a hard budget, exactly as the
    provider runs it: vivisect's disassembly loop has no cancellation point, so
    a thread-based timeout can report an overrun while the work keeps running.
    A child process can actually be killed, and on expiry this one is.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "capa"}
    rules = resolve_data(rules_dir)
    if not rules.is_dir() or not any(rules.rglob("*.yml")):
        return {"error": f"capa rules directory {rules} is missing or empty", "tool": "capa"}

    from maljan.providers.static.capa_yara import _BACKEND_NAMES, run_capa_document

    backend_name = _BACKEND_NAMES.get(backend, "BACKEND_VIV")
    document = run_capa_document(
        sample_path=str(target),
        rules_dir=str(rules),
        signatures_dir=str(resolve_data(signatures_dir)),
        backend_name=backend_name,
        timeout_seconds=max(1, int(timeout_s)),
    )
    if document is None:
        return {"error": "capa produced no result within its budget", "tool": "capa"}
    return {"capabilities": _capa_capabilities(document), "meta": _capa_meta(document)}


def _capa_capabilities(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a capa ResultDocument's rule map into one row per rule."""
    rows: list[dict[str, Any]] = []
    for rule in (document.get("rules") or {}).values():
        if not isinstance(rule, dict):
            continue
        meta = rule.get("meta") or {}
        scopes = rule.get("matches") or []
        rows.append(
            {
                "namespace": str(meta.get("namespace") or ""),
                "rule": str(meta.get("name") or ""),
                "attck": [_capa_attck(entry) for entry in (meta.get("attack") or [])],
                "mbc": [_capa_mbc(entry) for entry in (meta.get("mbc") or [])],
                "match_count": len(scopes),
            }
        )
    rows.sort(key=lambda r: (r["namespace"], r["rule"]))
    return rows


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
