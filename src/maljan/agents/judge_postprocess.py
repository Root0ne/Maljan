"""Judge bundle post-processor.

Single helper that runs after the verdict LLM returns a parsed bundle
``dict`` and before :class:`maljan.schemas.stix_models.Bundle` validation.
Three jobs, all defensive:

* ``J-01`` — replace placeholder / non-UUID STIX IDs the LLM smuggled in
  from the example schema (``malware--12345678-1234-1234-1234-123456789012``
  or non-UUID ``attack-pattern--T1497``) with spec-compliant UUIDs and
  rewrite every cross-reference so the bundle stays internally consistent.
* ``J-02`` — drop ``Indicator`` SDOs whose STIX pattern value does not
  appear verbatim in the deterministic evidence corpus (interesting
  strings + sandbox observations). Eliminates the hallucinated
  ``[domain-name:value = 'c2-beacon.net']`` class of artefact.
* ``REP-01`` — back-fill ``external_references`` on each ``AttackPattern``
  SDO with the canonical MITRE ATT&CK URL when the LLM left it empty.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from maljan.agents._indicator_denylists import (
    COMPILE_ARTIFACT_RE,
    FOREIGN_CLASS_REF_RE,
    IOC_FILE_EXTENSIONS,
    IOC_OS_RESOURCE_PREFIXES,
    MAX_FILE_NAME_INDICATORS,
    URL_DENY_HOSTS,
)
from maljan.core.logger import logger

# UUID5 namespace for ATT&CK technique IDs — same value on every run so a
# downstream consumer can dedupe ``attack-pattern--<uuid5>`` across reports.
_MITRE_NS = uuid.UUID("6ba7b815-9dad-11d1-80b4-00c04fd430c8")

# Strict ``<type>--<uuid4>`` validation. Accepts any UUID variant
# (1/3/4/5) — STIX 2.1 only requires the canonical 8-4-4-4-12 hex shape.
_STIX_ID_RE = re.compile(
    r"^(?P<type>[a-z][a-z0-9-]+)--"
    r"(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)

# The literal placeholder UUID found in this codebase's prompt example.
_PLACEHOLDER_UUID = "12345678-1234-1234-1234-123456789012"

# Curated technique ID → (display name, URL) map. Extend over time; the
# back-fill is best-effort and falls back to a deterministic URL when the
# technique isn't here.
_MITRE_LOOKUP: dict[str, tuple[str, str]] = {
    "T1006": ("Direct Volume Access", "https://attack.mitre.org/techniques/T1006/"),
    "T1021.001": ("Remote Desktop Protocol", "https://attack.mitre.org/techniques/T1021/001/"),
    "T1027": ("Obfuscated Files or Information", "https://attack.mitre.org/techniques/T1027/"),
    "T1036.006": ("Space after Filename", "https://attack.mitre.org/techniques/T1036/006/"),
    "T1055": ("Process Injection", "https://attack.mitre.org/techniques/T1055/"),
    "T1059.001": ("PowerShell", "https://attack.mitre.org/techniques/T1059/001/"),
    "T1071": ("Application Layer Protocol", "https://attack.mitre.org/techniques/T1071/"),
    "T1078.004": ("Cloud Accounts", "https://attack.mitre.org/techniques/T1078/004/"),
    "T1095": ("Non-Application Layer Protocol", "https://attack.mitre.org/techniques/T1095/"),
    "T1106": ("Native API", "https://attack.mitre.org/techniques/T1106/"),
    "T1140": (
        "Deobfuscate/Decode Files or Information",
        "https://attack.mitre.org/techniques/T1140/",
    ),
    "T1486": ("Data Encrypted for Impact", "https://attack.mitre.org/techniques/T1486/"),
    "T1497": ("Virtualization/Sandbox Evasion", "https://attack.mitre.org/techniques/T1497/"),
    "T1547": ("Boot or Logon Autostart Execution", "https://attack.mitre.org/techniques/T1547/"),
}

# STIX pattern values are usually wrapped in single quotes inside square
# brackets: ``[file:hashes.SHA-256 = 'abcd...']``. This regex pulls every
# such quoted literal out so we can compare against the evidence corpus.
_PATTERN_LITERAL_RE = re.compile(r"'([^']+)'")


def _technique_display_name(tid: str) -> str | None:
    """Friendly ATT&CK technique name from the already-built index, else None.

    Reuses the ATTCKValidator singleton ONLY when it is already initialized —
    never forces an index build, so unit tests stay offline/fast. Fail-safe.
    Lets REP-01 give correct names for all ~700 techniques, not just the curated
    fallback table below.
    """
    try:
        from maljan.memory.attck_validator import ATTCKValidator

        validator = ATTCKValidator.current_instance()
        if validator is None:
            return None
        tech = validator.get_technique(tid)
        return tech.name if tech is not None else None
    except Exception:  # noqa: BLE001 — best-effort cosmetic back-fill
        return None


def postprocess_judge_bundle(
    bundle_dict: dict[str, Any],
    evidence_corpus: set[str] | None = None,
    valid_technique_ids: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Apply J-01 / J-02 / REP-01 fixes in place; return the same dict.

    ``bundle_dict`` is the parsed JSON Bundle returned by the verdict LLM
    (and already filtered for hallucinated technique IDs upstream).

    ``evidence_corpus`` is an optional set of lower-cased string tokens
    drawn from the deterministic findings — interesting strings, sandbox
    observations, network IOCs. When provided, indicators whose pattern
    value isn't a substring of any corpus entry are dropped.

    ``valid_technique_ids`` (Wave 9, 2026-05-29) is the set of TIDs that
    survived the cascade and are present in the report's
    capability_matrix. When provided, REP-01 drops AttackPattern SDOs
    whose technique_id is not in the set (orphan attack-patterns), along
    with any Relationship SDOs that referenced them. This prevents the
    judge LLM from synthesizing a TTP the deterministic pipeline
    rejected and giving it MITRE legitimacy via external_references.
    """
    objects = bundle_dict.get("objects")
    if not isinstance(objects, list):
        return bundle_dict

    # ── J-01: rewrite invalid / placeholder STIX IDs ────────────────
    id_remap: dict[str, str] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        old_id = obj.get("id")
        if not isinstance(old_id, str):
            continue
        m = _STIX_ID_RE.match(old_id)
        if m is None or m.group("uuid") == _PLACEHOLDER_UUID:
            new_id = _mint_id(obj, old_id)
            if new_id != old_id:
                id_remap[old_id] = new_id
                obj["id"] = new_id
    if id_remap:
        logger.warning(
            "judge_postprocess: rewrote %d invalid STIX IDs: %s",
            len(id_remap),
            ", ".join(f"{k} -> {v}" for k, v in list(id_remap.items())[:5]),
        )
        _rewrite_references(objects, id_remap)

    # ── J-02: drop hallucinated indicators ─────────────────────────
    if evidence_corpus is not None:
        haystack = " ".join(evidence_corpus).lower()
        # Sandbox-derived "real activity" corpus for tightened file:name
        # admission (Wave 4 Step 5). Carried separately because evidence
        # corpus is permissive (whole interesting_strings list); the
        # sandbox set is the only positive runtime signal.
        runtime_paths: set[str] = set()
        for tok in evidence_corpus:
            # Heuristic: any literal that itself contains a known prefix
            # or extension is "runtime-like" enough to anchor admission.
            t = tok.strip()
            if any(t.startswith(p.lower()) for p in IOC_OS_RESOURCE_PREFIXES):
                runtime_paths.add(t)

        kept: list[dict[str, Any]] = []
        dropped = 0
        file_name_kept = 0
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "indicator":
                kept.append(obj)
                continue
            pattern = obj.get("pattern", "")
            literals: list[str] = (
                _PATTERN_LITERAL_RE.findall(pattern) if isinstance(pattern, str) else []
            )

            verdict = _admit_indicator(
                pattern=str(pattern),
                literals=literals,
                haystack=haystack,
                runtime_paths=runtime_paths,
                file_name_kept=file_name_kept,
            )
            if verdict == "keep":
                kept.append(obj)
                if isinstance(pattern, str) and pattern.lstrip().startswith("[file:name"):
                    file_name_kept += 1
            else:
                dropped += 1
                logger.warning(
                    "judge_postprocess: dropping indicator (reason=%s name=%s pattern=%s)",
                    verdict,
                    obj.get("name", "<unnamed>"),
                    pattern[:120],
                )
        if dropped:
            objects = kept
            bundle_dict["objects"] = kept

    # ── REP-02 (Wave 9): drop orphan attack-patterns absent from the
    # report's capability_matrix. Sweep relationships pointing to them.
    if valid_technique_ids is not None:
        orphan_ap_ids: set[str] = set()
        kept_ap: list[dict[str, Any]] = []
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
                kept_ap.append(obj)
                continue
            tid = _attack_pattern_technique_id(obj)
            if tid and tid not in valid_technique_ids:
                ap_id = obj.get("id")
                if isinstance(ap_id, str):
                    orphan_ap_ids.add(ap_id)
                logger.warning(
                    "judge_postprocess: dropping orphan attack-pattern (tid=%s "
                    "not in capability_matrix; id=%s)",
                    tid,
                    obj.get("id", "<no-id>"),
                )
                continue
            kept_ap.append(obj)
        if orphan_ap_ids:
            objects = [
                obj
                for obj in kept_ap
                if not (
                    isinstance(obj, dict)
                    and obj.get("type") == "relationship"
                    and (
                        obj.get("source_ref") in orphan_ap_ids
                        or obj.get("target_ref") in orphan_ap_ids
                    )
                )
            ]
            bundle_dict["objects"] = objects

    # ── REP-01: back-fill external_references on AttackPatterns ────
    _VALID_TID_RE_LOCAL = re.compile(r"^T\d{4}(?:\.\d{3})?$")
    _CURATED_PLACEHOLDERS = frozenset({"T0000", "T0000.000", "T9999", "T1234"})
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references") or []
        if refs:
            continue
        tid = _attack_pattern_technique_id(obj)
        # FILT-COVERAGE-01 follow-up: never back-fill external_references
        # with a placeholder or non-MITRE-shaped value. Without this guard,
        # ``attack-pattern--<uuid>(name=T0000)`` would gain a synthesized
        # MITRE reference that links to a non-existent technique page.
        if not tid or tid in _CURATED_PLACEHOLDERS or not _VALID_TID_RE_LOCAL.match(tid):
            continue
        if tid in _MITRE_LOOKUP:
            name, url = _MITRE_LOOKUP[tid]
        else:
            # Beyond the curated table, pull the real name from the live ATT&CK
            # index when it's loaded; fall back to the LLM name / bare ID.
            name = _technique_display_name(tid) or obj.get("name") or tid
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        obj["external_references"] = [
            {"source_name": "mitre-attack", "external_id": tid, "url": url},
        ]
        # Promote a friendlier name when LLM left it as the bare ID.
        if not obj.get("name") or obj.get("name") == tid:
            obj["name"] = name

    # ── REP-03: reconcile the bundle against the cascade ────────────
    if valid_technique_ids is not None:
        objects = _reconcile_with_cascade(objects, valid_technique_ids)
        bundle_dict["objects"] = objects

    # ── Final integrity pass: empty-pattern drop, dedup, dangling-ref sweep ──
    before = len(objects)
    objects = enforce_bundle_integrity(objects)
    bundle_dict["objects"] = objects
    if len(objects) != before:
        logger.info(
            "judge_postprocess: integrity pass kept %d/%d objects (dropped empty/dup/dangling).",
            len(objects),
            before,
        )

    return bundle_dict


# ---------------------------------------------------------------------------
# Indicator admission (Wave 4 Step 5)
# ---------------------------------------------------------------------------


def _admit_indicator(
    *,
    pattern: str,
    literals: list[str],
    haystack: str,
    runtime_paths: set[str],
    file_name_kept: int,
) -> str:
    """Return ``"keep"`` or a short reason string for J-02 logging.

    Acceptance-based filter for ``file:name`` indicators (tightened in
    Wave 4 after a noise audit found ~45 noisy SDOs); falls back to the
    original "any-literal-in-corpus" check for every other kind.
    """
    if not pattern:
        return "empty_pattern"

    stripped = pattern.lstrip()

    # ── URL denylist ────────────────────────────────────────────────
    if stripped.startswith("[url:value"):
        for lit in literals:
            host = _extract_url_host(lit)
            if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
                return "url_denylist"
        # URLs surviving the denylist still need corpus presence.
        if not any(lit.lower() in haystack for lit in literals if lit):
            return "url_not_in_corpus"
        return "keep"

    # ── file:name admission ────────────────────────────────────────
    if stripped.startswith("[file:name"):
        # Cap reached → drop.
        if file_name_kept >= MAX_FILE_NAME_INDICATORS:
            return "file_name_cap"
        if not literals:
            return "file_name_no_literal"

        # Every literal must (a) not be a denylisted compile artefact
        # AND (b) satisfy at least one acceptance signal.
        for lit in literals:
            if COMPILE_ARTIFACT_RE.search(lit):
                return "file_name_compile_artifact"
            if FOREIGN_CLASS_REF_RE.match(lit):
                return "file_name_foreign_class_ref"

        for lit in literals:
            if _looks_like_real_file_path(lit, runtime_paths):
                return "keep"
        return "file_name_no_acceptance_signal"

    # ── default (hash / domain / ip / etc.): keep if any literal hits.
    if any(lit.lower() in haystack for lit in literals if lit):
        return "keep"
    return "not_in_corpus"


def _looks_like_real_file_path(literal: str, runtime_paths: set[str]) -> bool:
    """Acceptance signals for a ``file:name`` literal (Step 5)."""
    if not literal:
        return False
    lit_lower = literal.lower()

    # Real, persisted file extension wins immediately.
    for ext in IOC_FILE_EXTENSIONS:
        if lit_lower.endswith(ext):
            return True

    # Known OS-resource prefix anchors the path into a real FS location.
    for prefix in IOC_OS_RESOURCE_PREFIXES:
        if literal.startswith(prefix):
            return True

    # Sandbox actually observed this path at runtime (file_operations /
    # registry_mods). When present, even an extension-less literal is fine.
    if lit_lower in runtime_paths:
        return True

    return False


def _extract_url_host(raw_url: str) -> str | None:
    """Best-effort host extraction without a full URL parser."""
    if not raw_url:
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(raw_url)
        if parsed.hostname:
            return parsed.hostname.lower()
    except (ValueError, TypeError):
        pass
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mint_id(obj: dict[str, Any], old_id: str) -> str:
    """Generate a spec-compliant STIX ID for ``obj``.

    For ``attack-pattern--T1497`` we hash the technique ID into a stable
    UUID5 so identical techniques map to identical IDs across runs.
    Anything else gets a fresh random UUID4.
    """
    stix_type = obj.get("type") or _parse_type(old_id) or "indicator"
    if stix_type == "attack-pattern":
        tid = _attack_pattern_technique_id(obj) or _parse_type_suffix(old_id)
        if tid:
            return f"attack-pattern--{uuid.uuid5(_MITRE_NS, tid)}"
    return f"{stix_type}--{uuid.uuid4()}"


def _parse_type(stix_id: str) -> str | None:
    if "--" in stix_id:
        return stix_id.split("--", 1)[0]
    return None


def _parse_type_suffix(stix_id: str) -> str | None:
    if "--" in stix_id:
        return stix_id.split("--", 1)[1]
    return None


def _attack_pattern_technique_id(obj: dict[str, Any]) -> str | None:
    r"""Best-effort technique ID extraction from an ``attack-pattern`` SDO.

    Order of attempts:
    1. ``external_references[*].external_id`` matching ``T####``.
    2. ``name`` matching ``^T####(\.###)?$``.
    3. ``x_maljan_technique_id`` (Maljan custom field).
    """
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("external_id"), str):
            tid = str(ref["external_id"]).strip()
            if re.match(r"^T\d{4}(?:\.\d{3})?$", tid):
                return tid
    name = obj.get("name", "")
    if isinstance(name, str) and re.match(r"^T\d{4}(?:\.\d{3})?$", name.strip()):
        return name.strip()
    custom = obj.get("x_maljan_technique_id")
    if isinstance(custom, str) and re.match(r"^T\d{4}(?:\.\d{3})?$", custom.strip()):
        return custom.strip()
    return None


def _rewrite_references(objects: list[Any], id_remap: dict[str, str]) -> None:
    """In-place: rewrite ``source_ref`` / ``target_ref`` / ``object_refs``."""
    if not id_remap:
        return
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        for key in ("source_ref", "target_ref", "created_by_ref"):
            if obj.get(key) in id_remap:
                obj[key] = id_remap[obj[key]]
        refs = obj.get("object_refs")
        if isinstance(refs, list):
            obj["object_refs"] = [id_remap.get(r, r) for r in refs]


def _oid(o: Any) -> Any:
    return o.get("id") if isinstance(o, dict) else getattr(o, "id", None)


def _otype(o: Any) -> Any:
    return o.get("type") if isinstance(o, dict) else getattr(o, "type", None)


def _oget(o: Any, key: str, default: Any = None) -> Any:
    return o.get(key, default) if isinstance(o, dict) else getattr(o, key, default)


def _oset(o: Any, key: str, value: Any) -> None:
    if isinstance(o, dict):
        o[key] = value
    else:
        setattr(o, key, value)


def _technique_id_poly(o: Any) -> str | None:
    """Technique ID from an attack-pattern (dict or pydantic), via refs or name."""
    for ref in _oget(o, "external_references", []) or []:
        ext = ref.get("external_id") if isinstance(ref, dict) else getattr(ref, "external_id", None)
        if isinstance(ext, str) and re.match(r"^T\d{4}(?:\.\d{3})?$", ext.strip()):
            return ext.strip()
    name = _oget(o, "name", "") or ""
    if isinstance(name, str) and re.match(r"^T\d{4}(?:\.\d{3})?$", name.strip()):
        return name.strip()
    return None


def _remap_refs_poly(objects: list[Any], remap: dict[str, str]) -> None:
    """Rewrite source_ref/target_ref/object_refs through ``remap`` (dict or pydantic)."""
    if not remap:
        return
    for o in objects:
        for key in ("source_ref", "target_ref"):
            v = _oget(o, key)
            if isinstance(v, str) and v in remap:
                _oset(o, key, remap[v])
        refs = _oget(o, "object_refs")
        if isinstance(refs, list):
            _oset(o, "object_refs", [remap.get(r, r) for r in refs])


def _is_wellformed_pattern(indicator: Any) -> bool:
    """Conservative STIX 2.1 pattern shape check for an indicator object.

    Returns True only when the pattern is a bracketed comparison expression
    (``[ <path> <op> '<value>' ]``). Keeps all patterns Maljan emits; rejects
    empty/whitespace and truncated/garbage LLM output (e.g. ``[file:name = 'x``).
    """
    pat = str(_oget(indicator, "pattern", "") or "").strip()
    return pat.startswith("[") and pat.endswith("]") and "=" in pat


def enforce_bundle_integrity(objects: list[Any]) -> list[Any]:
    """Make a STIX object list internally valid and non-redundant, in place-ish.

    Works on both parsed dicts (judge bundle) and pydantic SDOs (extended
    bundle). Order-preserving. Steps:
      1. Drop indicators with an empty/whitespace pattern (STIX 2.1 invalid).
      2. Deduplicate attack-patterns by technique ID (keep first; remap refs).
      3. Deduplicate indicators by (pattern_type, pattern) (keep first; remap refs).
      4. Drop relationships whose source/target is not in the bundle, and
         deduplicate identical relationships.
      5. Trim object_refs (Report/Note) to objects that still exist.
    """
    # 1) drop indicators with an empty or syntactically malformed pattern. The
    # shape check is deliberately conservative — a STIX comparison expression is
    # wrapped in brackets and contains a comparator — so it keeps every pattern
    # this codebase emits and only rejects truncated/garbage LLM output (no full
    # grammar parser, hence no over-dropping).
    objects = [o for o in objects if _otype(o) != "indicator" or _is_wellformed_pattern(o)]

    remap: dict[str, str] = {}

    # 2) attack-pattern dedup by technique ID
    seen_tid: dict[str, str] = {}
    kept: list[Any] = []
    for o in objects:
        if _otype(o) == "attack-pattern":
            tid = _technique_id_poly(o)
            if tid and tid in seen_tid:
                oid = _oid(o)
                if isinstance(oid, str):
                    remap[oid] = seen_tid[tid]
                continue
            if tid and isinstance(_oid(o), str):
                seen_tid[tid] = _oid(o)
        kept.append(o)
    objects = kept

    # 3) indicator dedup by (pattern_type, pattern)
    seen_pat: dict[tuple[str, str], str] = {}
    kept = []
    for o in objects:
        if _otype(o) == "indicator":
            key = (str(_oget(o, "pattern_type", "stix")), str(_oget(o, "pattern", "")))
            if key in seen_pat:
                oid = _oid(o)
                if isinstance(oid, str):
                    remap[oid] = seen_pat[key]
                continue
            if isinstance(_oid(o), str):
                seen_pat[key] = _oid(o)
        kept.append(o)
    objects = kept

    # apply remap so refs to deduped objects point at the kept ones
    _remap_refs_poly(objects, remap)

    # 4) drop dangling + duplicate relationships
    ids = {_oid(o) for o in objects}
    seen_rel: set[tuple[str, str, str]] = set()
    kept = []
    for o in objects:
        if _otype(o) == "relationship":
            src, tgt = _oget(o, "source_ref"), _oget(o, "target_ref")
            if src not in ids or tgt not in ids:
                continue
            rkey = (str(_oget(o, "relationship_type", "")), str(src), str(tgt))
            if rkey in seen_rel:
                continue
            seen_rel.add(rkey)
        kept.append(o)
    objects = kept

    # 5) trim object_refs to surviving objects
    ids = {_oid(o) for o in objects}
    for o in objects:
        refs = _oget(o, "object_refs")
        if isinstance(refs, list):
            _oset(o, "object_refs", [r for r in refs if r in ids])

    return objects


def build_evidence_corpus(
    *,
    interesting_strings: list[dict[str, Any]] | None = None,
    sandbox_report: dict[str, Any] | None = None,
    extra: list[str] | None = None,
) -> set[str]:
    """Build the lower-cased token set used by the J-02 filter.

    The output deliberately overcollects (whole strings, parts split on
    ``/`` or ``.``) so a substring check inside :func:`postprocess_judge_bundle`
    is cheap. ``False positives'' here are fine — they only allow a
    questionable indicator through, which is preferable to dropping a
    valid one.
    """
    corpus: set[str] = set()

    for item in interesting_strings or []:
        v = item.get("value") if isinstance(item, dict) else None
        if isinstance(v, str) and v:
            corpus.add(v.lower())

    if isinstance(sandbox_report, dict):
        network = sandbox_report.get("network") or {}
        for kind in ("dns", "http", "tcp", "udp"):
            for entry in network.get(kind) or []:
                if isinstance(entry, str):
                    corpus.add(entry.lower())
                elif isinstance(entry, dict):
                    for v in entry.values():
                        if isinstance(v, str) and v:
                            corpus.add(v.lower())

    for s in extra or []:
        if isinstance(s, str) and s:
            corpus.add(s.lower())

    return corpus


def _reconcile_with_cascade(objects: list[Any], valid_technique_ids: frozenset[str]) -> list[Any]:
    """REP-03 — make the bundle carry exactly the cascade's technique set.

    REP-01 and REP-02 both key off a technique ID the LLM has to have supplied:
    the orphan drop is ``if tid and tid not in valid_ids``, so a ``None`` tid
    survives, and the reference back-fill only runs once a tid resolves. When
    the model answers with prose names and no IDs anywhere, both are no-ops —
    and nothing in the pipeline ever *added* the techniques it left out, so the
    bundle was only ever a filtered view of the model's output.

    Measured on one sample, 2026-08-07: the run where the verdict LLM succeeded
    produced 5 attack-patterns with **zero** external_ids, against 39 techniques
    in the same report's ttp_mappings; the run where it timed out and fell back
    to the deterministic builder produced 33, all with IDs. The fallback was the
    better artefact, which is the wrong way round.

    Two directions, both necessary:

    * An ``attack-pattern`` whose technique ID cannot be resolved is dropped.
      Without an ``external_id`` there is no ATT&CK mapping — the object claims
      a technique without naming one, and a consumer cannot act on it.
    * Every cascade technique missing from the bundle is added, carrying the
      same ``external_references`` shape the deterministic fallback emits.

    ``objects`` is returned as a new list; relationships pointing at dropped
    patterns go with them (the integrity pass would sweep them anyway, but
    leaving dangling refs for it to find hides *why* they dangle).
    """
    malware_ids = [
        o.get("id") for o in objects if isinstance(o, dict) and o.get("type") == "malware"
    ]
    malware_id = next((m for m in malware_ids if isinstance(m, str)), None)

    kept: list[Any] = []
    dropped_ap_ids: set[str] = set()
    present: set[str] = set()
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            kept.append(obj)
            continue
        tid = _attack_pattern_technique_id(obj)
        if not tid:
            ap_id = obj.get("id")
            if isinstance(ap_id, str):
                dropped_ap_ids.add(ap_id)
            logger.warning(
                "judge_postprocess: dropping attack-pattern with no resolvable "
                "technique id (name=%r) — an ATT&CK mapping without an ID is unusable.",
                obj.get("name", "<unnamed>"),
            )
            continue
        present.add(tid)
        kept.append(obj)

    if dropped_ap_ids:
        kept = [
            o
            for o in kept
            if not (
                isinstance(o, dict)
                and o.get("type") == "relationship"
                and (o.get("source_ref") in dropped_ap_ids or o.get("target_ref") in dropped_ap_ids)
            )
        ]

    missing = sorted(valid_technique_ids - present)
    for tid in missing:
        name = _technique_display_name(tid)
        if not name and tid in _MITRE_LOOKUP:
            name = _MITRE_LOOKUP[tid][0]
        url = (
            _MITRE_LOOKUP[tid][1]
            if tid in _MITRE_LOOKUP
            else f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        )
        ap_id = f"attack-pattern--{uuid.uuid5(_MITRE_NS, tid)}"
        kept.append(
            {
                "type": "attack-pattern",
                "id": ap_id,
                "name": name or tid,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": tid, "url": url}
                ],
            }
        )
        if malware_id:
            kept.append(
                {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid5(_MITRE_NS, f'{malware_id}:{tid}')}",
                    "relationship_type": "uses",
                    "source_ref": malware_id,
                    "target_ref": ap_id,
                    "x_maljan_technique_id": tid,
                }
            )

    if missing:
        logger.info(
            "judge_postprocess: added %d cascade technique(s) the verdict LLM omitted "
            "from the bundle (%s%s).",
            len(missing),
            ", ".join(missing[:6]),
            "…" if len(missing) > 6 else "",
        )
    return kept
