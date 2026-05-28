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
    ANDROID_CLASS_REF_RE,
    COMPILE_ARTIFACT_RE,
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


def postprocess_judge_bundle(
    bundle_dict: dict[str, Any],
    evidence_corpus: set[str] | None = None,
) -> dict[str, Any]:
    """Apply J-01 / J-02 / REP-01 fixes in place; return the same dict.

    ``bundle_dict`` is the parsed JSON Bundle returned by the verdict LLM
    (and already filtered for hallucinated technique IDs upstream).

    ``evidence_corpus`` is an optional set of lower-cased string tokens
    drawn from the deterministic findings — interesting strings, sandbox
    observations, network IOCs. When provided, indicators whose pattern
    value isn't a substring of any corpus entry are dropped.
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
        name, url = _MITRE_LOOKUP.get(
            tid,
            (
                obj.get("name") or tid,
                f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            ),
        )
        obj["external_references"] = [
            {"source_name": "mitre-attack", "external_id": tid, "url": url},
        ]
        # Promote a friendlier name when LLM left it as the bare ID.
        if not obj.get("name") or obj.get("name") == tid:
            obj["name"] = name

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
    Wave 4 after the zararli.apk audit found ~45 noisy SDOs); falls back
    to the original "any-literal-in-corpus" check for every other kind.
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
            if ANDROID_CLASS_REF_RE.match(lit):
                return "file_name_android_class_ref"

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
