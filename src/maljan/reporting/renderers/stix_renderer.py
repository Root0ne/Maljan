"""Build an extended STIX 2.1 Bundle from a ``MalwareReport``.

The judge node already emits a minimal Bundle (Malware + AttackPattern +
Relationship). This renderer takes that bundle as a starting point and
augments it with the richer SDO set required by downstream CTI tooling:

  - ``Identity`` for Maljan itself (the report producer)
  - ``Indicator`` for every typed IOC (file hash, domain, IP, URL, mutex)
  - ``ObservedData`` snapshots of the sandbox process tree
  - ``Note`` containing the LLM-generated executive summary
  - ``Report`` top-level container with object_refs to every member

The renderer is additive but for one set: the judge's attack-patterns are
replaced by one per technique in ``report.ttp_mappings``, so the bundle names
the techniques the report names, with stable ids and an ATT&CK reference on
each. Everything else the judge emitted is preserved as-is. Producing this
bundle is side-effect free; callers serialise it via ``model_dump(mode="json")``.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Any

from maljan.agents._indicator_denylists import (
    COMPILE_ARTIFACT_RE,
    FOREIGN_CLASS_REF_RE,
    IOC_FILE_EXTENSIONS,
    IOC_OS_RESOURCE_PREFIXES,
    MAX_FILE_NAME_INDICATORS,
    MAX_TOTAL_INDICATORS,
    URL_DENY_HOSTS,
)
from maljan.core.logger import logger
from maljan.extractors.network_extractor import (
    corroboration_reason,
    domain_is_corroborated,
    url_corroboration_reason,
    url_host,
)
from maljan.reporting.models import (
    MalwareReport,
    NetworkDomain,
    NetworkIP,
    NetworkURL,
    ProcessNode,
    StringIOC,
)
from maljan.schemas.stix_models import (
    AttackPattern,
    Bundle,
    Identity,
    Indicator,
    Malware,
    Note,
    ObservedData,
    Relationship,
    Report,
    get_utcnow,
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# What the run summary calls a judge object this export declined to carry. Each
# says what is not in the bundle and why; nothing is rewritten, and the judge's
# own bundle keeps the object.
MALWARE_UNDER_BENIGN_CODE = "stix.malware_object_under_benign"
UNPUBLISHABLE_URL_CODE = "stix.unpublishable_url"

# Which of the three priority kinds an indicator belongs to, by its pattern.
# The cap spends its budget in this order: hashes, then network indicators,
# then the file names, which are the noisiest thing a string sweep produces.
_NETWORK_PATTERN_PREFIXES = (
    "[url:value",
    "[domain-name:value",
    "[ipv4-addr:value",
    "[ipv6-addr:value",
)


# The literals a STIX pattern quotes, which is where a URL indicator keeps its
# URL.
_PATTERN_LITERALS_RE = re.compile(r"'([^']*)'")


def _indicator_kind(pattern: str) -> str:
    """``hash``, ``network`` or ``string`` for one indicator pattern."""
    stripped = (pattern or "").lstrip()
    if stripped.startswith("[file:hashes"):
        return "hash"
    if any(stripped.startswith(prefix) for prefix in _NETWORK_PATTERN_PREFIXES):
        return "network"
    return "string"


def _judge_indicator_problem(indicator: Indicator) -> tuple[str, str] | None:
    """Why this judge indicator is not exported, as ``(code, sentence)``, or ``None``.

    The judge's objects go through the same publish rule the deterministic
    rows do, and the answer for one that fails it is the one this pipeline
    gives everywhere else: not published, recorded, never rewritten. A URL is
    the only kind asked so far — it is the one the string sweep feeds and the
    one a cut-off host reaches a consumer through.
    """
    pattern = (indicator.pattern or "").lstrip()
    if not pattern.startswith("[url:value"):
        return None
    for literal in _PATTERN_LITERALS_RE.findall(pattern):
        if url_corroboration_reason(literal, "judge") is None:
            return (
                UNPUBLISHABLE_URL_CODE,
                f"the URL indicator for {literal!r} is not in the exported bundle: its host is "
                "not a name or address that could exist. It is unchanged in the judge's own "
                "bundle.",
            )
    return None


class ExtendedSTIXRenderer:
    """Augment a minimal Bundle with the SDOs derived from a ``MalwareReport``.

    ``render(report, base_bundle)`` returns a new ``Bundle`` instance — the
    input bundle is treated as immutable.
    """

    def __init__(self) -> None:
        # Per render: the techniques whose judge relationships went with them,
        # as ``(technique, relationships dropped)``. The report node writes
        # them into ``run_summary.validation`` — an annotation the judge made
        # about a technique the checks rejected is not a defect of the bundle,
        # it is part of what the run has to say about that technique.
        self.unlinked: list[tuple[str, int]] = []
        # Per render: the objects this export declined to carry, as
        # ``(validation code, what and why)``. Nothing is rewritten — the
        # judge's bundle is stored as the run's own record — and the report
        # node writes these rows beside the run's other findings so a reader
        # of the export is told what is not in it.
        self.declined: list[tuple[str, str]] = []

    def render(
        self,
        report: MalwareReport,
        base_bundle: Bundle | None = None,
        *,
        ledger: Any | None = None,
    ) -> Bundle:
        """Render the extended bundle.

        ``ledger`` is an optional ``TruncationLedger``; the integrity pass at the
        end records what it removed there, which is the measurement the
        repair-versus-reject claim needs. This is the *second* place the pass
        runs — the judge's
        own post-process is the first — so both must report or the aggregate
        undercounts.
        """
        objects: list[Any] = []
        self.unlinked = []
        self.declined = []
        # A verdict of Benign is a finding that this sample is not malware, so
        # the bundle it publishes carries no malware object — neither one the
        # judge wrote as "a container for the object type in STIX" beside an
        # assessment calling the sample benign, nor one minted here. The
        # verdict is the judge's and is published as stated; what is declined
        # is the object that contradicts it, and the decline is recorded.
        benign = str(getattr(report, "verdict", "") or "").strip().lower() == "benign"

        # 1) Preserve everything the judge already emitted, except its
        #    attack-patterns: those are rebuilt from the report's published
        #    technique list below, so the bundle and the report cannot disagree
        #    about what this run found. One audited run exported ten techniques
        #    in the report and zero attack-patterns in the bundle; another
        #    exported three attack-patterns with no ATT&CK reference at all.
        #
        #    What the judge said *about* those techniques stays. Its
        #    relationships carry the confidence, the evidence basis and the
        #    contributing agents it put on each one, and they point at objects
        #    that are about to be replaced — so both ends of every ref move to
        #    the rebuilt object of the same technique before the originals go,
        #    and the annotations travel unedited. A relationship to a technique
        #    the checks rejected has nothing to move to: it is taken out here,
        #    with the technique, and counted as that technique's loss rather
        #    than left to the integrity pass, which would count it a second
        #    time as a dangling ref of the judge's bundle.
        # ``carried`` holds the judge's own indicators, which go through the
        # same cap the minted ones do: the cap used to count only what this
        # renderer made, so a bundle with two judge indicators and fourteen
        # minted ones shipped sixteen against a ceiling of fifteen and the
        # report's own linter said so.
        linked: set[str] = set()
        carried: list[Indicator] = []
        if base_bundle is not None:
            self._normalize_judge_timestamps(base_bundle.objects)
            remap = _technique_remap(report, base_bundle)
            gone = _rejected_pattern_ids(base_bundle, remap)
            for obj in base_bundle.objects:
                kind = getattr(obj, "type", "")
                if kind == "attack-pattern":
                    continue
                if kind == "malware" and benign:
                    self.declined.append(
                        (
                            MALWARE_UNDER_BENIGN_CODE,
                            f"the malware object {str(getattr(obj, 'name', '') or 'it')!r} is not "
                            "in the exported bundle: this run's verdict is Benign. The object is "
                            "unchanged in the judge's own bundle and the disagreement is in this "
                            "run's validation findings.",
                        )
                    )
                    continue
                if _points_at(obj, gone):
                    continue
                moved, technique = _relinked(obj, remap)
                if technique:
                    linked.add(technique)
                if isinstance(moved, Indicator):
                    declined = _judge_indicator_problem(moved)
                    if declined:
                        self.declined.append(declined)
                        continue
                    carried.append(moved)
                    continue
                objects.append(moved)
            self.unlinked = _unlinked_techniques(base_bundle, gone)

        # 2) Identity SDO for Maljan itself.
        identity = Identity(
            name="Maljan",
            identity_class="software",
            description="Automated multi-agent malware analysis pipeline",
        )
        objects.append(identity)

        # 3) Locate the Malware object (created by judge or here as fallback).
        #    A Benign verdict gets none: the fallback used to mint one on every
        #    run, so the object a Benign export declines above was replaced by
        #    an identical one two steps later.
        malware_id = None if benign else self._find_malware_id(objects)
        if malware_id is None and not benign:
            malware_name = report.attribution.family or report.malware_category or "unknown"
            malware_obj = Malware(
                name=str(malware_name),
                description=f"Sample {report.identity.hashes.sha256}",
                is_family=False,
                malware_types=[report.malware_category] if report.malware_category else [],
            )
            objects.append(malware_obj)
            malware_id = malware_obj.id

        # 3.5) One attack-pattern per published technique, with a stable id and
        #      an ATT&CK reference, related to the malware object. The judge's
        #      own objects carried whatever id the model minted — including
        #      placeholder UUIDs out of the STIX documentation — and a
        #      technique the report published reached the bundle only if the
        #      judge had happened to emit an object for it. With no malware
        #      object there is nothing for a ``uses`` edge to start at, and the
        #      techniques are published without one.
        for pattern_sdo, uses in _attack_patterns_for(report, malware_id, linked):
            objects.append(pattern_sdo)
            if uses is not None:
                objects.append(uses)

        # Collect indicators per-kind, then apply
        # MAX_TOTAL_INDICATORS as a hard cap with priority order
        # (hashes > network > file:name strings). The 2026-05-29 Linux
        # ELF audit found 19 indicators leaking past the ≤15 ceiling
        # because the per-kind cap (MAX_FILE_NAME_INDICATORS=10) ignored
        # hashes and network IOCs.
        by_kind: dict[str, list[Indicator]] = {"hash": [], "network": [], "string": []}
        # The ``indicates`` edge a published indicator still needs, by the id of
        # the indicator it belongs to, so an indicator the cap leaves out does
        # not put a dangling edge in the bundle.
        indicates: dict[str, Relationship] = {}

        # The judge's own indicators, sorted into the same three kinds as the
        # minted ones and ahead of them, because they are the verdict's.
        for carried_indicator in carried:
            by_kind[_indicator_kind(carried_indicator.pattern)].append(carried_indicator)

        # 4) Indicator for the file hash itself (always present).
        sha256 = report.identity.hashes.sha256
        if sha256 and _SHA256_RE.match(sha256):
            indicator = Indicator(
                name=f"Sample hash {sha256[:12]}",
                pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
                pattern_type="stix",
                indicator_types=["malicious-activity"],
            )
            by_kind["hash"].append(indicator)
            if malware_id is not None:
                indicates[indicator.id] = Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware_id,
                )

        # 5) StringIOC → Indicator.
        #
        # Which names this run may publish at all. One rule, read once, and
        # every path that mints a domain indicator asks it: the network block
        # below, and the string rows here, which are the same names arriving
        # by a second road.
        publishable_domains = _publishable_domains(report)

        # Apply the same acceptance-based filter
        # used by the judge bundle postprocess so deterministic
        # interesting_strings can't smuggle noise (NDK build paths, bundled
        # bytecode class refs, random short strings) into the public STIX
        # bundle. Without this, the 2026-05-23 noise audit's 49-noisy-paths
        # FP reappears for every sample that bundles NDK-compiled libraries.
        if report.static is not None:
            file_name_kept = 0
            for ioc in report.static.interesting_strings[:50]:
                pattern = _stix_pattern_for_string_ioc(ioc)
                if pattern is None:
                    continue
                if not _accept_string_ioc(ioc, pattern, file_name_kept, publishable_domains):
                    continue
                is_file_name = pattern.lstrip().startswith("[file:name")
                if is_file_name:
                    file_name_kept += 1
                ind = Indicator(
                    name=f"{ioc.kind} {ioc.value[:32]}",
                    pattern=pattern,
                    pattern_type="stix",
                    # file:name string IOCs are the FP-prone kind (heavily
                    # capped/filtered upstream); mark them anomalous-activity so
                    # consumers can weight them below high-confidence hash/C2 IOCs.
                    indicator_types=(
                        ["anomalous-activity"] if is_file_name else ["malicious-activity"]
                    ),
                )
                by_kind[_indicator_kind(pattern)].append(ind)

        # 6) Network domain/IP/URL → Indicator.
        if report.network is not None:
            for domain in report.network.domains[:40]:
                dom_ind = _indicator_for_domain(domain)
                if dom_ind is not None:
                    by_kind["network"].append(dom_ind)
            for ip in report.network.ips[:40]:
                ip_ind = _indicator_for_ip(ip)
                if ip_ind is not None:
                    by_kind["network"].append(ip_ind)
            for url in report.network.urls[:40]:
                url_ind = _indicator_for_url(url, report)
                if url_ind is not None:
                    by_kind["network"].append(url_ind)

        # 6.5) Apply the total-indicator cap with priority order, over every
        #      indicator that would be in the bundle rather than over the ones
        #      this renderer happened to mint.
        budget = MAX_TOTAL_INDICATORS
        dropped_counts = {"hash": 0, "network": 0, "string": 0}
        for kind in ("hash", "network", "string"):
            for ind in by_kind[kind]:
                if budget <= 0:
                    dropped_counts[kind] += 1
                    continue
                objects.append(ind)
                edge = indicates.get(ind.id)
                if edge is not None:
                    objects.append(edge)
                budget -= 1
        if sum(dropped_counts.values()):
            logger.warning(
                "stix_renderer: total indicator cap (%d) exceeded; dropped "
                "hash=%d network=%d string=%d",
                MAX_TOTAL_INDICATORS,
                dropped_counts["hash"],
                dropped_counts["network"],
                dropped_counts["string"],
            )

        # 7) ObservedData for the process tree roots.
        if report.dynamic is not None and report.dynamic.process_tree:
            obs_objects = _processes_to_observed(report.dynamic.process_tree)
            if obs_objects:
                observed = ObservedData(
                    first_observed=report.generated_at,
                    last_observed=report.generated_at,
                    number_observed=len(obs_objects),
                    objects=obs_objects,
                )
                objects.append(observed)

        # 8) Note wraps the executive summary; abstract is the verdict.
        summary = report.executive_summary.strip()
        if summary:
            note = Note(
                abstract=(
                    f"{report.verdict} — confidence "
                    + (
                        "not assessed"
                        if report.overall_confidence is None
                        else f"{report.overall_confidence:.2f}"
                    )
                ),
                content=summary,
                object_refs=[malware_id] if malware_id is not None else [],
            )
            objects.append(note)

        # 9) Report SDO bundles every object_ref. Pre-existing AttackPattern
        #    objects are referenced too so the report stays the single root.
        report_sdo = Report(
            name=f"Maljan analysis of {sha256[:12] if sha256 else 'sample'}",
            description=(
                f"Verdict: {report.verdict}. "
                + (
                    f"Severity {report.severity.overall_score}/10 ({report.severity.rating})."
                    if report.severity
                    else "Severity not assessed."
                )
            ),
            published=report.generated_at,
            report_types=["malware-analysis"],
            object_refs=[obj.id for obj in objects if obj is not identity],
        )
        objects.append(report_sdo)

        # Final referential-integrity + dedup pass over the assembled bundle —
        # also collapses indicators duplicated across the judge base bundle and
        # the renderer's synthesized set, and prunes any ref dangling from
        # upstream drops. See judge_postprocess.enforce_bundle_integrity.
        from maljan.agents.judge_postprocess import enforce_bundle_integrity

        return Bundle(objects=enforce_bundle_integrity(objects, ledger=ledger))

    @staticmethod
    def _normalize_judge_timestamps(objects: list[Any]) -> None:
        """Normalize the judge's LLM-emitted SDOs to authoritative values.

        The judge Bundle is emitted by the LLM, which copies STIX documentation
        examples verbatim. Two fields are never authoritative and are fixed here:

        * ``created``/``modified`` — land on the placeholder
          ``2023-01-01T00:00:00Z`` epoch instead of the analysis
          time; a downstream CTI consumer would trust that bogus date. Overwrite
          with the render time (matching every renderer-produced SDO).
        * ``is_family`` on Malware SDOs — the LLM often
          copies ``is_family: true`` from the docs, but Maljan analyses a single
          specimen, so this must be ``false``. STIX ``is_family=true`` asserts
          the object represents a malware *family*, not one sample.

        Object ids are left untouched so intra-bundle relationship refs stay
        valid.
        """
        now = get_utcnow()
        for obj in objects:
            if hasattr(obj, "created"):
                obj.created = now
            if hasattr(obj, "modified"):
                obj.modified = now
            if isinstance(obj, Malware) and getattr(obj, "is_family", False):
                obj.is_family = False

    @staticmethod
    def _find_malware_id(objects: list[Any]) -> str | None:
        for obj in objects:
            if isinstance(obj, Malware):
                return obj.id
            obj_type = getattr(obj, "type", None)
            if obj_type == "malware":
                return getattr(obj, "id", None)
        return None


# The namespace the technique objects' ids are derived in. A UUIDv5 over the
# technique id, so the same technique is the same object across exports of the
# same run and across runs — and never a UUID copied out of the STIX
# documentation, which is what the judge's own objects sometimes carried.
_ATTACK_PATTERN_NAMESPACE = uuid.UUID("2f0b4c10-6f7e-5b6a-9d3b-1f6a5c7e8d90")


def _pattern_id_for(technique_id: str) -> str:
    """The published object id of one technique. Same id every time."""
    return f"attack-pattern--{uuid.uuid5(_ATTACK_PATTERN_NAMESPACE, technique_id)}"


def _published_ids(report: MalwareReport) -> dict[str, str]:
    """``technique id -> published object id`` for the validated mappings."""
    out: dict[str, str] = {}
    for mapping in report.ttp_mappings:
        tid = str(mapping.technique_id or "").strip().upper()
        if tid and tid not in out:
            out[tid] = _pattern_id_for(tid)
    return out


def _declared_technique(obj: Any) -> str:
    """The ATT&CK id an attack-pattern declares, from its reference or its name."""
    for ref in getattr(obj, "external_references", None) or []:
        if isinstance(ref, dict) and str(ref.get("external_id") or "").strip():
            return str(ref["external_id"]).strip().upper()
    name = str(getattr(obj, "name", "") or "").strip().upper()
    first = name.split()[0].rstrip(":") if name else ""
    return first if first.startswith("T") else ""


def _technique_remap(report: MalwareReport, base_bundle: Bundle) -> dict[str, str]:
    """``judge object id -> published object id``, per surviving technique."""
    published = _published_ids(report)
    remap: dict[str, str] = {}
    for obj in base_bundle.objects:
        if getattr(obj, "type", "") != "attack-pattern":
            continue
        published_id = published.get(_declared_technique(obj))
        if published_id:
            remap[str(getattr(obj, "id", ""))] = published_id
    return remap


def _relinked(obj: Any, remap: dict[str, str]) -> tuple[Any, str]:
    """``obj`` pointing at the rebuilt technique, and the technique it now uses.

    Both ends: a judge relationship is usually ``malware --uses--> technique``,
    and one sourced at the technique would dangle just as surely. A copy rather
    than a write: the judge's bundle is stored as the run's own record and a
    renderer that edited it would change what the run says it answered.

    The second value is the technique of a ``uses`` edge from the sample —
    the one edge the rebuild would otherwise mint a second, unannotated copy
    of. It is ``""`` for every other shape, which keeps the minted edge for a
    technique the judge only related some other way.
    """
    if getattr(obj, "type", "") != "relationship":
        return obj, ""
    source = str(getattr(obj, "source_ref", "") or "")
    target = str(getattr(obj, "target_ref", "") or "")
    update = {
        key: remap[ref]
        for key, ref in (("source_ref", source), ("target_ref", target))
        if ref in remap
    }
    if not update:
        return obj, ""
    moved = obj.model_copy(update=update)
    if str(getattr(obj, "relationship_type", "") or "") != "uses" or target not in remap:
        return moved, ""
    technique = str(getattr(obj, "x_maljan_technique_id", "") or "").strip().upper()
    return moved, technique or remap[target]


def _rejected_pattern_ids(base_bundle: Bundle, remap: dict[str, str]) -> dict[str, str]:
    """``judge object id -> technique`` for the attack-patterns nothing published."""
    gone: dict[str, str] = {}
    for obj in base_bundle.objects:
        object_id = str(getattr(obj, "id", "") or "")
        if getattr(obj, "type", "") != "attack-pattern" or object_id in remap:
            continue
        gone[object_id] = _declared_technique(obj) or str(getattr(obj, "name", "") or "")
    return gone


def _points_at(obj: Any, gone: dict[str, str]) -> bool:
    """Whether a relationship names an attack-pattern that is not published."""
    if getattr(obj, "type", "") != "relationship":
        return False
    return str(getattr(obj, "source_ref", "") or "") in gone or (
        str(getattr(obj, "target_ref", "") or "") in gone
    )


def _unlinked_techniques(base_bundle: Bundle, gone: dict[str, str]) -> list[tuple[str, int]]:
    """Per technique the checks rejected, how many judge relationships went with it."""
    counts: dict[str, int] = {}
    for obj in base_bundle.objects:
        if getattr(obj, "type", "") != "relationship":
            continue
        for ref in (getattr(obj, "source_ref", ""), getattr(obj, "target_ref", "")):
            label = gone.get(str(ref or ""))
            if label:
                counts[label] = counts.get(label, 0) + 1
                break
    return sorted(counts.items())


def _attack_patterns_for(
    report: MalwareReport, malware_id: str | None, linked: set[str] | None = None
) -> list[tuple[AttackPattern, Relationship | None]]:
    """One attack-pattern per published technique, and the link it still needs.

    The report's ``ttp_mappings`` is the source, so the bundle names exactly
    the techniques the report names: the same list the ATT&CK section, the
    References and ``/reports/{id}/mitre`` are built from, with the ids the
    catalogue check rejected already out of it. A technique the judge already
    related to the sample gets no second relationship — the judge's own carries
    its confidence and this one would carry none — and neither does one in a
    bundle with no malware object, which a Benign verdict publishes.
    """
    already = linked or set()
    out: list[tuple[AttackPattern, Relationship | None]] = []
    seen: set[str] = set()
    for mapping in report.ttp_mappings:
        tid = str(mapping.technique_id or "").strip().upper()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        pattern = AttackPattern(
            id=_pattern_id_for(tid),
            name=mapping.technique_name or tid,
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": tid,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                }
            ],
        )
        if malware_id is None or tid in already or pattern.id in already:
            out.append((pattern, None))
            continue
        out.append(
            (
                pattern,
                Relationship(
                    relationship_type="uses",
                    source_ref=malware_id,
                    target_ref=pattern.id,
                ),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------


def _escape_stix(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _stix_pattern_for_string_ioc(ioc: StringIOC) -> str | None:
    value = _escape_stix(ioc.value)
    if ioc.kind == "url":
        return f"[url:value = '{value}']"
    if ioc.kind == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc.kind == "ip":
        return _ip_pattern(value)
    if ioc.kind == "email":
        return f"[email-addr:value = '{value}']"
    if ioc.kind == "mutex":
        return f"[mutex:name = '{value}']"
    if ioc.kind == "registry":
        return f"[windows-registry-key:key = '{value}']"
    if ioc.kind == "path":
        return f"[file:name = '{value}']"
    # "secret" and "crypto_wallet" reach here and are deliberately not patterned.
    # STIX 2.1 has no SCO for a leaked credential or a wallet address, and
    # inventing a custom object would produce a bundle that no consumer can
    # ingest — worse than omitting it, because it looks importable and is not.
    # Both kinds are carried in the consolidated IOC table instead, where they
    # are typed and readable.
    return None


def _publishable_domains(report: Any) -> frozenset[str]:
    """The domains this report may publish, by the one corroboration rule.

    A name the sample's byte image knows and nothing else is not an
    observation of infrastructure, so it is not offered to a consumer that
    would block on it. The network block is where each name's source is
    recorded, so it is the answer for both minting paths — a `domain` string
    row is by construction string-derived, and is published only when the
    network block says a second source names it too.
    """
    network = getattr(report, "network", None)
    if network is None:
        return frozenset()
    return frozenset(
        domain.fqdn.strip().lower().rstrip(".")
        for domain in network.domains
        if domain.fqdn and domain_is_corroborated(domain.source, domain.reputation, domain.fqdn)
    )


def _accept_string_ioc(
    ioc: StringIOC,
    pattern: str,
    file_name_kept: int,
    publishable_domains: frozenset[str] = frozenset(),
) -> bool:
    """Gate StringIOC → Indicator emission.

    Applies the same rules as :func:`maljan.pipeline.validation._indicator_problem`
    so the extended renderer cannot bypass the indicator noise floor. These IOCs
    come from the deterministic string scan rather than from a model, so there
    is nobody to hand a violation back to: the gate is the whole check. Mocking
    out the LLM (or any judge bundle path) no longer means the bundle ships with
    NDK build paths / bundled bytecode class refs / random short strings.
    """
    stripped = pattern.lstrip()
    value = (ioc.value or "").strip()

    # Domains: the corroboration rule, the same one the network block is
    # gated by. Every `domain` row here came out of the string scan, so an
    # uncorroborated one is a run of bytes shaped like a hostname.
    if stripped.startswith("[domain-name:value"):
        return value.lower().rstrip(".") in publishable_domains

    # URLs: the corroboration rule, then the denylist of developer and build
    # hosts. Every ``url`` row here came out of the string scan, so it is
    # string-derived by construction and asks the predicate as one.
    if stripped.startswith("[url:value"):
        host = _extract_url_host(value)
        if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
            return False
        return url_corroboration_reason(value, "strings") is not None

    # file:name: acceptance-based admission + per-report cap.
    if stripped.startswith("[file:name"):
        if file_name_kept >= MAX_FILE_NAME_INDICATORS:
            return False
        if not value:
            return False
        if COMPILE_ARTIFACT_RE.search(value):
            return False
        if FOREIGN_CLASS_REF_RE.match(value):
            return False
        return _looks_like_real_path(value)

    return True


def _extract_url_host(raw_url: str) -> str | None:
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


def _looks_like_real_path(value: str) -> bool:
    lit_lower = value.lower()
    for ext in IOC_FILE_EXTENSIONS:
        if lit_lower.endswith(ext):
            return True
    for prefix in IOC_OS_RESOURCE_PREFIXES:
        if value.startswith(prefix):
            return True
    return False


def _ip_pattern(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return f"[ipv4-addr:value = '{value}']"
    family = "ipv6-addr" if addr.version == 6 else "ipv4-addr"
    return f"[{family}:value = '{value}']"


def _indicator_for_domain(domain: NetworkDomain) -> Indicator | None:
    fqdn = domain.fqdn.strip()
    if not fqdn:
        return None
    admitted = corroboration_reason(domain.source, domain.reputation, fqdn)
    if admitted is None:
        # A run of bytes that has the shape of a hostname is not an
        # observation of infrastructure. One PE's string sweep put fifteen
        # such fragments into a published bundle, each as an indicator a
        # downstream consumer would block on. They stay in the report's
        # network block, labelled with where they came from; they are not
        # offered to the world until a second source knows the name.
        return None
    pattern = f"[domain-name:value = '{_escape_stix(fqdn)}']"
    name = f"Domain {fqdn}"
    return Indicator(
        name=name,
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"] if domain.is_suspicious else ["anomalous-activity"],
        # Only the surprising admission is spelled out. A name the sandbox
        # resolved needs no explanation, and adding one would rewrite the
        # description of every domain in every bundle; a Tor address reaches a
        # bundle on the strength of its own syntax and of nothing anybody
        # watched, and a reader finding it there is owed that sentence.
        # ``None`` rather than an empty string: an absent key is what a
        # consumer saw before there was anything to say, and an empty
        # description is noise in a published bundle.
        description="; ".join(
            part
            for part in (domain.reason, admitted if domain.source == "strings" else None)
            if part
        )
        or None,
    )


def _indicator_for_ip(ip: NetworkIP) -> Indicator | None:
    address = ip.address.strip()
    if not address:
        return None
    pattern = _ip_pattern(_escape_stix(address))
    return Indicator(
        name=f"IP {address}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"] if ip.is_suspicious else ["anomalous-activity"],
    )


def _indicator_for_url(url: NetworkURL, report: Any = None) -> Indicator | None:
    """The URL as an indicator, or ``None`` when this run may not publish it.

    The same rule the domains go through, for the same reason: a URL pulled out
    of the file's bytes is not an endpoint anybody watched, and one live run
    published five string-sweep cut-offs — ``http://localho``, ``https://q``,
    ``http://3271`` — as indicators a consumer would block on. The host's own
    reputation row, where the enrichment wrote one, is what a second source
    looks like here.
    """
    if not url.url:
        return None
    host = url_host(url.url)
    admitted = url_corroboration_reason(url.url, url.source, _host_reputation(report, host))
    if admitted is None:
        return None
    pattern = f"[url:value = '{_escape_stix(url.url)}']"
    return Indicator(
        name=f"URL {url.url[:48]}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"],
        # As for a domain, only the surprising admission is spelled out.
        description=admitted if url.source == "strings" else None,
    )


def _host_reputation(report: Any, host: str) -> dict[str, Any] | None:
    """What a reputation provider said about this host, from the network block."""
    network = getattr(report, "network", None)
    if network is None or not host:
        return None
    for domain in network.domains:
        if domain.fqdn.strip().lower().rstrip(".") == host:
            reputation = domain.reputation
            return reputation if isinstance(reputation, dict) else None
    return None


def _processes_to_observed(roots: list[ProcessNode]) -> dict[str, dict[str, Any]]:
    """Flatten the process tree to a STIX 2.1 ``observed-data`` objects dict."""
    out: dict[str, dict[str, Any]] = {}
    counter = 0

    def _walk(node: ProcessNode) -> None:
        nonlocal counter
        entry: dict[str, Any] = {
            "type": "process",
            "pid": node.pid,
            "name": node.name,
        }
        if node.command_line:
            entry["command_line"] = node.command_line
        out[str(counter)] = entry
        counter += 1
        for child in node.children:
            _walk(child)

    for root in roots[:20]:  # cap to keep ObservedData reasonable
        _walk(root)
    return out


# Type-only re-exports keep linters happy when this module is grepped.
_ = (AttackPattern,)
