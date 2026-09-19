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
    address_is_publishable,
    corroboration_reason,
    host_is_public,
    ip_corroboration_reason,
    url_corroboration_reason,
    url_host,
)
from maljan.pipeline.events import safe_finding_value
from maljan.reporting.models import (
    MalwareReport,
    NetworkDomain,
    NetworkIP,
    NetworkURL,
    ProcessNode,
    StringIOC,
)
from maljan.schemas.judgement import indicator_type_for
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
UNPUBLISHABLE_DOMAIN_CODE = "stix.unpublishable_domain"

# The sources whose rows are worth a recorded decline. Something a sandbox
# watched, an agent wrote down or the judge asserted is an observation, and a
# reader is owed a sentence when one does not reach the export. A string
# sweep's own output is not: it produces up to forty rows a run that were never
# going to be published, and forty unresolved findings nobody can act on bury
# the ones somebody can.
_OBSERVED_SOURCES = ("sandbox", "analyst", "judge")

# The bands the indicator cap spends its budget in, best first. The sample's
# own hashes are what every consumer of the bundle came for; then the network
# indicators somebody observed or a second source knows, which is what a
# blocklist is made of; then the other hashes the judge carried, which describe
# the sample by another route; then the file names, the noisiest thing a string
# sweep produces.
_BAND_OWN_HASH = 0
_BAND_NETWORK = 1
_BAND_JUDGE_HASH = 2
_BAND_FILE_NAME = 3

# How strong the origin of a network indicator is, which orders the band.
# Something a sandbox watched outranks something an agent or the judge wrote
# down, which outranks a run of bytes in the file that a second source happened
# to know.
#
# What an unrecorded source is worth is the caller's answer, not this table's,
# and the caller gives this function the same value it gave the publish rule:
# two readings of "unrecorded" is how one of them publishes what the other
# ranks as noise. A URL row carrying none is read as string-derived by both; a
# domain or an address carrying none is read the way ``corroboration_reason``
# reads it, as a producer that did not make the weak claim.
_NETWORK_SOURCE_RANK: dict[str, int] = {"sandbox": 2, "analyst": 1, "judge": 1, "strings": 0}
_UNRECORDED_SOURCE_RANK = 2

# The patterns that name the sample rather than an endpoint. Matched anywhere in
# the pattern rather than at its start, because the judge writes compound ones —
# ``[file:extensions['pe'].pe_imphash = … OR file:hashes.'SHA-1' = …]`` is a
# hash indicator whichever comparison it leads with.
_HASH_PATTERN_MARKERS = ("file:hashes", "imphash")

_NETWORK_PATTERN_PREFIXES = (
    "[url:value",
    "[domain-name:value",
    "[ipv4-addr:value",
    "[ipv6-addr:value",
)


# The literals a STIX pattern quotes, which is where a URL indicator keeps its
# URL.
_PATTERN_LITERALS_RE = re.compile(r"'([^']*)'")

# An object path in a pattern comparison: the type, then the property. Case
# does not carry meaning in a STIX object path, and a judge writes
# ``[URL:value = ...]`` often enough that reading it as a kind this question is
# not about would be a hole rather than a nicety.
_OBJECT_PATH_RE = re.compile(r"([a-z0-9-]+):[a-z_.]+", re.IGNORECASE)

# Comparison operators whose right-hand side is not an endpoint: a regular
# expression, a wildcard shape, a subnet. The value cannot be asked the host
# question, so the indicator is declined for that reason and not for a reason
# that would be untrue of it.
_UNREADABLE_OPERATORS = ("matches", "like", "issubset", "issuperset")

# The object types whose value is an endpoint a consumer would act on, which is
# what the host question is asked about.
_NETWORK_OBJECT_TYPES = ("url", "domain-name", "ipv4-addr", "ipv6-addr")


def _indicator_band(pattern: str) -> int:
    """Which cap band one indicator pattern belongs to, the sample's own aside."""
    stripped = (pattern or "").lstrip()
    if any(marker in stripped for marker in _HASH_PATTERN_MARKERS):
        return _BAND_JUDGE_HASH
    if any(stripped.startswith(prefix) for prefix in _NETWORK_PATTERN_PREFIXES):
        return _BAND_NETWORK
    return _BAND_FILE_NAME


def _network_rank(source: Any) -> int:
    """How strong one network indicator's origin is, for the cap's own order."""
    name = str(source or "").strip().lower()
    if not name:
        return _UNRECORDED_SOURCE_RANK
    return _NETWORK_SOURCE_RANK.get(name, _UNRECORDED_SOURCE_RANK)


def _within_the_indicator_cap(
    objects: list[Any], order: dict[str, tuple[int, int, int]]
) -> list[Any]:
    """``objects`` with the lowest-priority indicators removed, or ``objects`` itself.

    The cap is over every indicator the bundle would carry, whoever minted it,
    and it is spent in the order the report's own linter describes: the
    sample's hashes, the network indicators somebody observed or a second
    source knows, the other hashes the judge carried, the file names. An
    indicator nothing queued — one that arrived in the judge's bundle and was
    merged into another by the integrity pass keeps the first writer's id, so
    this is rare — sorts last rather than raising.
    """
    indicators = [obj for obj in objects if getattr(obj, "type", "") == "indicator"]
    if len(indicators) <= MAX_TOTAL_INDICATORS:
        return objects
    last = (_BAND_FILE_NAME + 1, 0, len(order))
    ranked = sorted(indicators, key=lambda obj: order.get(obj.id, last))
    kept = {obj.id for obj in ranked[:MAX_TOTAL_INDICATORS]}
    logger.warning(
        "stix_renderer: total indicator cap (%d) exceeded by %d; the lowest-priority "
        "indicator(s) are not exported.",
        MAX_TOTAL_INDICATORS,
        len(indicators) - MAX_TOTAL_INDICATORS,
    )
    return [obj for obj in objects if getattr(obj, "type", "") != "indicator" or obj.id in kept]


def impossible_host_sentence(value: str, whose: str) -> str:
    """The recorded sentence for a URL no host could ever answer for."""
    return (
        f"the URL indicator for {safe_finding_value(value)!r} is not in the exported bundle: its "
        f"host is not a name or address that could exist outside the analysed network. It is "
        f"unchanged in {whose}."
    )


def unpublishable_endpoint_sentence(value: str, kind_words: str, whose: str) -> str:
    """The recorded sentence for an endpoint no export may carry, left where it is."""
    return (
        f"the {kind_words} indicator for {safe_finding_value(value)!r} is not in the exported "
        f"bundle: it is not a name or address that could exist outside the analysed network. It "
        f"is unchanged in {whose}."
    )


def unreadable_endpoint_sentence(value: str, kind_words: str, whose: str) -> str:
    """The recorded sentence for a comparison this code cannot read an endpoint from."""
    return (
        f"the {kind_words} indicator for {safe_finding_value(value)!r} is not in the exported "
        f"bundle: the pipeline could not read the pattern's endpoint, so it could not ask whether "
        f"this export may carry it. It is unchanged in {whose}."
    )


def unpublishable_domain_sentence(fqdn: str) -> str:
    """The recorded sentence for a name somebody watched that no export may carry."""
    return (
        f"the domain indicator for {safe_finding_value(fqdn)!r} is not in the exported bundle: it "
        "is a name that does not resolve outside the analysed network. The report's network block "
        "keeps the row with the source that saw it."
    )


def _observed(source: Any) -> bool:
    """Whether this row is somebody's observation rather than a string sweep's."""
    return str(source or "").strip().lower() in _OBSERVED_SOURCES


def _pattern_endpoints(pattern: str) -> list[tuple[str, str, str]]:
    """Every ``(object type, literal, operator)`` a network comparison names.

    A STIX pattern is not one comparison. ``[a] OR [b]``, an ``AND`` of two
    object paths and an ``IN`` list of several values are all one pattern with
    several endpoints in it, and an indicator is exported or not as a whole. So
    every quoted value is credited to the object path most recently written
    before it, and the caller answers for all of them.

    The split is on the quotes rather than on the object paths, because a
    pattern's literals are where a URL lives and a URL can carry anything that
    looks like an object path inside it. Only what is written *outside* the
    quotes says what is being compared.
    """
    found: list[tuple[str, str, str]] = []
    kind = ""
    operator = ""
    for index, chunk in enumerate(pattern.split("'")):
        if index % 2 == 0:
            # No path in this chunk means the list of values goes on: ``IN
            # ('a', 'b')`` writes the path once and quotes twice.
            paths = list(_OBJECT_PATH_RE.finditer(chunk))
            if paths:
                kind = paths[-1].group(1).lower()
                operator = chunk[paths[-1].end() :].strip().lower()
        elif kind in _NETWORK_OBJECT_TYPES:
            found.append((kind, chunk, operator))
    return found


def _endpoint_is_readable(operator: str) -> bool:
    """Whether the right-hand side of this comparison is an endpoint at all."""
    return not any(word in operator for word in _UNREADABLE_OPERATORS)


def _endpoint_is_publishable(kind: str, literal: str) -> bool:
    """Whether an export could carry this endpoint at all, whoever wrote it down.

    The host question only — could anything outside the analysed network ever
    answer for this. Who recorded the row is the corroboration question's
    business and is not asked here.
    """
    if kind == "url":
        return host_is_public(url_host(literal))
    if kind == "domain-name":
        return host_is_public(literal)
    # The judge asserting an address is somebody observing it, so a private one
    # it cites out of the sandbox's own evidence is lateral movement and stays.
    # Loopback, unspecified, documentation, multicast and broadcast never are.
    return address_is_publishable(literal, "judge")


def _judge_indicator_problem(indicator: Indicator) -> tuple[str, str] | None:
    """Why this judge indicator is not exported, as ``(code, sentence)``, or ``None``.

    The judge's objects go through the host question the deterministic rows do,
    and the answer for one that fails it is the one this pipeline gives
    everywhere else: not published, recorded, never rewritten. All three
    network kinds are asked, because the question is about the endpoint rather
    than about who wrote it down — a judge-written ``localhost`` or
    ``127.0.0.1`` is the same thing a consumer's blocklist cannot use as the
    one the network block already refuses.

    What is deliberately *not* asked is the corroboration half. The judge's own
    assertion is the source, so that half would answer trivially, and letting
    "the judge said so" count as a second source is a claim this code should
    not make on the judge's behalf. Whether any evidence holds a judge-written
    endpoint up is ``stix.ungrounded_indicator``'s question, and it is asked of
    every indicator the judge writes.
    """
    for kind, literal, operator in _pattern_endpoints(indicator.pattern or ""):
        readable = _endpoint_is_readable(operator)
        if readable and _endpoint_is_publishable(kind, literal):
            continue
        code = UNPUBLISHABLE_URL_CODE if kind == "url" else UNPUBLISHABLE_DOMAIN_CODE
        words = {"url": "URL", "domain-name": "domain"}.get(kind, "address")
        if not readable:
            return (code, unreadable_endpoint_sentence(literal, words, "the judge's own bundle"))
        if kind == "url":
            return (code, impossible_host_sentence(literal, "the judge's own bundle"))
        return (code, unpublishable_endpoint_sentence(literal, words, "the judge's own bundle"))
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
                    named = safe_finding_value(getattr(obj, "name", "") or "it")
                    self.declined.append(
                        (
                            MALWARE_UNDER_BENIGN_CODE,
                            f"the malware object {named!r} is not "
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

        # Every indicator that could be in the bundle, each with the key the
        # cap will order it by: its band, how strong its origin is, and where
        # it was collected. The cap runs after the integrity pass rather than
        # here, so a slot is never spent on a row that pass is about to
        # deduplicate away; see the end of this method.
        order: dict[str, tuple[int, int, int]] = {}

        def _queue(indicator: Indicator, band: int, source: Any = None) -> None:
            order[indicator.id] = (band, -_network_rank(source), len(order))
            objects.append(indicator)

        # 4) Indicator for the file hash itself (always present), in a band of
        #    its own: it names the sample, which is what every consumer of this
        #    bundle came for, and it used to queue behind whatever hashes the
        #    judge happened to write.
        #    What it claims about the sample follows the verdict the run
        #    publishes. It used to claim ``malicious-activity`` whatever the
        #    verdict was, so a Benign export told every blocklist that the
        #    sample's hash is malicious activity — a stronger contradiction
        #    than the malware object the same export declines, because a
        #    consumer blocks on the indicator and reads the objects afterwards.
        sample_hash_id: str | None = None
        sha256 = report.identity.hashes.sha256
        if sha256 and _SHA256_RE.match(sha256):
            indicator = Indicator(
                name=f"Sample hash {sha256[:12]}",
                pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
                pattern_type="stix",
                indicator_types=[indicator_type_for(report.verdict)],
            )
            _queue(indicator, _BAND_OWN_HASH)
            sample_hash_id = indicator.id
            if malware_id is not None:
                objects.append(
                    Relationship(
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=malware_id,
                    )
                )

        # 5) Network IP/URL/domain → Indicator, in the order the priority rule
        #    names them, so a tie inside the band breaks the way it is written
        #    down.
        #
        #    Before the string rows, not after them, and that order is load
        #    bearing: a corroborated string row and the network row that
        #    corroborated it are the same indicator written twice, the
        #    integrity pass keeps whichever was queued first, and the one worth
        #    keeping is the one that carries the observation.
        if report.network is not None:
            for ip in report.network.ips[:40]:
                ip_ind = _indicator_for_ip(ip)
                if ip_ind is not None:
                    _queue(ip_ind, _BAND_NETWORK, ip.source)
            for url in report.network.urls[:40]:
                url_ind = _indicator_for_url(url, report)
                if url_ind is not None:
                    # The source the publish rule was given, so the order and
                    # the decision read the same value: a row with none is
                    # string-derived to both.
                    _queue(url_ind, _BAND_NETWORK, url.source or "strings")
                    continue
                # A host nothing could answer for is worth telling a reader
                # about when somebody watched the row; a string sweep's own
                # cut-offs were never going to be published, and recording
                # forty of them a run buries the findings a reader can act on.
                if _observed(url.source) and not host_is_public(url_host(url.url)):
                    self.declined.append(
                        (
                            UNPUBLISHABLE_URL_CODE,
                            impossible_host_sentence(url.url, "the report's network block"),
                        )
                    )
            for domain in report.network.domains[:40]:
                dom_ind = _indicator_for_domain(domain)
                if dom_ind is not None:
                    _queue(dom_ind, _BAND_NETWORK, domain.source)
                    continue
                # The name a sandbox resolved stays in the report either way;
                # what is recorded is that the export does not carry it, and
                # the reason. A name only the string sweep produced is held
                # back by the corroboration rule, which is the rule working.
                if _observed(domain.source) and not host_is_public(domain.fqdn):
                    self.declined.append(
                        (
                            UNPUBLISHABLE_DOMAIN_CODE,
                            unpublishable_domain_sentence(domain.fqdn),
                        )
                    )

        # 6) StringIOC → Indicator.
        #
        # Which names this run may publish at all. One rule, read once, and
        # every path that mints a domain indicator asks it: the network block
        # above, and the string rows here, which are the same names arriving
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
                # String-derived by construction, and only here at all because
                # a second source knew the name; the band reads the pattern and
                # the rank reads that origin, so it never outranks a row the
                # sandbox watched.
                _queue(ind, _indicator_band(pattern), "strings")

        # 6.5) The judge's own indicators, banded by their patterns. They are
        #      queued last within their bands: the judge asserts, a sandbox
        #      observes, and the order says which is which.
        for carried_indicator in carried:
            _queue(carried_indicator, _indicator_band(carried_indicator.pattern), "judge")

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
        #
        #    A STIX note is about something, and ``object_refs`` is required
        #    and may not be empty. A Benign verdict has no malware object for
        #    it to be about, so it is about the object that stands for the
        #    sample instead — the indicator carrying the sample's own hash,
        #    which is in a band of its own and therefore cannot be capped out
        #    from under the reference. A bundle carrying neither is a bundle
        #    with nothing the note could truthfully be about, and then there is
        #    no note: the summary is in the report, which is where a reader
        #    reads it.
        summary = report.executive_summary.strip()
        about = malware_id or sample_hash_id
        if summary and about is not None:
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
                object_refs=[about],
            )
            objects.append(note)

        # 9) Report SDO bundles every object_ref. Pre-existing AttackPattern
        #    objects are referenced too so the report stays the single root.
        #    A report with nothing to reference is not emitted: ``object_refs``
        #    is required and a required list may not be empty, and a bundle
        #    holding only this pipeline's identity has nothing to report on.
        refs = [obj.id for obj in objects if obj is not identity]
        if refs:
            objects.append(
                Report(
                    name=f"Maljan analysis of {sha256[:12] if sha256 else 'sample'}",
                    description=(
                        f"Verdict: {report.verdict}. "
                        + (
                            f"Severity {report.severity.overall_score}/10 "
                            f"({report.severity.rating})."
                            if report.severity
                            else "Severity not assessed."
                        )
                    ),
                    published=report.generated_at,
                    report_types=["malware-analysis"],
                    object_refs=refs,
                )
            )

        # Referential-integrity + dedup pass over the assembled bundle — it
        # collapses indicators duplicated across the judge base bundle and the
        # renderer's synthesized set, and prunes any ref dangling from upstream
        # drops. See judge_postprocess.enforce_bundle_integrity.
        #
        # It runs *before* the cap, which is the whole reason the cap moved
        # here. A string row and the network row it was corroborated by are the
        # same indicator written twice; capping first spent two of fifteen
        # slots on a pair this pass then folded into one, so a bundle over the
        # cap shipped under it and the rows it lost were the ones the priority
        # order exists to keep — five observed C2 addresses, on the probe that
        # found this. Deduplicated first, the cap keeps exactly as many
        # indicators as there is room for.
        from maljan.agents.judge_postprocess import enforce_bundle_integrity

        objects = enforce_bundle_integrity(objects, ledger=ledger)
        capped = _within_the_indicator_cap(objects, order)
        if capped is objects:
            return Bundle(objects=objects)
        # Only what the cap orphaned is left to sweep, and it is the cap's
        # doing rather than the pass's, so this one is not counted again.
        return Bundle(objects=enforce_bundle_integrity(capped))

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


# The network kinds, and the one place a pattern for any of them is written.
# Nothing else in the tree builds one: a path that wrote its own would be a
# path that had not asked :func:`network_publish_reason`, which is how a
# version number out of a strings table came to be exported as malicious
# infrastructure two sections after the network block had refused the same
# address. ``tests/unit/reporting/test_one_network_publish_rule.py`` fails if a
# second place starts writing one.
NETWORK_KINDS: tuple[str, ...] = ("domain", "ip", "url")


def network_pattern(kind: str, value: str) -> str | None:
    """The STIX pattern for one network endpoint, or ``None`` for another kind."""
    quoted = _escape_stix(value)
    if kind == "url":
        return f"[url:value = '{quoted}']"
    if kind == "domain":
        return f"[domain-name:value = '{quoted}']"
    if kind != "ip":
        return None
    try:
        family = "ipv6-addr" if ipaddress.ip_address(quoted).version == 6 else "ipv4-addr"
    except ValueError:
        family = "ipv4-addr"
    return f"[{family}:value = '{quoted}']"


def network_publish_reason(
    kind: str, value: str, source: Any, reputation: Any = None
) -> str | None:
    """Why this run may publish one network endpoint, or ``None``.

    One rule for the three kinds, and every path that can mint a network
    indicator asks it: the network block's own rows, the string rows that reach
    the bundle through ``static.interesting_strings``, and the judge's own
    indicator objects. It used to be three rules on four paths, and the path
    nobody had named published what the other three refused.
    """
    if kind == "domain":
        if not host_is_public(value):
            return None
        return corroboration_reason(source, reputation, value)
    if kind == "ip":
        return ip_corroboration_reason(value, source, reputation)
    if kind == "url":
        return url_corroboration_reason(value, source, reputation)
    return None


def _stix_pattern_for_string_ioc(ioc: StringIOC) -> str | None:
    value = _escape_stix(ioc.value)
    if ioc.kind in NETWORK_KINDS:
        return network_pattern(ioc.kind, ioc.value)
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
        if domain.fqdn
        and network_publish_reason("domain", domain.fqdn, domain.source, domain.reputation)
        is not None
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

    # Every network kind asks the one publish rule, and every row here came out
    # of the string scan, so every one of them asks it as ``strings``. A domain
    # asks it through the network block's own answer, which is where the same
    # name's reputation and its stronger source live; the other two ask it
    # directly. The addresses used to fall past all of this to ``return True``
    # below, so a version number written with dots in it was exported as
    # malicious infrastructure while the network block was refusing the very
    # same address.
    if ioc.kind in NETWORK_KINDS:
        if ioc.kind == "domain":
            return value.lower().rstrip(".") in publishable_domains
        if ioc.kind == "url":
            host = _extract_url_host(value)
            if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
                return False
        return network_publish_reason(ioc.kind, value, "strings") is not None

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


def _indicator_for_domain(domain: NetworkDomain) -> Indicator | None:
    """The name as an indicator, or ``None`` when this run may not publish it.

    Two ways to be refused, and they are different facts: a name nothing but
    the sample's own byte image knows, which is the string sweep's own output
    and is held back silently; and a name that does not resolve outside the
    analysed network — reserved, private-use, or a single label — which is
    refused whoever watched it, and recorded when somebody did.
    """
    fqdn = domain.fqdn.strip()
    if not fqdn:
        return None
    admitted = network_publish_reason("domain", fqdn, domain.source, domain.reputation)
    if admitted is None:
        # A run of bytes that has the shape of a hostname is not an
        # observation of infrastructure. One PE's string sweep put fifteen
        # such fragments into a published bundle, each as an indicator a
        # downstream consumer would block on. They stay in the report's
        # network block, labelled with where they came from; they are not
        # offered to the world until a second source knows the name.
        return None
    pattern = network_pattern("domain", fqdn)
    assert pattern is not None  # noqa: S101 - a domain always has one
    return Indicator(
        name=f"Domain {fqdn}",
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
    """The address as an indicator, or ``None`` when this run may not publish it.

    The same rule the domains and the URLs go through. The addresses were the
    one network kind with no gate at all, so every run of digits the string
    sweep read as an address was published and ranked as though a sandbox had
    watched it — one live bundle carried ``6.0.0.0``, a version number out of
    the strings table.
    """
    address = ip.address.strip()
    if not address:
        return None
    admitted = network_publish_reason("ip", address, ip.source, ip.reputation)
    if admitted is None:
        return None
    pattern = network_pattern("ip", address)
    assert pattern is not None  # noqa: S101 - an address always has one
    return Indicator(
        name=f"IP {address}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"] if ip.is_suspicious else ["anomalous-activity"],
        # As for a domain, only the surprising admission is spelled out: an
        # address a sandbox watched needs no explanation, and one the file's
        # own bytes carried reaches a bundle on a reputation record alone.
        description=admitted if ip.source == "strings" else None,
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
    # A row that records no source at all is read as the weakest claim there
    # is, which is the reading the cap gives it as well: two readings of
    # "unrecorded" is how one of them ends up publishing what the other ranks
    # as noise. Only a row persisted before the field existed reaches this.
    source = url.source or "strings"
    admitted = network_publish_reason("url", url.url, source, _host_reputation(report, host))
    if admitted is None:
        return None
    pattern = network_pattern("url", url.url)
    assert pattern is not None  # noqa: S101 - a URL always has one
    return Indicator(
        name=f"URL {url.url[:48]}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"],
        # As for a domain, only the surprising admission is spelled out.
        description=admitted if source == "strings" else None,
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
