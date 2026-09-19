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
    HASH_HEX_LENGTHS,
    IOC_FILE_EXTENSIONS,
    IOC_OS_RESOURCE_PREFIXES,
    MAX_FILE_NAME_INDICATORS,
    MAX_TOTAL_INDICATORS,
    URL_DENY_HOSTS,
    malformed_hash_in,
    whole_value_in,
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
from maljan.schemas.stix_pattern import read_comparisons

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# What the truncation ledger files the integrity pass's second run under: a
# relationship the indicator cap left pointing at nothing.
CAP_ORPHAN_REASON = "cap_orphan"

# What the run summary calls a judge object this export declined to carry. Each
# says what is not in the bundle and why; nothing is rewritten, and the judge's
# own bundle keeps the object.
MALWARE_UNDER_BENIGN_CODE = "stix.malware_object_under_benign"
# One endpoint question, one code. A URL, a name and an address that fail the
# same host question are one class of decline, and a reader filtering on the
# code used to find that class under two names — with the second of them
# covering addresses too, which is not what it is called. The kind is in the
# sentence, where it says something.
UNPUBLISHABLE_ENDPOINT_CODE = "stix.unpublishable_endpoint"
# What a run stored before that carries for the same decision. Nothing is
# migrated: a stored row is what that run recorded. The console reads these as
# the same decision, and ``apps/web/src/lib/validationRows.ts`` holds the list
# it reads them from.
LEGACY_UNPUBLISHABLE_CODES = ("stix.unpublishable_url", "stix.unpublishable_domain")
# An indicator over something that is not an endpoint: a mailbox that is not
# one, a file name that names a directory or a root.
UNPUBLISHABLE_ARTEFACT_CODE = "stix.unpublishable_artefact"
# A digest literal that is not a digest of the algorithm it is written under.
MALFORMED_HASH_CODE = "stix.malformed_hash"

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


# Comparison operators whose right-hand side is not an endpoint: a regular
# expression, a wildcard shape, a subnet. The value cannot be asked the host
# question, so the indicator is declined for that reason and not for a reason
# that would be untrue of it.
_UNREADABLE_OPERATORS = ("matches", "like", "issubset", "issuperset")

# The object paths whose value this export can ask a validity question about:
# the four endpoints a consumer would act on, the mailbox and the file name. A
# pattern over anything else is carried as the judge wrote it — there is no
# true question to ask of it, and inventing one would decline an object for a
# reason that is not so.
_DIRECT_PATHS = {
    "url:value": "url",
    "domain-name:value": "domain-name",
    "ipv4-addr:value": "ipv4-addr",
    "ipv6-addr:value": "ipv6-addr",
    "email-addr:value": "email-addr",
    "file:name": "file",
}

# A value reached through a reference carries the referenced object's own
# value: ``network-traffic:dst_ref.value`` is the address the traffic went to
# and ``domain-name:resolves_to_refs[*].value`` is what the name resolved to.
# Either could be a name or an address, so both questions are asked of it.
#
# These three references from these two owners, and no others. A reference is
# not an endpoint by itself — ``email-message:from_ref.value`` is a mailbox and
# ``network-traffic:src_payload_ref`` points at an artefact — and asking either
# of them the host question would decline an object for a reason that is not
# so, which is the thing the checked set exists to avoid.
_ENDPOINT_KIND = "endpoint"
_REFERENCE_OWNERS = ("network-traffic", "domain-name")
_REFERENCE_STEP_RE = re.compile(r"(?:^|\.)(?:src_ref|dst_ref|resolves_to_refs)\.")

# A hardware address, which is a legal target of ``src_ref`` and ``dst_ref``
# and is not a host. There is no true host question to ask of one, so it is
# carried as the judge wrote it rather than declined with a sentence about
# names and addresses that could exist outside the analysed network.
_MAC_ADDRESS_RE = re.compile(r"^[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}$", re.IGNORECASE)

# A list step inside an object path says which element, never what the value is.
_INDEX_STEP_RE = re.compile(r"\[[^\]]*\]")

# What each kind is called in a recorded decline, and which code the decline is
# filed under: one code for an endpoint no export may carry, one for an
# indicator over something that is not an endpoint at all.
_OBJECT_TYPE_WORDS = {
    "url": "URL",
    "domain-name": "domain",
    "email-addr": "e-mail address",
    "file": "file name",
    _ENDPOINT_KIND: "endpoint",
}
_DECLINE_CODES = {
    "email-addr": UNPUBLISHABLE_ARTEFACT_CODE,
    "file": UNPUBLISHABLE_ARTEFACT_CODE,
}


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


def _record_indicator_cap(ledger: Any | None, *, removed: int) -> None:
    """Tell the truncation ledger what the cap spent. Never raises.

    The cap is the one place a bundle loses objects that the integrity pass
    does not account for, so without this the ledger's reasons stop short of
    the bundle.
    """
    if ledger is None:
        return
    try:
        ledger.record_indicator_cap(removed=removed)
    except Exception:  # noqa: BLE001 — telemetry must never break an export
        return


def _within_the_indicator_cap(
    objects: list[Any], order: dict[str, tuple[int, int, int]], ledger: Any | None = None
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
        _record_indicator_cap(ledger, removed=0)
        return objects
    last = (_BAND_FILE_NAME + 1, 0, len(order))
    ranked = sorted(indicators, key=lambda obj: order.get(obj.id, last))
    kept = {obj.id for obj in ranked[:MAX_TOTAL_INDICATORS]}
    _record_indicator_cap(ledger, removed=len(indicators) - MAX_TOTAL_INDICATORS)
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


def not_an_address_sentence(value: str) -> str:
    """The recorded sentence for a mailbox that is not one, left where it is."""
    return (
        f"the e-mail indicator for {safe_finding_value(value)!r} is not in the exported bundle: "
        f"it is not a mailbox — either its syntax is not an address, or its domain part is not a "
        f"name anything outside the analysed network could answer for. It is unchanged in the "
        f"judge's own bundle."
    )


def not_a_file_sentence(value: str) -> str:
    """The recorded sentence for a file name that names a place, not a file."""
    return (
        f"the file indicator for {safe_finding_value(value)!r} is not in the exported bundle: it "
        f"names a directory or a root rather than a file, and a consumer matching on file:name "
        f"cannot act on one. It is unchanged in the judge's own bundle."
    )


def malformed_hash_sentence(algorithm: str, value: str) -> str:
    """The recorded sentence for a digest that is not one of its algorithm."""
    expected = HASH_HEX_LENGTHS.get(str(algorithm).strip().upper())
    length = f"{expected} hexadecimal characters" if expected else "the algorithm's own length"
    named = safe_finding_value(algorithm)
    return (
        f"the {named} indicator for {safe_finding_value(value)!r} is not in the exported "
        f"bundle: {named} is {length}, and a consumer matching on it will never match this "
        f"value. It is unchanged in the judge's own bundle."
    )


def unpublishable_domain_sentence(fqdn: str) -> str:
    """The recorded sentence for a name somebody watched that no export may carry."""
    return (
        f"the domain indicator for {safe_finding_value(fqdn)!r} is not in the exported bundle: it "
        "is a name that does not resolve outside the analysed network. The report's network block "
        "keeps the row with the source that saw it."
    )


def minted_indicator_type(verdict: Any, *, suspicious: bool = False) -> str:
    """What one indicator this pipeline mints claims, for the verdict published.

    One function for every kind, because the answer is one answer: an endpoint
    or an artefact found in a run is a claim about that run, and a run that
    concluded the sample is benign publishes no indicator saying otherwise. The
    sample's own hash indicator is the verdict's word exactly
    (:func:`indicator_type_for`); everything else is that word softened by one
    step unless the row itself was flagged, because nothing but the verdict
    entitles this export to say "malicious activity".

    ``malicious-activity`` used to be the default for a URL and for every
    string row, so a Benign export told every blocklist that ten SSH algorithm
    identifiers were malicious.

    ``benign`` is the sample's own word and is not lent to anything else: a
    host a benign sample talked to is not thereby a benign host, and this
    export has no standing to say it is.
    """
    if suspicious and indicator_type_for(verdict) == "malicious-activity":
        return "malicious-activity"
    return "anomalous-activity"


def _observed(source: Any) -> bool:
    """Whether this row is somebody's observation rather than a string sweep's."""
    return str(source or "").strip().lower() in _OBSERVED_SOURCES


def _checked_kind(object_type: str, prop: str) -> str:
    """Which validity question this export can ask at this object path, or ``""``.

    Structural, in one place: a key quoted inside a path is the reader's
    business and a property is either one this export can ask about or one it
    carries as written. It used to be decided here by ``prop != "name"``, which
    reads the ``'MD5'`` of ``file:hashes.'MD5'`` as a file name's neighbour
    rather than as the key it is, and left the object types of every reference
    path out of the question entirely.
    """
    steps = _INDEX_STEP_RE.sub("", prop)
    direct = _DIRECT_PATHS.get(f"{object_type}:{steps}")
    if direct is not None:
        return direct
    if (
        object_type in _REFERENCE_OWNERS
        and steps.endswith(".value")
        and _REFERENCE_STEP_RE.search(steps)
    ):
        return _ENDPOINT_KIND
    return ""


def _pattern_endpoints(pattern: str) -> list[tuple[str, str, str, bool]]:
    """Every ``(kind, literal, operator, readable)`` a checked comparison names.

    A STIX pattern is not one comparison. ``[a] OR [b]``, an ``AND`` of two
    object paths and an ``IN`` list of several values are all one pattern with
    several endpoints in it, and an indicator is exported or not as a whole, so
    the caller answers for all of them.
    ``maljan.schemas.stix_pattern`` is what reads the syntax, here and in the
    validator both; what is kept here is this export's own question — which
    paths it has something true to ask about.
    """
    found: list[tuple[str, str, str, bool]] = []
    for comparison in read_comparisons(pattern):
        kind = _checked_kind(comparison.object_type, comparison.prop)
        if not kind:
            # An unreadable comparison names no path, so nothing says which
            # question to ask of it; it is declined rather than carried.
            if not comparison.readable:
                found.append((_ENDPOINT_KIND, comparison.literal, comparison.operator, False))
            continue
        found.append((kind, comparison.literal, comparison.operator, comparison.readable))
    return found


def _endpoint_is_readable(operator: str) -> bool:
    """Whether the right-hand side of this comparison is an endpoint at all."""
    return not any(word in operator for word in _UNREADABLE_OPERATORS)


def _endpoint_is_publishable(kind: str, literal: str) -> bool:
    """Whether an export could carry this value at all, whoever wrote it down.

    The validity question only — could this be the thing it claims to be. Who
    recorded the row is the corroboration question's business and is not asked
    here; the judge's own assertion is a source, and asking it would answer
    trivially.
    """
    if kind == "url":
        return host_is_public(url_host(literal))
    if kind == "domain-name":
        return host_is_public(literal)
    if kind == "email-addr":
        return email_is_publishable(literal)
    if kind == "file":
        return path_names_a_file(literal)
    if kind == _ENDPOINT_KIND:
        # A reference's value is whichever of the three it happens to be, so it
        # is asked the question that fits what is written, and a hardware
        # address is asked none of them.
        text = str(literal).strip()
        if _MAC_ADDRESS_RE.match(text):
            return True
        try:
            ipaddress.ip_address(text.strip("[]"))
        except ValueError:
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
    pattern = indicator.pattern or ""
    malformed = malformed_hash_in(pattern)
    if malformed is not None:
        algorithm, literal = malformed
        return (MALFORMED_HASH_CODE, malformed_hash_sentence(algorithm, literal))
    for kind, literal, operator, read in _pattern_endpoints(pattern):
        readable = read and _endpoint_is_readable(operator)
        if readable and _endpoint_is_publishable(kind, literal):
            continue
        code = _DECLINE_CODES.get(kind, UNPUBLISHABLE_ENDPOINT_CODE)
        words = _OBJECT_TYPE_WORDS.get(kind, "address")
        if not readable:
            return (code, unreadable_endpoint_sentence(literal, words, "the judge's own bundle"))
        if kind == "url":
            return (code, impossible_host_sentence(literal, "the judge's own bundle"))
        if kind == "email-addr":
            return (code, not_an_address_sentence(literal))
        if kind == "file":
            return (code, not_a_file_sentence(literal))
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
        corpus: Any = None,
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
                ip_ind = _indicator_for_ip(ip, report.verdict)
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
                            UNPUBLISHABLE_ENDPOINT_CODE,
                            impossible_host_sentence(url.url, "the report's network block"),
                        )
                    )
            for domain in report.network.domains[:40]:
                dom_ind = _indicator_for_domain(domain, report.verdict)
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
                            UNPUBLISHABLE_ENDPOINT_CODE,
                            unpublishable_domain_sentence(domain.fqdn),
                        )
                    )

        # 6) StringIOC → Indicator.
        #
        # Which values this run may publish at all. One rule, read once, and
        # every path that mints an indicator asks it: the network block above,
        # and the string rows here, which are the same values arriving by a
        # second road. A row here is string-derived by construction, so what it
        # needs is a second source, and these two sets are where one is found —
        # the network block's own answer for a name, and everything some other
        # producer in this run wrote down for every other kind.
        publishable_domains = _publishable_domains(report)
        corroborating = _corroborating_values(report, corpus)

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
                if not _accept_string_ioc(
                    ioc, pattern, file_name_kept, publishable_domains, corroborating
                ):
                    continue
                if pattern.lstrip().startswith("[file:name"):
                    file_name_kept += 1
                ind = Indicator(
                    name=f"{ioc.kind} {ioc.value[:32]}",
                    pattern=pattern,
                    pattern_type="stix",
                    # The one type rule every indicator this renderer mints
                    # goes through. A string-derived artefact is nobody's
                    # observation of activity and is never flagged suspicious,
                    # so it is ``anomalous-activity`` under every verdict —
                    # ``benign`` is the sample's own word and is not lent to
                    # anything else. It used to be minted ``malicious-activity``
                    # whatever the run concluded.
                    indicator_types=[minted_indicator_type(report.verdict)],
                )
                # String-derived by construction, and only here at all because
                # a second source knew the value; the band reads the pattern
                # and the rank reads that origin, so it never outranks a row
                # the sandbox watched.
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
        capped = _within_the_indicator_cap(objects, order, ledger=ledger)
        if capped is objects:
            return Bundle(objects=objects)
        # Only what the cap orphaned is left to sweep, and it is the cap's
        # doing rather than a defect of anybody's bundle — so it is counted
        # under a reason of its own. Counted it must be: the pass used to run
        # here with no ledger at all, so this sweep's losses appeared in no
        # total. The cap's own removals are counted beside them, under
        # ``indicator_cap_removed``, so every object that left this bundle
        # left under a name.
        return Bundle(
            objects=enforce_bundle_integrity(capped, ledger=ledger, dropped_as=CAP_ORPHAN_REASON)
        )

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


# The network kinds, and the kinds the string sweep types a row as. The second
# tuple mirrors ``StringIOC.kind``: a kind added there with no answer in
# :func:`indicator_publish_reason` is a kind that falls past the publish rule,
# which is how ten SSH algorithm identifiers left a Benign run as e-mail
# addresses typed ``malicious-activity``.
NETWORK_KINDS: tuple[str, ...] = ("domain", "ip", "url")
STRING_IOC_KINDS: tuple[str, ...] = (
    "url",
    "domain",
    "ip",
    "email",
    "path",
    "registry",
    "mutex",
    "command",
    "secret",
    "crypto_wallet",
    "other",
)


def indicator_pattern(kind: str, value: str) -> str | None:
    """The STIX pattern for one indicator value, or ``None`` for a kind with none.

    The one place in the tree a pattern is written. A path that wrote its own
    would be a path that had not asked :func:`indicator_publish_reason` first,
    which is how a version number out of a strings table came to be exported as
    malicious infrastructure two sections after the network block had refused
    the same address, and how the e-mail rows were exported with no rule asked
    at all. ``tests/unit/reporting/test_one_network_publish_rule.py`` fails if a
    second place starts writing one.

    "secret" and "crypto_wallet" are deliberately not patterned. STIX 2.1 has
    no SCO for a leaked credential or a wallet address, and inventing a custom
    object would produce a bundle that no consumer can ingest — worse than
    omitting it, because it looks importable and is not. Both kinds are carried
    in the consolidated IOC table instead, where they are typed and readable.
    """
    quoted = _escape_stix(value)
    if kind == "url":
        return f"[url:value = '{quoted}']"
    if kind == "domain":
        return f"[domain-name:value = '{quoted}']"
    if kind == "email":
        return f"[email-addr:value = '{quoted}']"
    if kind == "mutex":
        return f"[mutex:name = '{quoted}']"
    if kind == "registry":
        return f"[windows-registry-key:key = '{quoted}']"
    if kind == "path":
        return f"[file:name = '{quoted}']"
    if kind != "ip":
        return None
    try:
        family = "ipv6-addr" if ipaddress.ip_address(value.strip()).version == 6 else "ipv4-addr"
    except ValueError:
        family = "ipv4-addr"
    return f"[{family}:value = '{quoted}']"


# A mailbox: a local part, one ``@``, and a domain part. Deliberately the
# syntax and nothing more — whether anything could answer for the domain is the
# host rule's question, asked separately below, and whether anybody but the
# sample's own bytes knows the address is the corroboration question's.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@([A-Za-z0-9.\-]{1,255})$")


def email_is_publishable(value: Any) -> bool:
    """Whether this literal is an address at all, and one that could exist.

    A string sweep reads any run of bytes with an ``@`` in it as a mailbox:
    ``aes128-gcm@openssh.com`` is an SSH algorithm identifier and
    ``z@D.setdefault`` is a fragment of Python source. The syntax question
    catches what is not an address; the domain part goes through the same host
    rule a domain indicator does, so a mailbox at a name nothing outside the
    analysed network could answer for is refused the way that name would be.
    """
    text = str(value or "").strip()
    match = _EMAIL_RE.match(text)
    if match is None:
        return False
    local = text.rsplit("@", 1)[0]
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return host_is_public(match.group(1))


# A label of a name as a program writes one. Host names are written in lower
# case wherever they are written — DNS does not distinguish case and nothing
# capitalises one — and the last label of a name that could exist is letters or
# a punycode label.
_LOWER_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
_LAST_LABEL_RE = re.compile(r"^(?:[a-z]{2,}|xn--[a-z0-9-]+)$")


def reads_as_a_host_in_the_bytes(domain: Any) -> bool:
    """Whether a name lifted out of a file reads as a host rather than as code.

    Asked only of a value the string sweep produced, where the capitalisation
    is the program's own and therefore says something. ``D.setdefault`` and
    ``r.Regsvr`` are attribute accesses in embedded source; ``openssh.com`` and
    ``crl.sectigo.com`` are names. The host rule cannot tell them apart — its
    last-label test is deliberately a shape rather than a list of TLDs, and
    ``setdefault`` is shaped exactly like one — and this can: an identifier
    capitalises the thing it is reaching into, and a host name never does.

    Not asked of a name anybody observed, and not asked of the judge's own
    objects: a model writing ``Example.COM`` has written a host, and refusing
    it would be this rule answering a question about capitalisation that only
    means something in a byte image.
    """
    labels = str(domain or "").strip().split(".")
    if len(labels) < 2 or not all(_LOWER_LABEL_RE.match(label) for label in labels):
        return False
    return _LAST_LABEL_RE.match(labels[-1]) is not None


def path_names_a_file(value: Any) -> bool:
    """Whether this literal names a file rather than a directory or a root.

    ``/Users/``, ``C:\\`` and a bare drive letter name a place, not a file, and
    a consumer matching on ``file:name`` can do nothing with one. A trailing
    separator is the tell every one of them carries.
    """
    text = str(value or "").strip()
    if not text or text.endswith(("/", "\\")):
        return False
    last = re.split(r"[\\/]", text)[-1]
    return bool(last) and re.fullmatch(r"[A-Za-z]:", last) is None


def indicator_publish_reason(
    kind: str,
    value: str,
    source: Any,
    reputation: Any = None,
    *,
    corroborated_by: str = "",
) -> str | None:
    """Why this run may publish one indicator of ``kind``, or ``None``.

    One rule for every kind the platform mints, and every minting path asks it:
    the network block's own rows, the string rows that reach the bundle through
    ``static.interesting_strings``, and the judge's own indicator objects. It
    used to answer for the three network kinds only, and everything else — an
    e-mail address, a file name, a registry key, a mutex — fell past it into
    the cap's file-name band and was exported with no question asked.

    Two halves, in this order. Could this value be the thing it claims to be:
    a host that could exist, a mailbox, a path naming a file. And does anything
    but the sample's own byte image know it: a sandbox observation, an analyst
    claim citing evidence that holds it, a reputation record. ``source`` is who
    recorded the row, and ``corroborated_by`` is what a caller found for a row
    whose source is by construction the string sweep.
    """
    if kind == "domain":
        if not host_is_public(value):
            return None
        return corroboration_reason(source, reputation, value)
    if kind == "ip":
        return ip_corroboration_reason(value, source, reputation)
    if kind == "url":
        return url_corroboration_reason(value, source, reputation)
    if kind == "email":
        if not email_is_publishable(value):
            return None
        # A mailbox the string sweep read out of the file answers one question
        # more than one the judge asserted: whether its domain part reads as a
        # host at all. The capitalisation in a byte image is the program's own,
        # and an attribute access capitalises what it reaches into.
        if str(source or "").strip().lower() in (
            "",
            "strings",
        ) and not reads_as_a_host_in_the_bytes(str(value).rsplit("@", 1)[-1]):
            return None
    if kind == "path" and not path_names_a_file(value):
        return None
    if kind not in STRING_IOC_KINDS or indicator_pattern(kind, value) is None:
        return None
    if str(source or "").strip().lower() not in ("", "strings"):
        return str(source)
    return corroborated_by or None


def _stix_pattern_for_string_ioc(ioc: StringIOC) -> str | None:
    return indicator_pattern(ioc.kind, ioc.value)


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
        and indicator_publish_reason("domain", domain.fqdn, domain.source, domain.reputation)
        is not None
    )


# Where a second source for a string row is looked for. A section built from
# an analyst's own artefact or finding is a claim that cites evidence; a
# section built from a tool's output is the string sweep's own table arriving
# under another heading, and reading those would let every string corroborate
# itself.
# Where a second source for a string row is looked for. A section built from
# an analyst's own artefact or finding is a claim; the ledger entries it cites
# are what the claim stands on, and only the entries of a tool that is not the
# string sweep can hold a value up. A section built from the sweep's own output
# is the thing being corroborated, and reading it would let every string
# corroborate itself.
_ANALYST_SECTION_SOURCES = ("artifact:", "finding", "agent")

# The tools whose output *is* the string sweep. An analyst quoting one of these
# in a finding has quoted the sweep's own table back, which is one source said
# twice.
_STRING_SWEEP_TOOLS = ("strings", "iocs_from_file", "iocs_from_text")


def _section_text(section: Any) -> list[str]:
    """Everything one evidence section prints, as plain strings."""
    parts = [str(getattr(section, "text", "") or "")]
    parts.extend(str(item) for item in (getattr(section, "items", None) or []))
    for row in getattr(section, "rows", None) or []:
        parts.extend(str(cell) for cell in row)
    return parts


def _corroborating_values(report: Any, corpus: Any = None) -> str:
    """Everything a second source in this run recorded, lowercased, built once.

    One haystack per render, searched for whole values rather than by
    containment, and deliberately narrow about what goes into it:

    * what a sandbox watched — the process tree, the registry modifications,
      the file operations, the notable API rows;
    * what a persistence mechanism names;
    * the output of a ledger entry that is **not** the string sweep's and that
      an analyst cited in an artefact or a finding.

    The third is the one that had to be narrowed. Reading the analyst's own
    prose corroborated anything an analyst quoted, and analysts quote the
    strings table — one sentence carrying a parse artefact out of embedded
    source published it as an indicator. A claim is a second source only when
    it points at an entry that saw the value, and the sweep's own entries are
    not that.
    """
    parts: list[str] = []
    dynamic = getattr(report, "dynamic", None)
    if dynamic is not None:
        for node in list(getattr(dynamic, "process_tree", None) or []):
            parts.extend(_process_text(node))
        for mod in list(getattr(dynamic, "registry_mods", None) or []):
            parts.extend(str(getattr(mod, field, "") or "") for field in ("key", "value", "data"))
        for operation in list(getattr(dynamic, "file_operations", None) or []):
            if isinstance(operation, dict):
                parts.extend(str(value) for value in operation.values())
        for api in list(getattr(dynamic, "notable_apis", None) or []):
            if isinstance(api, dict):
                parts.extend(str(value) for value in api.values())
    for mechanism in list(getattr(report, "persistence", None) or []):
        parts.append(str(getattr(mechanism, "target", "") or ""))
        parts.append(str(getattr(mechanism, "payload", "") or ""))

    sections = list(getattr(report, "sections", None) or [])
    cited: set[str] = set()
    # The cited entries a section already contributed text for, so the corpus
    # is read only where the stored record has nothing left.
    drawn: set[str] = set()
    for section in sections:
        origin = str(getattr(section, "source", "") or "").strip().lower()
        if origin.startswith(_ANALYST_SECTION_SOURCES):
            cited.update(str(eid) for eid in (getattr(section, "evidence_ids", None) or []))
    for section in sections:
        origin = str(getattr(section, "source", "") or "").strip().lower()
        if not origin.startswith("tool:"):
            continue
        if origin.removeprefix("tool:") in _STRING_SWEEP_TOOLS:
            continue
        if not cited.intersection(str(eid) for eid in (section.evidence_ids or [])):
            continue
        drawn.update(str(eid) for eid in (section.evidence_ids or []))
        parts.extend(_section_text(section))

    # What the run saw, for the cited entries whose stored output is gone. The
    # evidence byte budget blanks an entry after the model has read it, so an
    # answer an analyst cited can leave no section at all and a value a tool
    # really returned stops corroborating anything. The narrowing is unchanged
    # — an analyst has to have cited it, and the string sweep's own entries are
    # still not a second source — only the place the text is read from.
    if corpus is not None:
        for entry_id in sorted(cited - drawn):
            try:
                if str(corpus.tool_of(entry_id) or "") in _STRING_SWEEP_TOOLS:
                    continue
                parts.append(str(corpus.text_for(entry_id) or ""))
            except Exception:  # noqa: BLE001 — a weaker haystack, never a failed render
                continue
    return " ".join(part for part in parts if part).lower()


def _process_text(node: Any) -> list[str]:
    """One process node's name and command line, and its children's."""
    out = [str(getattr(node, "name", "") or ""), str(getattr(node, "command_line", "") or "")]
    for child in list(getattr(node, "children", None) or []):
        out.extend(_process_text(child))
    return out


def _accept_string_ioc(
    ioc: StringIOC,
    pattern: str,
    file_name_kept: int,
    publishable_domains: frozenset[str] = frozenset(),
    corroborating: str = "",
) -> bool:
    """Gate StringIOC → Indicator emission.

    Applies the same rules as :func:`maljan.pipeline.validation._indicator_problem`
    so the extended renderer cannot bypass the indicator noise floor. These IOCs
    come from the deterministic string scan rather than from a model, so there
    is nobody to hand a violation back to: the gate is the whole check. Mocking
    out the LLM (or any judge bundle path) no longer means the bundle ships with
    NDK build paths / bundled bytecode class refs / random short strings.

    Every kind asks the one publish rule as ``strings``, because that is what
    every row here is. A domain asks it through the network block's own answer,
    which is where the same name's reputation and its stronger source live; the
    others ask it directly, with whatever second source this run recorded. The
    addresses used to fall past all of this to a bare ``return True``, so a
    version number written with dots in it was exported as malicious
    infrastructure while the network block was refusing the very same address —
    and every kind that is not a network kind still did, which is how ten SSH
    algorithm identifiers left a Benign run as e-mail indicators.
    """
    stripped = pattern.lstrip()
    value = (ioc.value or "").strip()

    if ioc.kind == "domain":
        return value.lower().rstrip(".") in publishable_domains
    if ioc.kind == "url":
        host = _extract_url_host(value)
        if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
            return False

    # file:name: acceptance-based admission + per-report cap, asked before the
    # publish rule because its answer is about the shape of the value and the
    # budget, not about who saw it.
    if stripped.startswith("[file:name"):
        if file_name_kept >= MAX_FILE_NAME_INDICATORS:
            return False
        if not value:
            return False
        if COMPILE_ARTIFACT_RE.search(value):
            return False
        if FOREIGN_CLASS_REF_RE.match(value):
            return False
        if not _looks_like_real_path(value):
            return False

    # Whole value, never a slice of a longer one: a short mutex name or a bare
    # file name is otherwise "corroborated" by any token that happens to spell
    # it, which is the mistake the digest rule already fixed one kind at a time.
    corroborated = (
        "a second source in this run records it"
        if value and whole_value_in(value, corroborating)
        else ""
    )
    return (
        indicator_publish_reason(ioc.kind, value, "strings", corroborated_by=corroborated)
        is not None
    )


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


def _indicator_for_domain(domain: NetworkDomain, verdict: Any = "") -> Indicator | None:
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
    admitted = indicator_publish_reason("domain", fqdn, domain.source, domain.reputation)
    if admitted is None:
        # A run of bytes that has the shape of a hostname is not an
        # observation of infrastructure. One PE's string sweep put fifteen
        # such fragments into a published bundle, each as an indicator a
        # downstream consumer would block on. They stay in the report's
        # network block, labelled with where they came from; they are not
        # offered to the world until a second source knows the name.
        return None
    pattern = indicator_pattern("domain", fqdn)
    assert pattern is not None  # noqa: S101 - a domain always has one
    return Indicator(
        name=f"Domain {fqdn}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=[minted_indicator_type(verdict, suspicious=domain.is_suspicious)],
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


def _indicator_for_ip(ip: NetworkIP, verdict: Any = "") -> Indicator | None:
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
    admitted = indicator_publish_reason("ip", address, ip.source, ip.reputation)
    if admitted is None:
        return None
    pattern = indicator_pattern("ip", address)
    assert pattern is not None  # noqa: S101 - an address always has one
    return Indicator(
        name=f"IP {address}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=[minted_indicator_type(verdict, suspicious=ip.is_suspicious)],
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
    admitted = indicator_publish_reason("url", url.url, source, _host_reputation(report, host))
    if admitted is None:
        return None
    pattern = indicator_pattern("url", url.url)
    assert pattern is not None  # noqa: S101 - a URL always has one
    return Indicator(
        name=f"URL {url.url[:48]}",
        pattern=pattern,
        pattern_type="stix",
        # A URL used to be minted ``malicious-activity`` whatever the run
        # concluded, which is the one network kind that never asked.
        indicator_types=[minted_indicator_type(getattr(report, "verdict", ""), suspicious=True)],
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
