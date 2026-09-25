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
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from maljan.agents._indicator_denylists import (
    COMPILE_ARTIFACT_RE,
    FOREIGN_CLASS_REF_RE,
    HASH_HEX_LENGTHS,
    IOC_FILE_EXTENSIONS,
    IOC_OS_RESOURCE_PREFIXES,
    URL_DENY_HOSTS,
    malformed_hash_in,
    whole_value_in,
)
from maljan.analysis.technique_ids import attack_reference_id
from maljan.extractors.network_extractor import (
    address_is_publishable,
    corroboration_reason,
    host_is_public,
    ip_corroboration_reason,
    is_well_known_benign_host,
    url_corroboration_reason,
    url_host,
)
from maljan.pipeline.events import safe_finding_value
from maljan.reporting.models import (
    EmulatedStrings,
    MalwareReport,
    NetworkDomain,
    NetworkIP,
    NetworkURL,
    ProcessNode,
    StringIOC,
)
from maljan.schemas.judgement import indicator_type_for
from maljan.schemas.stix_models import (
    ATTACK_PATTERN_NAMESPACE,
    EVIDENCE_REFS_PROPERTY,
    AttackPattern,
    Bundle,
    File,
    Identity,
    Indicator,
    Malware,
    Note,
    ObservedData,
    Process,
    Relationship,
    Report,
    attack_pattern_id,
    crediting_only,
    get_utcnow,
    produced_by,
)
from maljan.schemas.stix_pattern import (
    object_path_problems,
    pattern_refusal,
    read_comparisons,
    stray_backslash_values,
    unknown_object_types,
)

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
# A ``created_by_ref`` naming an identity the bundle does not hold, which the
# export replaced with this platform's identity.
UNPUBLISHABLE_PRODUCER_CODE = "stix.unpublishable_producer"
# A judge credit naming an agent that did not name the technique, which the
# judge was asked about (``stix.credit_without_claim``) and kept.
UNPUBLISHABLE_CREDIT_CODE = "stix.unpublishable_credit"
# A judge object without a property the standard requires of it — a malware
# object with no ``is_family``, a file with neither ``hashes`` nor ``name`` —
# that the judge was asked about and kept absent. Published, the bundle is one a
# consumer may refuse; filled in, it says something the judge did not.
UNPUBLISHABLE_OBJECT_CODE = "stix.unpublishable_object"
# An indicator over something that is not an endpoint: a mailbox that is not
# one, a file name that names a directory or a root.
UNPUBLISHABLE_ARTEFACT_CODE = "stix.unpublishable_artefact"
# A ledger id the run's record cites for an exported object that the run's
# ledger does not hold. The export writes only ids a reader can follow.
EVIDENCE_REF_NOT_IN_LEDGER_CODE = "stix.evidence_ref_not_in_ledger"
# A digest literal that is not a digest of the algorithm it is written under.
MALFORMED_HASH_CODE = "stix.malformed_hash"
# A pattern over an object type STIX does not have, which the judge was asked
# about under ``stix.unknown_observable_type`` and kept. This row is the
# export's decision rather than the judge's answer, so it has a code of its own.
UNPUBLISHABLE_PATTERN_CODE = "stix.unpublishable_pattern"
# A judge indicator naming a value the one publish rule refuses — a host only
# the file's strings carry, a command line. Not exported, recorded, and
# unchanged in the judge's own bundle; the IOC table and /iocs print the same
# answer for the value.
UNPUBLISHED_VALUE_CODE = "stix.indicator_not_published"

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
# pattern over any other STIX type is carried as the judge wrote it — there is
# no true question to ask of it, and inventing one would decline an object for
# a reason that is not so. A pattern over a type STIX does not have is a
# different case and is declined before this table is read: ``ipv-addr`` is
# not an unasked path, it is an address the endpoint question never saw.
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


class Declined(tuple[str, str]):
    """One thing the export left out: ``(code, sentence)``, and who wrote it down.

    A pair, so every reader that unpacks ``code, why`` still does. ``by`` is the
    producer of the object that was declined: the judge for the judge's own
    objects, and for a row of the report's network block the source that
    recorded it — a sandbox, an analyst. Those rows used to be filed under the
    judge, which wrote none of them.
    """

    by: str

    def __new__(cls, code: str, why: str, *, by: str | None = "judge") -> Declined:
        row = super().__new__(cls, (code, why))
        row.by = str(by or "judge")
        return row


def impossible_host_sentence(value: str, whose: str) -> str:
    """The recorded sentence for a URL no host could ever answer for.

    A value with no scheme is not a URL at all, and is said to be that rather
    than to name a host that could not exist.
    """
    if "://" not in str(value):
        return (
            f"the URL indicator for {safe_finding_value(value)!r} is not in the exported bundle: "
            "it is not a URL — it has no scheme — so there is no host in it to ask about; a "
            "host is written as domain-name:value. It is unchanged in "
            f"{whose}."
        )
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


def shaped_endpoint_sentence(value: str, kind_words: str, operator: str) -> str:
    """The recorded sentence for an endpoint written as a shape rather than a value."""
    return (
        f"the {kind_words} indicator for {safe_finding_value(value)!r} is not in the exported "
        f"bundle: it compares with {safe_finding_value(operator.upper())}, which names every "
        "endpoint that fits it rather than one, so this export could not ask whether it may "
        "carry the endpoint. It is unchanged in the judge's own bundle."
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


def unknown_observable_type_sentence(pattern: str, types: list[str]) -> str:
    """The recorded sentence for a pattern over a type STIX does not have."""
    named = ", ".join(repr(safe_finding_value(t)) for t in types)
    return (
        f"the indicator {safe_finding_value(pattern)!r} is not in the exported bundle: it "
        f"compares {named}, which is not a STIX Cyber-observable type, so no consumer holds "
        "an object it could match and this export could not ask whether it may carry the "
        "value. It is unchanged in the judge's own bundle."
    )


def unknown_object_path_sentence(pattern: str, problems: list[str]) -> str:
    """The recorded sentence for a pattern over a path its type does not have."""
    return (
        f"the indicator {safe_finding_value(pattern)!r} is not in the exported bundle: "
        f"{safe_finding_value('; '.join(problems))}, so the pattern matches nothing a consumer "
        "holds. It is unchanged in the judge's own bundle."
    )


def stray_backslash_sentence(pattern: str, values: list[str]) -> str:
    """The recorded sentence for a pattern whose value writes a backslash the grammar refuses."""
    named = "a value" if len(values) == 1 else f"{len(values)} values"
    return (
        f"the indicator {safe_finding_value(pattern)!r} is not in the exported bundle: it "
        f"quotes {named} with a backslash a STIX pattern cannot read — inside a quoted value "
        "the grammar escapes only the quote and the backslash — so a consumer's parser would "
        "refuse the whole pattern. It is unchanged in the judge's own bundle."
    )


def _unasked_findings(report: Any, code: str) -> list[str]:
    """The run's unresolved judge findings under ``code`` the judge was never shown.

    Read from ``run_summary.validation.unresolved``, where a finding the answer
    to the judge's only retry raised first is recorded ``"asked": "false"``.
    Each is its ``subject`` — the technique a credit is for, the malware
    object's name — and, for a row stored before rows carried one, its message.
    """
    summary = getattr(report, "run_summary", None)
    validation = summary.get("validation") if isinstance(summary, dict) else None
    rows = validation.get("unresolved") if isinstance(validation, dict) else None
    return [
        str(row.get("subject") or row.get("message") or "")
        for row in rows or []
        if isinstance(row, dict)
        and row.get("code") == code
        and str(row.get("agent") or "judge") == "judge"
        and str(row.get("asked") or "") == "false"
    ]


def _names_the_technique(sentence: str, technique: str) -> bool:
    """Whether ``sentence`` names ``technique`` as an id of its own, not a prefix."""
    return bool(re.search(rf"(?<![\w.]){re.escape(technique)}(?![\w.]\w)", sentence))


def _without_unconfirmed_credit(
    obj: Any, credit: Any, *, asked: bool = True
) -> tuple[Any, Declined]:
    """A copy of a judge relationship carrying only the credits a source stands behind.

    ``asked`` is whether the judge was shown the credit question. The sentence
    says which: "kept the credit when asked" of a credit it was never asked
    about is a statement the run's record does not support.
    """
    from maljan.pipeline.validation import credited_agents

    kept = [name for name in credited_agents(obj) if name not in credit.uncredited]
    copy = crediting_only(obj, kept)
    names = ", ".join(repr(safe_finding_value(n)) for n in credit.uncredited)
    what_the_judge_did = (
        "the judge kept the credit when asked"
        if asked
        else "the judge was not asked about it: the credit first appeared in an answer no "
        "turn was left to question"
    )
    return copy, Declined(
        UNPUBLISHABLE_CREDIT_CODE,
        f"the credit to {names} for {safe_finding_value(credit.technique)} is not in the "
        f"exported bundle: no source by that name named the technique in this run, and "
        f"{what_the_judge_did}. It is unchanged in the judge's own bundle.",
    )


def _missing_what_the_standard_requires(obj: Any, unasked: Sequence[str] = ()) -> str:
    """The recorded sentence for a judge object the standard refuses as written, or ``""``.

    ``unasked`` is the run's ``stix.is_family_missing`` findings the judge was
    never shown; the sentence says it was asked only when it was.
    """
    kind = str(getattr(obj, "type", "") or "")
    label = safe_finding_value(getattr(obj, "name", "") or getattr(obj, "id", ""))
    if kind == "malware" and getattr(obj, "is_family", None) is None:
        named = f"{safe_finding_value(str(getattr(obj, 'name', '') or '').strip())!r}"
        what_the_judge_did = (
            "the judge was not asked about it: it first appeared in an answer no turn was "
            "left to question"
            if any(
                said == str(getattr(obj, "name", "") or "").strip() or named in said
                for said in unasked
            )
            else "the judge kept it absent when asked"
        )
        return (
            f"the malware object {label!r} is not in the exported bundle: it does not say "
            f"is_family, which STIX requires, and {what_the_judge_did}. The "
            "export stands the platform's own sample object in for it, and the judge's "
            "relationships that named it move onto that object unchanged. It is unchanged "
            "in the judge's own bundle."
        )
    if kind == "file" and not getattr(obj, "hashes", None) and not getattr(obj, "name", None):
        return (
            f"the file {label!r} is not in the exported bundle: it has neither hashes nor "
            "name, and STIX needs one of them to say which file it is. It is unchanged in the "
            "judge's own bundle."
        )
    if kind in _ABOUT_OBJECTS and not getattr(obj, "object_refs", None):
        return (
            f"the {kind} {safe_finding_value(getattr(obj, 'abstract', '') or label)!r} is not "
            "in the exported bundle: it names no object it is about, which STIX requires. It "
            "is unchanged in the judge's own bundle."
        )
    return ""


# The objects STIX defines as being about others, each of which must name at
# least one in ``object_refs``.
_ABOUT_OBJECTS = frozenset({"note", "opinion", "grouping", "report"})


def _names_nothing_sentence(obj: Any) -> str:
    """The recorded sentence for an object about others that names none of them."""
    kind = safe_finding_value(getattr(obj, "type", "") or "object")
    label = safe_finding_value(
        getattr(obj, "abstract", "") or getattr(obj, "name", "") or getattr(obj, "id", "")
    )
    return (
        f"the {kind} {label!r} is not in the exported bundle: every object it was about is "
        "outside this export, and STIX requires it to name at least one. It is unchanged in "
        "the judge's own bundle."
    )


def _names_any(obj: Any, ids: set[str]) -> bool:
    """Whether a relationship names one of ``ids`` at either end."""
    if not ids or getattr(obj, "type", "") != "relationship":
        return False
    return str(getattr(obj, "source_ref", "")) in ids or str(getattr(obj, "target_ref", "")) in ids


def _onto(edge: Any, stood_in: set[str], stand_in: str) -> Any:
    """A copy of a judge relationship naming the stand-in where it named a declined object."""
    update = {
        key: stand_in
        for key in ("source_ref", "target_ref")
        if str(getattr(edge, key, "")) in stood_in
    }
    return edge.model_copy(update=update)


def replaced_producer_sentence(obj: Any, named: str) -> str:
    """The recorded sentence for a producer the bundle does not hold, replaced."""
    kind = safe_finding_value(getattr(obj, "type", "") or "object")
    label = safe_finding_value(getattr(obj, "name", "") or getattr(obj, "id", ""))
    return (
        f"the {kind} {label!r} names {safe_finding_value(named)!r} as its producer, an "
        "identity this bundle does not hold, so the export names this platform's identity "
        "instead. It is unchanged in the judge's own bundle."
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
    unknown = unknown_object_types(pattern)
    if unknown:
        return (
            UNPUBLISHABLE_PATTERN_CODE,
            unknown_observable_type_sentence(pattern, unknown),
        )
    wrong_paths = object_path_problems(pattern)
    if wrong_paths:
        return (UNPUBLISHABLE_PATTERN_CODE, unknown_object_path_sentence(pattern, wrong_paths))
    stray = stray_backslash_values(pattern)
    if stray:
        return (UNPUBLISHABLE_PATTERN_CODE, stray_backslash_sentence(pattern, stray))
    malformed = malformed_hash_in(pattern)
    refusal = "" if malformed is not None else pattern_refusal(pattern)
    if refusal:
        return (
            UNPUBLISHABLE_PATTERN_CODE,
            f"the indicator {safe_finding_value(pattern)!r} is not in the exported bundle: the "
            f"STIX pattern grammar refuses it ({safe_finding_value(refusal)}), so a consumer's "
            "parser would refuse it whole. It is unchanged in the judge's own bundle.",
        )
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
        if read and not readable:
            # Read whole, and written as a shape: a ``LIKE`` or ``MATCHES``
            # names every endpoint that fits it, which is not one the host
            # question can be asked of.
            return (code, shaped_endpoint_sentence(literal, words, operator))
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


def _judge_indicator_unpublished(
    report: Any, indicator: Indicator, corroborating: str
) -> tuple[str, str] | None:
    """Why the one publish rule declines this judge indicator, or ``None``.

    Every value a comparison of a kind the rule answers names is asked it,
    whatever the operator — ``=``, each member of an ``IN`` list, the operand
    of ``!=``, ``<`` or ``>`` — exactly as the report's own row for the value
    is asked (:func:`judge_value_answer`); one refused value declines the
    indicator. The IOC table and ``/iocs`` still read ``=`` alone; the export
    asks every operator, so no operator carries a value the rule refused. A
    comparison of a kind the IOC table has no row for (a port, a property of a
    process) is left to the host question and the grounding check before this.
    """
    named = safe_finding_value(getattr(indicator, "name", "") or indicator.pattern)
    for value in rule_values(indicator.pattern or ""):
        answer = judge_value_answer(report, value.kind, value.value, corroborating)
        if answer == "yes":
            continue
        return (
            UNPUBLISHED_VALUE_CODE,
            f"the judge's indicator {named!r} names {safe_finding_value(value.value)!r}, "
            f"which this run does not publish ({safe_finding_value(answer)}). It is not in "
            "the exported bundle and is unchanged in the judge's own bundle.",
        )
    # A comparison of a kind the rule answers for, written as a shape — a
    # ``LIKE`` with its wildcards, a ``MATCHES`` expression, a range — names
    # every value that fits it and none in particular. The rule answers for a
    # value, and ``'%whoami%'`` is not the value ``whoami``: asking it about the
    # text between the wildcards would publish a match nobody put to it, and
    # asking nothing would let a shape carry a value the ``=`` form of the same
    # indicator is refused. It is declined, with the reason, as a refused value is.
    for comparison in read_comparisons(indicator.pattern or ""):
        if not _exported_kind(comparison)[0] or _endpoint_is_readable(comparison.operator):
            continue
        return (
            UNPUBLISHED_VALUE_CODE,
            f"the judge's indicator {named!r} compares {safe_finding_value(comparison.path)} "
            f"{safe_finding_value(comparison.operator.upper())} "
            f"{safe_finding_value(comparison.literal)!r}, which names the values that fit it "
            "rather than one value. The one publish rule answers for a value, so it cannot say "
            "this run may publish what the pattern matches. It is not in the exported bundle "
            "and is unchanged in the judge's own bundle.",
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
        corpus: Any = None,
        technique_sources: Any = None,
        technique_evidence: Mapping[str, Sequence[str]] | None = None,
        ledger_ids: Sequence[str] | None = None,
    ) -> Bundle:
        """Render the extended bundle.

        ``ledger`` is an optional ``TruncationLedger``; the integrity pass at the
        end records what it removed there, which is the measurement the
        repair-versus-reject claim needs. This is the *second* place the pass
        runs — the judge's
        own post-process is the first — so both must report or the aggregate
        undercounts.

        ``technique_evidence`` is ``{technique id: [ledger id, ...]}`` as the
        run's record ties them (``pipeline.evidence_summary.technique_evidence``).
        The ids are written on the sample's ``uses`` edge to that technique,
        and the attribution's family ids on a malware object this export mints
        from the family name, as ``x_maljan_evidence_refs``. Nothing else gets
        the property, and nothing is matched by value or read out of text.

        ``ledger_ids`` is the run's ledger, in its order. Every id the export
        writes is one it holds, in that order; with no ledger no id is written.
        A family id it does not hold is recorded as
        ``stix.evidence_ref_not_in_ledger`` and left out.
        """
        with one_reading(report):
            return self._render(
                report,
                base_bundle,
                ledger=ledger,
                corpus=corpus,
                technique_sources=technique_sources,
                technique_evidence=technique_evidence,
                ledger_ids=ledger_ids,
            )

    def _render(
        self,
        report: MalwareReport,
        base_bundle: Bundle | None = None,
        *,
        ledger: Any | None = None,
        corpus: Any = None,
        technique_sources: Any = None,
        technique_evidence: Mapping[str, Sequence[str]] | None = None,
        ledger_ids: Sequence[str] | None = None,
    ) -> Bundle:
        objects: list[Any] = []
        self.unlinked = []
        self.declined = []
        ledger_order = {eid: i for i, eid in reversed(list(enumerate(ledger_ids or [])))}
        minted_family_id: str | None = None
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
        # The judge's malware objects the export declines for a property the
        # standard requires, and the judge's relationships that name them. The
        # platform's own sample object stands in for such an object, and the
        # relationships move onto it unchanged — confidence, basis and credits
        # as the judge wrote them — so the export's malware object uses what the
        # judge said the sample uses and the judge's number is published.
        stood_in: set[str] = set()
        awaiting_stand_in: list[Any] = []
        if base_bundle is not None and not benign:
            stood_in = {
                str(obj.id)
                for obj in base_bundle.objects
                if getattr(obj, "type", "") == "malware"
                and _missing_what_the_standard_requires(obj)
            }
        # The run's second-source record, read once for the judge's values here
        # and for the string rows below: one rule, asked of both.
        judge_corroborating = _corroborating_values(report, corpus)
        if base_bundle is not None:
            self._normalize_judge_timestamps(base_bundle.objects)
            remap = _technique_remap(report, base_bundle)
            gone = _rejected_pattern_ids(base_bundle, remap)
            # A credit the judge was asked about and kept, naming an agent no
            # source of that name stands behind. The judge's own bundle keeps
            # it; the export's copy of the relationship does not carry it, so
            # no surface prints an agent as having named a technique it never
            # named.
            from maljan.pipeline.validation import unconfirmed_credits

            unconfirmed = {
                credit.index: credit
                for credit in unconfirmed_credits(base_bundle, technique_sources)
            }
            unasked_credits = _unasked_findings(report, "stix.credit_without_claim")
            for position, obj in enumerate(base_bundle.objects):
                kind = getattr(obj, "type", "")
                if position in unconfirmed:
                    credit = unconfirmed[position]
                    obj, row = _without_unconfirmed_credit(
                        obj,
                        credit,
                        asked=not any(
                            said.upper() == str(credit.technique).upper()
                            or _names_the_technique(said, str(credit.technique))
                            for said in unasked_credits
                        ),
                    )
                    self.declined.append(row)
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
                incomplete = _missing_what_the_standard_requires(
                    obj, _unasked_findings(report, "stix.is_family_missing")
                )
                if incomplete:
                    self.declined.append(Declined(UNPUBLISHABLE_OBJECT_CODE, incomplete))
                    continue
                if _points_at(obj, gone):
                    continue
                moved, technique = _relinked(obj, remap)
                if technique:
                    linked.add(technique)
                if _names_any(moved, stood_in):
                    # The judge's edge from a malware object the export
                    # declined: it moves to the platform's stand-in, unchanged,
                    # once that object exists (below).
                    awaiting_stand_in.append(moved)
                    continue
                if isinstance(moved, Indicator):
                    declined = _judge_indicator_problem(moved) or _judge_indicator_unpublished(
                        report, moved, judge_corroborating
                    )
                    if declined:
                        self.declined.append(declined)
                        continue
                    carried.append(moved)
                    continue
                objects.append(moved)
            self.unlinked = _unlinked_techniques(base_bundle, gone)

        # 2) Identity SDO for Maljan itself. ``system`` is STIX's word for a
        #    producer that is software; ``software`` is not in the vocabulary.
        #    One id on every export, so a consumer holding several reads one
        #    producer rather than one per run.
        identity = Identity(
            id=PRODUCER_IDENTITY_ID,
            name="Maljan",
            identity_class="system",
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
                # Named from the family, so the family's own citations are
                # this object's; a name from the category or ``unknown`` has
                # none in the record.
                x_maljan_evidence_refs=(
                    self._family_refs(report, ledger_order) if report.attribution.family else None
                ),
            )
            objects.append(malware_obj)
            malware_id = malware_obj.id
            if report.attribution.family:
                minted_family_id = malware_obj.id
        if malware_id is not None:
            objects.extend(_onto(edge, stood_in, malware_id) for edge in awaiting_stand_in)

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
            for ip in report.network.ips:
                ip_ind = _indicator_for_ip(ip, report.verdict, report)
                if ip_ind is not None:
                    _queue(ip_ind, _BAND_NETWORK, ip.source)
            for url in report.network.urls:
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
                        Declined(
                            UNPUBLISHABLE_ENDPOINT_CODE,
                            impossible_host_sentence(url.url, "the report's network block"),
                            by=url.source,
                        )
                    )
            for domain in report.network.domains:
                dom_ind = _indicator_for_domain(domain, report.verdict, report)
                if dom_ind is not None:
                    _queue(dom_ind, _BAND_NETWORK, domain.source)
                    continue
                # The name a sandbox resolved stays in the report either way;
                # what is recorded is that the export does not carry it, and
                # the reason. A name only the string sweep produced is held
                # back by the corroboration rule, which is the rule working.
                if _observed(domain.source) and not host_is_public(domain.fqdn):
                    self.declined.append(
                        Declined(
                            UNPUBLISHABLE_ENDPOINT_CODE,
                            unpublishable_domain_sentence(domain.fqdn),
                            by=domain.source,
                        )
                    )

        # 5.5) The host of every URL this run publishes, where the network
        #      block has no row for it: the host follows the URL's decision.
        #      The judge's own URL indicators count, which is the case that
        #      published two C2 URLs and neither of their names.
        listed_domains = {
            d.fqdn.strip().lower().rstrip(".")
            for d in (report.network.domains if report.network is not None else [])
        }
        for host, (_url, source) in published_url_hosts(report).items():
            if host in listed_domains:
                continue
            admitted = indicator_publish_reason(
                "domain", host, source, **emulation_kwargs(report, "domain", host)
            )
            pattern = indicator_pattern("domain", host)
            if admitted is None or pattern is None:
                continue
            _queue(
                Indicator(
                    name=f"Domain {host}",
                    pattern=pattern,
                    pattern_type="stix",
                    indicator_types=[minted_indicator_type(report.verdict, suspicious=True)],
                    description=admitted,
                ),
                _BAND_NETWORK,
                source,
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
        corroborating = judge_corroborating

        # Apply the same acceptance-based filter
        # used by the judge bundle postprocess so deterministic
        # interesting_strings can't smuggle noise (NDK build paths, bundled
        # bytecode class refs, random short strings) into the public STIX
        # bundle. Without this, the 2026-05-23 noise audit's 49-noisy-paths
        # FP reappears for every sample that bundles NDK-compiled libraries.
        if report.static is not None:
            file_name_kept = 0
            for ioc in report.static.interesting_strings:
                pattern = _stix_pattern_for_string_ioc(ioc)
                if pattern is None:
                    continue
                if not _accept_string_ioc(
                    ioc, pattern, file_name_kept, publishable_domains, corroborating, report
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
        #    The processes and their images are objects of the bundle, named by
        #    ``object_refs``. The sandbox block carries no observation time, so
        #    both ends are the time the report was built — the latest the
        #    observation can have been — and one run is one observation.
        if report.dynamic is not None and report.dynamic.process_tree:
            observables = _processes_to_observables(report.dynamic.process_tree)
            if observables:
                objects.extend(observables)
                objects.append(
                    ObservedData(
                        first_observed=report.generated_at,
                        last_observed=report.generated_at,
                        number_observed=1,
                        object_refs=[obs.id for obs in observables],
                    )
                )

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

        # 8.5) The ledger entries the record ties to each technique, on the
        #      sample's ``uses`` edge to it. On the edge and not on the
        #      attack-pattern: the attack-pattern's id is the same in every
        #      export, and one run's evidence written on it would make two
        #      bundles disagree about one object. The edge is this run's claim.
        #      Every object is passed through, so the property on the export
        #      is only ever the record's: a judge object reaches here without
        #      it (``judge_postprocess.PLATFORM_ONLY_PROPERTIES``), and nothing
        #      else is kept.
        objects = _with_record_evidence(
            objects, malware_id, technique_evidence or {}, ledger_order, minted_family_id
        )

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
                            f"Severity {report.severity.rating}."
                            if report.severity
                            else "Severity not assessed."
                        )
                    ),
                    published=report.generated_at,
                    report_types=report_types_for(report.verdict),
                    object_refs=refs,
                )
            )

        # Referential-integrity + dedup pass over the assembled bundle — it
        # collapses indicators duplicated across the judge base bundle and the
        # renderer's synthesized set, and prunes any ref dangling from upstream
        # drops. See judge_postprocess.enforce_bundle_integrity.
        #
        # No count bounds the indicators after it. The export carries every
        # value the one publish rule publishes, which is every ``yes`` row of
        # the report's IOC table: a total cap of fifteen used to drop the
        # lowest-ranked of them, so the table and ``/iocs`` said ``yes`` for
        # values the bundle did not carry.
        from maljan.agents.judge_postprocess import enforce_bundle_integrity

        objects = enforce_bundle_integrity(objects, ledger=ledger)
        _record_indicator_cap(ledger, removed=0)
        # A note, opinion, grouping or report is about the objects it names,
        # and STIX requires it to name at least one. The passes above take out
        # references to what the export declined; one left naming nothing is
        # an object the standard refuses, and it is declined with the reason
        # rather than exported so.
        objects = self._without_empty_references(objects)
        return Bundle(objects=_produced_by(objects, identity.id, self.declined))

    def _without_empty_references(self, objects: list[Any]) -> list[Any]:
        """``objects`` less every object whose required references are now empty."""
        while True:
            empty = {
                str(getattr(obj, "id", ""))
                for obj in objects
                if getattr(obj, "type", "") in _ABOUT_OBJECTS
                and not getattr(obj, "object_refs", None)
            }
            if not empty:
                return objects
            kept: list[Any] = []
            for obj in objects:
                if str(getattr(obj, "id", "")) in empty:
                    self.declined.append(
                        Declined(UNPUBLISHABLE_OBJECT_CODE, _names_nothing_sentence(obj))
                    )
                    continue
                refs = getattr(obj, "object_refs", None)
                if isinstance(refs, list) and any(ref in empty for ref in refs):
                    obj = obj.model_copy(
                        update={"object_refs": [ref for ref in refs if ref not in empty]}
                    )
                kept.append(obj)
            objects = kept

    def _family_refs(
        self, report: MalwareReport, ledger_order: Mapping[str, int]
    ) -> list[str] | None:
        """The family's ledger ids the ledger holds; each one it does not is recorded."""
        who = report.attribution.family_source or "judge"
        for raw in report.attribution.family_evidence_ids or []:
            eid = str(raw or "").strip()
            if eid and eid not in ledger_order:
                self.declined.append(
                    Declined(
                        EVIDENCE_REF_NOT_IN_LEDGER_CODE,
                        f"the family {safe_finding_value(report.attribution.family)!r} cites "
                        f"{safe_finding_value(eid)!r}, which this run's ledger does not hold, so "
                        "the export's malware object does not carry it. The attribution keeps "
                        "the citation as written.",
                        by=who,
                    )
                )
        return _evidence_refs(report.attribution.family_evidence_ids, ledger_order)

    @staticmethod
    def _normalize_judge_timestamps(objects: list[Any]) -> None:
        """Stamp the judge's SDOs with the time the platform published them.

        ``created`` and ``modified`` are the platform's bookkeeping — when this
        export made the object — and the prompt tells the judge to leave them
        out; a model that writes them copies the documentation's
        ``2023-01-01T00:00:00Z``. They are set to the render time, matching
        every renderer-produced SDO.

        Nothing the judge states is touched. ``is_family`` used to be forced to
        ``false`` here, on the reasoning that one sample is not a family; whether
        the object stands for the family is the judge's statement, and it is
        published as written.

        Object ids are left untouched so intra-bundle relationship refs stay
        valid.
        """
        now = get_utcnow()
        for obj in objects:
            if hasattr(obj, "created"):
                obj.created = now
            if hasattr(obj, "modified"):
                obj.modified = now

    @staticmethod
    def _find_malware_id(objects: list[Any]) -> str | None:
        for obj in objects:
            if isinstance(obj, Malware):
                return obj.id
            obj_type = getattr(obj, "type", None)
            if obj_type == "malware":
                return getattr(obj, "id", None)
        return None


def _produced_by(
    objects: list[Any], producer: str, declined: list[tuple[str, str]] | None = None
) -> list[Any]:
    """Every object naming the identity that produced it, as a copy.

    A copy, because the judge's objects are the judge's own bundle's too, and
    that bundle is kept as the run's record (``analysis_reports.judge_stix_bundle``,
    served at ``/reports/{id}/stix?source=judge``). An object that already names a
    producer in this bundle keeps the one it names; one naming an identity the
    bundle does not hold names nothing, the way a relationship pointing at
    nothing does, and is given this one — recorded in ``declined``, because the
    export then says something about the object that its writer did not.
    """
    present = {getattr(obj, "id", None) for obj in objects} - {None}
    out: list[Any] = []
    for obj in objects:
        named = getattr(obj, "created_by_ref", None)
        if getattr(obj, "id", None) == producer or named in present:
            out.append(obj)
            continue
        if "created_by_ref" not in type(obj).model_fields:
            out.append(obj)
            continue
        if named and declined is not None:
            declined.append(
                Declined(UNPUBLISHABLE_PRODUCER_CODE, replaced_producer_sentence(obj, str(named)))
            )
        out.append(produced_by(obj, producer))
    return out


# The namespace the technique objects' ids are derived in: one, in
# ``schemas.stix_models``, for the export and for the judge's own bundle.
_ATTACK_PATTERN_NAMESPACE = ATTACK_PATTERN_NAMESPACE

# This platform's identity, the producer every exported object names. Derived
# in the same namespace, so it is the same object in every export and a
# consumer holding many of them holds one producer.
PRODUCER_IDENTITY_ID = f"identity--{uuid.uuid5(_ATTACK_PATTERN_NAMESPACE, 'maljan')}"


def _pattern_id_for(technique_id: str) -> str:
    """The published object id of one technique. Same id every time."""
    return attack_pattern_id(technique_id)


def report_types_for(verdict: str) -> list[str]:
    """The STIX 2.1 ``report_types`` for the verdict the record states.

    A report type says what the report is about (``report-type-ov``; the
    object type ``malware-analysis`` is not one of them). ``malware`` is "a
    characterization of one or more malware instances", which a Malware
    verdict states and a Suspicious or Benign one does not: a Benign export
    once went out typed ``malware``. The vocabulary has no term for a finding
    that the subject is not a threat, and its general entry, ``threat-report``
    ("a broad characterization of a threat across multiple facets"), is the
    one that claims no malware instance.
    """
    return ["malware"] if str(verdict or "") == "Malware" else ["threat-report"]


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
    declared = attack_reference_id(obj)
    if declared:
        return declared
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
    refs = getattr(obj, "object_refs", None)
    if isinstance(refs, list) and any(ref in remap for ref in refs):
        # An object about the judge's techniques is about the rebuilt ones.
        return obj.model_copy(update={"object_refs": [remap.get(r, r) for r in refs]}), ""
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


def _evidence_refs(ids: Any, ledger_order: Mapping[str, int]) -> list[str] | None:
    """Ledger ids as the export writes them: ids the ledger holds, once each,
    in the ledger's order. ``None`` for none."""
    kept = {str(raw or "").strip() for raw in ids or []}
    held = sorted((eid for eid in kept if eid in ledger_order), key=ledger_order.__getitem__)
    return held or None


def _with_record_evidence(
    objects: list[Any],
    malware_id: str | None,
    technique_evidence: Mapping[str, Sequence[str]],
    ledger_order: Mapping[str, int],
    minted_id: str | None = None,
) -> list[Any]:
    """``objects`` with the property on each object exactly as the record gives it.

    The sample's ``uses`` edge to a technique gets that technique's ledger ids.
    The malware object this export minted keeps the family ids it was minted
    with (already checked against the ledger). Every other object that could
    carry the property carries none. A copy is written rather than the object
    changed, because the judge's objects are the judge's own bundle's too.
    """
    by_pattern: dict[str, list[str]] = {}
    for tid, ids in technique_evidence.items():
        refs = _evidence_refs(ids, ledger_order)
        if refs:
            by_pattern[_pattern_id_for(str(tid).strip().upper())] = refs
    out: list[Any] = []
    for obj in objects:
        if EVIDENCE_REFS_PROPERTY not in type(obj).model_fields:
            out.append(obj)
            continue
        current = getattr(obj, EVIDENCE_REFS_PROPERTY, None)
        if minted_id is not None and getattr(obj, "id", None) == minted_id:
            wanted = current
        elif (
            malware_id is not None
            and getattr(obj, "type", "") == "relationship"
            and getattr(obj, "relationship_type", "") == "uses"
            and getattr(obj, "source_ref", None) == malware_id
        ):
            wanted = by_pattern.get(str(getattr(obj, "target_ref", "") or ""))
        else:
            wanted = None
        if wanted != current:
            obj = obj.model_copy(update={EVIDENCE_REFS_PROPERTY: wanted})
        out.append(obj)
    return out


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
    recovered: str = "",
    verdict: Any = None,
    also_plain: str = "",
    unattributed: str = "",
    kept_by: str = "",
    mentioned_by: str = "",
    in_published_url: str = "",
) -> str | None:
    """Why this run may publish one indicator of ``kind``, or ``None``.

    ``in_published_url`` names a URL this run publishes whose host is this
    domain (:func:`published_url_hosts`). The domain follows that URL's
    decision: one live run published two C2 URLs and neither of their names,
    because the judge wrote URL indicators only and nothing carried a
    published URL's host to a row of its own. A well-known benign host does
    not follow its URL: it is published only when a model kept the host itself.

    ``unattributed`` is why a sandbox row is not the sample's own observation
    — a flow the report does not attribute to the sample's process tree, a
    well-known benign name the guest resolved — and ``kept_by`` the models
    that kept the value as an indicator (:func:`sandbox_row_kwargs`): an
    analyst's artifact or the judge's indicator. Such a row is published only
    when a model kept it; the observation alone is the guest's traffic, and a
    claim that only mentions the value (``mentioned_by``) keeps nothing.

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

    A network value the sample hid and only emulation recovered — a decoded,
    stack or tight string in the run's FLOSS entry that the static string sweep
    did not also read as a plain string (``also_plain`` names the sweep's entry
    when it did, and the value is then the sweep's) — is a source of its own
    (``recovered``: "recovered by emulation (decoded strings), ev_NNNN"). Hiding
    a host behind encoding is a deliberate act benign software rarely performs,
    where a plain string in a binary is routinely benign. It admits a domain,
    an address or a URL that passes every other question here — the host
    question, the address classes, the reputation half — and is not a
    well-known benign host or a denied URL host. It admits nothing under a
    Benign ``verdict``, nor under one the judge did not state with a confidence:
    a Benign run publishes no malicious indicator, and the refusal says so.
    A value only the string sweep read stays unpublished.
    """
    if kind == "domain":
        if not host_is_public(value):
            return None
        if in_published_url and not is_well_known_benign_host(value):
            return f"the host of {in_published_url}, which this run publishes"
        if in_published_url or unattributed:
            return _kept_by_a_model(kept_by)
        return corroboration_reason(source, reputation, value) or _emulation_admits(
            value, recovered, verdict
        )
    if kind == "ip":
        if unattributed and address_is_publishable(value, source):
            return _kept_by_a_model(kept_by)
        admitted = ip_corroboration_reason(value, source, reputation)
        if admitted or not address_is_publishable(value, source):
            return admitted
        return _emulation_admits(value, recovered, verdict)
    if kind == "url":
        admitted = url_corroboration_reason(value, source, reputation)
        host = url_host(value)
        if admitted or not host_is_public(host):
            return admitted
        if any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
            return None
        return _emulation_admits(host, recovered, verdict)
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
    if kind == "hash":
        # A digest is publishable when it is whole and somebody other than the
        # string sweep knows it: the sample's own identity, a sandbox's dropped
        # file, an analyst's carved payload, a second source's record. A run of
        # hex the byte image carries is not a file anybody has.
        if not _is_a_whole_digest(value):
            return None
        if str(source or "").strip().lower() not in ("", "strings"):
            return str(source)
        return corroborated_by or None
    # A command line is not an indicator this platform publishes: it is a
    # behaviour a detection rule reads, not a value a blocklist or the /iocs
    # feed matches on, and STIX has no pattern this export writes for one. The
    # rule answers it — no — rather than leaving it to whichever path asks.
    if kind not in STRING_IOC_KINDS or indicator_pattern(kind, value) is None:
        return None
    if str(source or "").strip().lower() not in ("", "strings"):
        return str(source)
    return corroborated_by or None


def published_url_hosts(report: Any) -> dict[str, tuple[str, str]]:
    """``{host: (url, source)}`` for every URL this report publishes whose host is a name.

    The URLs of the network block the rule publishes, and the judge's URL
    values the rule publishes (source ``judge``), in that order; the first URL
    to carry a host is the one named. An address host is not a name and is
    not carried: it is an ``ip`` row's to answer. Built once per reading
    (:func:`one_reading`).
    """
    return _memo(report, "url_hosts", lambda: _published_url_hosts(report))  # type: ignore[no-any-return]


def _published_url_hosts(report: Any) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}

    def _carry(url: str, source: str) -> None:
        host = url_host(url)
        if not host or not host_is_public(host):
            return
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            out.setdefault(host, (url, source))

    network = _field(report, "network")
    for row in (_field(network, "urls") or []) if network is not None else []:
        url = str(_field(row, "url") or "").strip()
        source = str(_field(row, "source") or "strings")
        if url and (
            indicator_publish_reason(
                "url",
                url,
                source,
                _host_reputation(report, url_host(url)),
                **emulation_kwargs(report, "url", url),
            )
            is not None
        ):
            _carry(url, source)
    judged = [
        str(_field(item, "value") or "").strip()
        for item in _field(report, "judge_indicators") or []
        if str(_field(item, "kind") or "") == "url"
    ]
    if judged:
        corroborating = _corroborating_values(report)
        for url in judged:
            if url and judge_value_answer(report, "url", url, corroborating) == "yes":
                _carry(url, "judge")
    return out


def _kept_by_a_model(kept_by: str) -> str | None:
    return f"kept as an indicator by {kept_by}" if kept_by else None


def not_kept_reason(why: str, mentioned_by: str = "") -> str:
    """The ``no:`` a row waiting for a model reads, naming any claim that only mentioned it."""
    said = f"no: {why}, and no model kept it as an indicator"
    if mentioned_by:
        said += f" ({mentioned_by} mentions it and does not keep it)"
    return said


# What the rule says of a well-known benign name a published URL carries.
BENIGN_NAME_IN_A_URL = "a well-known benign name carried by a published URL"


# Why a sandbox row is not the sample's own observation, as the rule reports it.
UNATTRIBUTED_FLOW = "the sandbox report does not say which process made the flows to it"
FLOW_OUTSIDE_THE_TREE = (
    "the sandbox report attributes its flows to a process outside the sample's process tree"
)
BENIGN_NAME_RESOLVED = "a well-known benign name the sandbox's guest resolved"


def sandbox_row_kwargs(report: Any, kind: str, value: str) -> dict[str, str]:
    """``unattributed``, ``kept_by`` and ``mentioned_by`` for one value's sandbox row, or nothing.

    Asked of the report's network block. An address the sandbox saw is the
    sample's own observation when a flow to it came from the sample's process
    tree; one no flow of the tree reached — the report attributes its flows
    elsewhere, or says nothing about which process made them — is the guest's
    traffic, and so is a well-known benign name a DNS lookup asked for (Windows
    resolves through its DNS service, never through the sample's tree, so a
    name is judged by what it is). Either is published only when a model kept
    it as an indicator: an analyst's artifact, or the judge's indicator. The
    public resolver and AS facts are stated in the reason. Rows are found
    through one index per report, so a table of any size is read once.
    """
    network = _field(report, "network")
    if network is None or kind not in ("ip", "domain"):
        return {}
    key = _value_key(kind, value)
    row = _network_index(report).get((kind, key))
    if kind == "ip":
        if row is None or _field(row, "source") != "sandbox":
            return {}
        if _field(row, "sample_process_tree") is True:
            return {}
        why = (
            FLOW_OUTSIDE_THE_TREE
            if _field(row, "sample_process_tree") is False
            else UNATTRIBUTED_FLOW
        )
        if _field(row, "public_resolver"):
            why += "; it is a public DNS resolver"
        if _field(row, "asn"):
            why += f"; AS {_field(row, 'asn')}"
    else:
        if row is None or _field(row, "source") != "sandbox":
            return {}
        if not is_well_known_benign_host(key):
            return {}
        why = BENIGN_NAME_RESOLVED
    return {"unattributed": why, **kept_kwargs(report, kind, key, row)}


def _value_key(kind: str, value: Any) -> str:
    """One spelling of a value for lookups: an address canonical, a name lower-cased."""
    text = str(value or "").strip()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(text.strip("[]")))
        except ValueError:
            return text.lower()
    return text.lower().rstrip(".")


def kept_kwargs(report: Any, kind: str, key: str, row: Any = None) -> dict[str, str]:
    """``kept_by`` and ``mentioned_by`` for one value: who kept it, whose claim only mentions it."""
    kept = [str(by) for by in (_field(row, "kept_by") or [])] if row is not None else []
    if (kind, key) in _judge_index(report):
        kept.append("the judge's indicator")
    elif (kind, key) in _judge_url_hosts(report) and not is_well_known_benign_host(key):
        # A well-known host a URL carries is kept only as itself (a CDN's
        # name is not the sample's C2 because a URL on it was).
        kept.append("the judge's URL indicator")
    mentioned = [str(by) for by in (_field(row, "mentioned_by") or [])] if row is not None else []
    return {
        "kept_by": ", ".join(dict.fromkeys(kept)),
        "mentioned_by": ", ".join(dict.fromkeys(mentioned)),
    }


# One reading of a report's lookups at a time. The IOC table, the export and
# the feed each ask the publish rule once per row, and every answer used to
# rescan the network block and recompute every published URL's host — which
# made a table of a few hundred rows take seconds. Inside ``one_reading`` each
# lookup is built once per report; outside it, each is built per call.
_READING: ContextVar[dict[str, Any] | None] = ContextVar("maljan_stix_reading", default=None)


@contextmanager
def one_reading(report: Any) -> Iterator[None]:
    """Hold the report's lookups for the duration of one table, export or feed."""
    token = _READING.set({"report": id(report)})
    try:
        yield
    finally:
        _READING.reset(token)


def _memo(report: Any, name: str, build: Any) -> Any:
    reading = _READING.get()
    if reading is None or reading.get("report") != id(report):
        return build()
    if name not in reading:
        reading[name] = build()
    return reading[name]


def _network_index(report: Any) -> dict[tuple[str, str], Any]:
    """``{(kind, key): row}`` for the report's network block, first row of each value."""

    def _build() -> dict[tuple[str, str], Any]:
        network = _field(report, "network")
        out: dict[tuple[str, str], Any] = {}
        if network is None:
            return out
        for row in _field(network, "ips") or []:
            out.setdefault(("ip", _value_key("ip", _field(row, "address"))), row)
        for row in _field(network, "domains") or []:
            out.setdefault(("domain", _value_key("domain", _field(row, "fqdn"))), row)
        return out

    return _memo(report, "network_index", _build)  # type: ignore[no-any-return]


def _judge_index(report: Any) -> frozenset[tuple[str, str]]:
    """The ``(kind, key)`` of every value the judge's indicators name."""

    def _build() -> frozenset[tuple[str, str]]:
        return frozenset(
            (
                str(_field(item, "kind") or ""),
                _value_key(str(_field(item, "kind") or ""), _field(item, "value")),
            )
            for item in _field(report, "judge_indicators") or []
        )

    return _memo(report, "judge_index", _build)  # type: ignore[no-any-return]


def _judge_url_hosts(report: Any) -> frozenset[tuple[str, str]]:
    """The ``(kind, key)`` of the host — address or name — of every URL the judge kept.

    A URL the judge kept keeps its host: the address or the name in it is the
    infrastructure the judge pointed at.
    """

    def _build() -> frozenset[tuple[str, str]]:
        out: set[tuple[str, str]] = set()
        for item in _field(report, "judge_indicators") or []:
            if str(_field(item, "kind") or "") != "url":
                continue
            host = url_host(str(_field(item, "value") or ""))
            if not host:
                continue
            try:
                ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                out.add(("domain", _value_key("domain", host)))
            else:
                out.add(("ip", _value_key("ip", host.strip("[]"))))
        return frozenset(out)

    return _memo(report, "judge_url_hosts", _build)  # type: ignore[no-any-return]


# What the rule writes for a value emulation recovered, before the entry id.
RECOVERED_BY_EMULATION = "recovered by emulation (decoded strings)"

# The FLOSS string kinds that are text the sample hid: a decoded string, a
# stack string, a tight string. A static string FLOSS also lists is not.
_EMULATED_KINDS = frozenset({"decoded", "stack", "tight"})


def _emulation_admits(host: str, recovered: str, verdict: Any) -> str | None:
    """``recovered`` when emulation may stand as this value's source, else ``None``.

    Never under a Benign verdict, nor under one the judge did not state with a
    confidence (a fallback's default word), nor for a well-known benign host.
    """
    if not recovered or _is_benign_verdict(verdict) or verdict == UNSTATED_VERDICT:
        return None
    if is_well_known_benign_host(host):
        return None
    return recovered


def _is_benign_verdict(verdict: Any) -> bool:
    return str(verdict or "").strip().lower() == "benign"


def _field(obj: Any, name: str) -> Any:
    """``obj.name`` or ``obj[name]``: a report as a model or as its stored dict."""
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def _rows_of(structured: Any, key: str) -> list[Any]:
    rows = structured.get(key) if isinstance(structured, dict) else None
    return list(rows) if isinstance(rows, list) else []


def _whole_listing(structured: Any, rows: list[Any]) -> bool:
    """Whether a paged listing's answer is every row it matched, unfiltered."""
    if not isinstance(structured, dict) or structured.get("pattern"):
        return False
    if structured.get("truncated") or int(structured.get("page_offset") or 0):
        return False
    matched = structured.get("total_matched", structured.get("total"))
    try:
        return int(matched if matched is not None else len(rows)) <= len(rows)
    except (TypeError, ValueError):
        return False


def _hold_out_plain(
    values: dict[str, str], plain_texts: list[tuple[str, str]]
) -> tuple[dict[str, str], dict[str, str]]:
    """Split emulated values into those only emulation read and those a plain string holds."""
    kept: dict[str, str] = {}
    plain: dict[str, str] = {}
    for value, entry in values.items():
        holder = next((eid for eid, text in plain_texts if whole_value_in(value, text)), "")
        if holder:
            plain[value] = holder
        else:
            kept[value] = entry
    return kept, plain


def _add_emulated(values: dict[str, str], text: Any, entry: str) -> None:
    value = str(text or "").strip().lower()
    if not value:
        return
    values.setdefault(value.rstrip("."), entry)
    host = url_host(value)
    if host:
        values.setdefault(host, entry)


def emulation_from_ledger(ledger: Iterable[Any] | None) -> EmulatedStrings:
    """What emulation alone recovered in this run, read from every FLOSS entry the ledger holds.

    A decoded, stack or tight string FLOSS returned, folded to lower case (a
    URL adds its host), with the entry it came from — the pack's own entry
    first, since it is issued first. A value the static string sweep also read
    as a whole value (the ``strings`` entries, the ``iocs_from_file`` rows) is
    held out: text the sample did not hide is not recovered by emulation,
    whatever kind FLOSS gave it. ``partial`` says why the record may not be
    the run's whole: no FLOSS entry listed every string it recovered, or no
    ``strings`` entry listed every plain string, so a value past a page could
    be missing from either side. Built at build time and stored on the report,
    so no kept-row cap of a section decides a publish answer.
    """
    values: dict[str, str] = {}
    plain_texts: list[tuple[str, str]] = []
    floss_whole = strings_whole = False
    saw_floss = saw_strings = False
    for entry in ledger or ():
        tool = str(getattr(entry, "tool", "") or "").rsplit("__", 1)[-1]
        entry_id = str(getattr(entry, "id", "") or getattr(entry, "entry_id", "") or "")
        structured = getattr(entry, "structured", None)
        if tool == "floss":
            saw_floss = True
            rows = _rows_of(structured, "strings")
            floss_whole = floss_whole or _whole_listing(structured, rows)
            for row in rows:
                if isinstance(row, dict) and str(row.get("kind") or "").lower() in _EMULATED_KINDS:
                    _add_emulated(values, row.get("string"), entry_id)
        elif tool == "strings":
            saw_strings = True
            rows = _rows_of(structured, "strings")
            strings_whole = strings_whole or _whole_listing(structured, rows)
            plain_texts.extend(
                (entry_id, str(row.get("text") or "").lower())
                for row in rows
                if isinstance(row, dict) and row.get("text")
            )
        elif tool == "iocs_from_file":
            plain_texts.extend(
                (entry_id, str(row.get("value") or "").lower())
                for row in _rows_of(structured, "iocs")
                if isinstance(row, dict) and row.get("value")
            )
    kept, plain = _hold_out_plain(values, plain_texts)
    why: list[str] = []
    if saw_floss and not floss_whole:
        why.append("no FLOSS entry listed every string it recovered")
    if kept and not (saw_strings and strings_whole):
        why.append("no strings entry listed every plain string in the file")
    return EmulatedStrings(values=kept, plain=plain, partial="; ".join(why))


# Why a record read back from a stored report is partial: it holds only the
# rows the report's sections kept.
_FROM_KEPT_ROWS = "read from the kept rows of a report stored before the record existed"


def emulation_record(report: Any) -> EmulatedStrings:
    """The report's record of what emulation alone recovered.

    The one built from the ledger at build time (``emulated_strings``), or, for
    a report stored before it existed, one read from the report's kept section
    rows — FLOSS's ``tool_floss_strings`` and the sweep's ``strings`` and
    string rows — and marked partial, because a section keeps a bounded number
    of rows.
    """
    stored = _field(report, "emulated_strings")
    if stored:
        return (
            stored
            if isinstance(stored, EmulatedStrings)
            else EmulatedStrings.model_validate(stored)
        )
    index = {
        str(_field(row, "id") or ""): str(_field(row, "agent") or "")
        for row in (_field(report, "evidence_index") or [])
    }
    values: dict[str, str] = {}
    plain_texts: list[tuple[str, str]] = []
    for section in _field(report, "sections") or []:
        key = str(_field(section, "key") or "")
        columns = [str(c) for c in (_field(section, "columns") or [])]
        ids = [str(i) for i in (_field(section, "evidence_ids") or [])]
        rows = _field(section, "rows") or []
        if key == "tool_floss_strings" and "kind" in columns and "string" in columns and ids:
            entry = next((i for i in ids if index.get(i) == "pipeline"), ids[0])
            at_kind, at_string = columns.index("kind"), columns.index("string")
            for row in rows:
                if len(row) > max(at_kind, at_string) and (
                    str(row[at_kind]).strip().lower() in _EMULATED_KINDS
                ):
                    _add_emulated(values, row[at_string], entry)
        elif key == "strings" and "Text" in columns:
            at_text = columns.index("Text")
            plain_texts.extend(
                (ids[0] if ids else "", str(row[at_text]).lower())
                for row in rows
                if len(row) > at_text
            )
    static = _field(report, "static")
    for row in _field(static, "interesting_strings") or [] if static is not None else []:
        plain_texts.append(("", str(_field(row, "value") or "").lower()))
    kept, plain = _hold_out_plain(values, plain_texts)
    return EmulatedStrings(values=kept, plain=plain, partial=_FROM_KEPT_ROWS if values else "")


# The verdict a record is asked under when the judge stated none with a
# confidence: a fallback's default word is not a verdict anybody stated.
UNSTATED_VERDICT = "unstated"


def emulation_kwargs(
    report: Any, kind: str, value: str, record: EmulatedStrings | None = None
) -> dict[str, Any]:
    """The rule's emulation arguments for one value of one report.

    ``recovered`` (the reason, with the record's partiality where it has
    any) and ``verdict`` for a value only emulation recovered; ``also_plain``
    (the sweep's entry) for one the static sweep read too; nothing otherwise.
    The verdict is read as stated only when the judge gave it a confidence.
    A sandbox row's ``unattributed``, ``kept_by`` and ``mentioned_by`` (:func:`sandbox_row_kwargs`)
    ride along, so every surface that asks the rule of a network value — the
    IOC table, the export, ``/iocs``, the judge's values — reads one decision.
    """
    if kind not in ("domain", "ip", "url"):
        return {}
    observed: dict[str, str] = (
        dict(sandbox_row_kwargs(report, kind, value)) if report is not None else {}
    )
    if kind == "domain" and report is not None:
        key = _value_key("domain", value)
        carried_by = published_url_hosts(report).get(key)
        if carried_by:
            observed["in_published_url"] = carried_by[0]
            if "kept_by" not in observed:
                observed.update(
                    kept_kwargs(report, "domain", key, _network_index(report).get(("domain", key)))
                )
    found = emulation_record(report) if record is None else record
    key = str(value or "").strip().lower().rstrip(".")
    if key in found.plain:
        return {"also_plain": found.plain[key] or "the strings entry", **observed}
    entry = found.values.get(key)
    if not entry:
        return dict(observed)
    reason = f"{RECOVERED_BY_EMULATION}, {entry}"
    if found.partial:
        reason += f" (the record is partial: {found.partial})"
    stated = _field(report, "overall_confidence") is not None
    return {
        "recovered": reason,
        "verdict": _field(report, "verdict") if stated else UNSTATED_VERDICT,
        **observed,
    }


_WHOLE_DIGEST_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_HEX_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})


def _is_a_whole_digest(value: Any) -> bool:
    """Whether ``value`` is hex of a digest's own length."""
    text = str(value or "").strip()
    return bool(_WHOLE_DIGEST_RE.match(text)) and len(text) in _DIGEST_HEX_LENGTHS


def publish_answer(
    kind: str,
    value: str,
    source: Any,
    reputation: Any = None,
    *,
    corroborating: str = "",
    recovered: str = "",
    verdict: Any = None,
    also_plain: str = "",
    unattributed: str = "",
    kept_by: str = "",
    mentioned_by: str = "",
    in_published_url: str = "",
) -> str:
    """The publish rule's answer for one row, as the report prints it.

    ``yes``, or ``no: <reason>`` naming the half of :func:`indicator_publish_reason`
    that refused it. The decision is that function's and nothing here decides
    anything: the reason is read back from the same questions it asks, in the
    same order. ``corroborating`` is the run's second-source record
    (:func:`corroborating_values`), asked whole-value for a string row the way
    the export asks it.
    """
    text = str(value or "").strip()
    from_strings = str(source or "").strip().lower() in ("", "strings")
    corroborated = (
        "a second source in this run records it"
        if from_strings and text and corroborating and whole_value_in(text, corroborating)
        else ""
    )
    if indicator_publish_reason(
        kind,
        text,
        source,
        reputation,
        corroborated_by=corroborated,
        recovered=recovered,
        verdict=verdict,
        unattributed=unattributed,
        kept_by=kept_by,
        mentioned_by=mentioned_by,
        in_published_url=in_published_url,
    ):
        return "yes"
    if kind == "domain" and not host_is_public(text):
        return "no: not a name that resolves outside the analysed network"
    if kind == "url" and not host_is_public(url_host(text)):
        return "no: its host does not resolve outside the analysed network"
    if kind == "ip" and not address_is_publishable(text, source):
        return "no: not an address this run may publish"
    if kind == "domain" and in_published_url and is_well_known_benign_host(text):
        return not_kept_reason(f"{BENIGN_NAME_IN_A_URL} ({in_published_url})", mentioned_by)
    if unattributed and kind in ("ip", "domain"):
        return not_kept_reason(unattributed, mentioned_by)
    if kind == "email" and not email_is_publishable(text):
        return "no: not a mailbox at a host that could exist"
    if (
        kind == "email"
        and from_strings
        and not reads_as_a_host_in_the_bytes(text.rsplit("@", 1)[-1])
    ):
        return "no: its domain part reads as code in the file, not as a host"
    if kind == "path" and not path_names_a_file(text):
        return "no: names a directory or a root, not a file"
    if kind == "hash" and not _is_a_whole_digest(text):
        return "no: not a whole digest"
    if recovered and _is_benign_verdict(verdict):
        return f"no: {recovered}, but the verdict is Benign, which publishes no malicious indicator"
    if recovered and verdict == UNSTATED_VERDICT:
        return f"no: {recovered}, but the judge stated no verdict with a confidence"
    if also_plain:
        return (
            f"no: seen only in the file's strings — also a plain string in the file "
            f"({also_plain}), so not recovered by emulation"
        )
    if recovered and is_well_known_benign_host(url_host(text) if kind == "url" else text):
        return f"no: {recovered}, but it is a well-known benign host"
    if kind == "command":
        return "no: a command line is not an indicator this run publishes"
    if kind != "hash" and (kind not in STRING_IOC_KINDS or indicator_pattern(kind, text) is None):
        return "no: the export has no object for this kind"
    return "no: seen only in the file's strings"


def corroborating_values(report: Any, corpus: Any = None) -> str:
    """The run's second-source record, as :func:`publish_answer` asks it."""
    return _corroborating_values(report, corpus)


def judge_value_answer(report: Any, kind: str, value: str, corroborating: str) -> str:
    """The one publish rule's answer for a value the judge's indicator names.

    The judge asserting a value is not a second source for it — the export
    used to take "the judge said so" as one, and a certificate authority's host
    the judge copied out of the strings table was published, fed and drafted
    an alert for. So the value is asked exactly as the report's own row for it
    is: a network value with the source and reputation of its row in the
    network block where the block has one, the sample's own digest as its
    identity, and anything else as the string sweep's, with the run's
    second-source record (:func:`corroborating_values`) asked whole-value.
    ``yes`` or ``no: <reason>``, as :func:`publish_answer` writes it.
    """
    text = str(value or "").strip()
    network = getattr(report, "network", None)
    emulated = emulation_kwargs(report, kind, text)
    if emulated.get("unattributed") or emulated.get("in_published_url"):
        # The value is the judge's own: a model kept it, which is what a row
        # the observation alone does not publish waits for.
        kept = [by for by in str(emulated.get("kept_by") or "").split(", ") if by]
        emulated["kept_by"] = ", ".join(dict.fromkeys([*kept, "the judge's indicator"]))
    if kind == "domain" and network is not None:
        for row in network.domains:
            if row.fqdn.strip().lower().rstrip(".") == text.lower().rstrip("."):
                return publish_answer("domain", text, row.source, row.reputation, **emulated)
    if kind == "ip" and network is not None:
        for ip_row in network.ips:
            if ip_row.address.strip() == text:
                return publish_answer("ip", text, ip_row.source, ip_row.reputation, **emulated)
    if kind == "url" and network is not None:
        for url_row in network.urls:
            if url_row.url.strip() == text:
                return publish_answer(
                    "url",
                    text,
                    url_row.source or "strings",
                    _host_reputation(report, url_host(text)),
                    **emulated,
                )
    if kind == "hash":
        hashes = getattr(getattr(report, "identity", None), "hashes", None)
        own = {
            str(getattr(hashes, name, "") or "").strip().lower()
            for name in ("md5", "sha1", "sha256", "sha512", "imphash")
        } - {""}
        if text.lower() in own:
            return publish_answer("hash", text, "identity")
    reputation = _host_reputation(report, url_host(text)) if kind == "url" else None
    return publish_answer(
        kind, text, "strings", reputation, corroborating=corroborating, **emulated
    )


def judge_indicator_rows(report: Any, corpus: Any = None) -> list[tuple[Any, str]]:
    """Each value the judge's indicators name, with the one rule's answer for it.

    What the IOC table and ``/iocs`` read for a judge value, and what the
    export asks before it carries a judge indicator, so the three surfaces
    read one decision.
    """
    rows = list(getattr(report, "judge_indicators", None) or [])
    if not rows:
        return []
    corroborating = _corroborating_values(report, corpus)
    return [(row, judge_value_answer(report, row.kind, row.value, corroborating)) for row in rows]


# What one comparison of an exported pattern names, as the IOC table's kind.
# The inverse of :func:`indicator_pattern` for the kinds it writes, plus the
# digests a hash indicator compares.
_EXPORTED_KINDS: dict[tuple[str, str], str] = {
    ("domain-name", "value"): "domain",
    ("ipv4-addr", "value"): "ip",
    ("ipv6-addr", "value"): "ip",
    ("url", "value"): "url",
    ("email-addr", "value"): "email",
    ("file", "name"): "path",
    ("windows-registry-key", "key"): "registry",
    ("mutex", "name"): "mutex",
    ("process", "command_line"): "command",
}
_HASH_PROPERTY_RE = re.compile(r"^hashes\.'([^']+)'$")


@dataclass(frozen=True)
class ExportedValue:
    """One value an exported indicator compares: its kind, the value, and a hash's algorithm."""

    kind: str
    value: str
    algorithm: str = ""


def pattern_values(pattern: str) -> list[ExportedValue]:
    """The values a pattern compares with ``=``, each typed as the IOC table types it.

    A comparison over a path the table has no kind for is not returned.
    """
    found: list[ExportedValue] = []
    for comparison in read_comparisons(str(pattern or "")):
        if not comparison.readable or comparison.operator != "=":
            continue
        value = comparison.literal.strip()
        kind, algorithm = _exported_kind(comparison)
        if kind and value:
            found.append(ExportedValue(kind=kind, value=value, algorithm=algorithm))
    return found


def rule_values(pattern: str) -> list[ExportedValue]:
    """Every value a pattern names over a kind the rule answers, whatever the operator.

    :func:`pattern_values` reads ``=`` alone, which is what the IOC table and
    ``/iocs`` list. This reads what the export asks the rule about: every
    quoted operand of an operator that compares with a value — ``=``, ``!=``,
    ``<``, ``>``, ``<=``, ``>=`` and each member of ``IN`` — and never a shape
    (``LIKE``, ``MATCHES``, ``ISSUBSET``, ``ISSUPERSET``), which names no value.
    An ``IN`` list, a ``<`` or a ``!=`` used to reach the export with nothing
    asked, so a value the rule refused as ``=`` was published inside one.
    """
    found: list[ExportedValue] = []
    for comparison in read_comparisons(str(pattern or "")):
        if not comparison.readable or not _endpoint_is_readable(comparison.operator):
            continue
        value = comparison.literal.strip()
        kind, algorithm = _exported_kind(comparison)
        if kind and value:
            found.append(ExportedValue(kind=kind, value=value, algorithm=algorithm))
    return found


def shape_is_asked_the_rule(comparison: Any) -> bool:
    """Whether a comparison is over an endpoint or a kind the one publish rule answers for.

    The two places a shape (``LIKE``, ``MATCHES``) is declined from the export:
    the host question's paths and the IOC table's kinds.
    """
    if _exported_kind(comparison)[0]:
        return True
    return bool(_checked_kind(comparison.object_type, comparison.prop))


def _exported_kind(comparison: Any) -> tuple[str, str]:
    """The IOC table's kind for a comparison's path, and a digest's algorithm; ``("", "")``."""
    digest = _HASH_PROPERTY_RE.match(comparison.prop)
    if comparison.object_type == "file" and digest:
        return "hash", digest.group(1).upper()
    return _EXPORTED_KINDS.get((comparison.object_type, comparison.prop), ""), ""


def exported_indicator_values(bundle: Any) -> list[ExportedValue]:
    """Every value a bundle's single-comparison indicators name, once each.

    Read of the judge's own bundle by the report builder, which stores the
    values for the IOC table and ``/iocs`` to ask the one publish rule of
    (:func:`judge_indicator_rows`), and of the export by the consistency test
    that holds the three surfaces to one decision. It decides nothing. A
    compound pattern (``[a] AND [b]``) names no single value and is left to
    the bundle, where the export asks each of its values the rule.
    """
    objects = (bundle or {}).get("objects") if isinstance(bundle, dict) else None
    found: list[ExportedValue] = []
    seen: set[tuple[str, str]] = set()
    for obj in objects or []:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = str(obj.get("pattern") or "")
        if len(read_comparisons(pattern)) != 1:
            continue
        for value in pattern_values(pattern):
            if (value.kind, value.value.lower()) in seen:
                continue
            seen.add((value.kind, value.value.lower()))
            found.append(value)
    return found


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
    record = emulation_record(report)
    return frozenset(
        domain.fqdn.strip().lower().rstrip(".")
        for domain in network.domains
        if domain.fqdn
        and indicator_publish_reason(
            "domain",
            domain.fqdn,
            domain.source,
            domain.reputation,
            **emulation_kwargs(report, "domain", domain.fqdn, record),
        )
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
    report: Any = None,
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

    # file:name: acceptance-based admission, asked before the publish rule
    # because its answer is about the shape of the value, not about who saw it.
    # No count bounds it: a file name the rule publishes is exported.
    if stripped.startswith("[file:name"):
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
        indicator_publish_reason(
            ioc.kind,
            value,
            "strings",
            corroborated_by=corroborated,
            **(emulation_kwargs(report, ioc.kind, value) if report is not None else {}),
        )
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


def _indicator_for_domain(
    domain: NetworkDomain, verdict: Any = "", report: Any = None
) -> Indicator | None:
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
    admitted = indicator_publish_reason(
        "domain",
        fqdn,
        domain.source,
        domain.reputation,
        **(emulation_kwargs(report, "domain", fqdn) if report is not None else {}),
    )
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


def _indicator_for_ip(ip: NetworkIP, verdict: Any = "", report: Any = None) -> Indicator | None:
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
    admitted = indicator_publish_reason(
        "ip",
        address,
        ip.source,
        ip.reputation,
        **(emulation_kwargs(report, "ip", address) if report is not None else {}),
    )
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
    admitted = indicator_publish_reason(
        "url",
        url.url,
        source,
        _host_reputation(report, host),
        **(emulation_kwargs(report, "url", url.url) if report is not None else {}),
    )
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


def _processes_to_observables(roots: list[ProcessNode]) -> list[File | Process]:
    """The process tree as STIX 2.1 observables: processes, their images, their children.

    A process's name is the file it ran from — STIX 2.1 has no ``name`` on a
    process — so it becomes a ``file`` observable the process names by
    ``image_ref``, and one image run twice is one file. The tree is kept by
    ``child_refs``.
    """
    out: list[File | Process] = []
    images: dict[str, File] = {}

    def _walk(node: ProcessNode) -> str:
        children = [_walk(child) for child in node.children]
        image_ref = None
        if node.name:
            image = images.get(node.name)
            if image is None:
                image = images[node.name] = File(name=node.name)
                out.append(image)
            image_ref = image.id
        process = Process(
            pid=node.pid,
            command_line=node.command_line or None,
            image_ref=image_ref,
            child_refs=children,
        )
        out.append(process)
        return process.id

    for root in roots[:20]:  # cap to keep ObservedData reasonable
        _walk(root)
    return out


# Type-only re-exports keep linters happy when this module is grepped.
_ = (AttackPattern,)
