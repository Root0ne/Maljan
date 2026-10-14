"""ATT&CK technique ids in the shapes the deterministic tools really emit.

Three producers spell a technique three ways. capa's ``attck`` field is a
list of decorated strings — ``Defense Evasion::Process Injection [T1055]``;
a Sigma rule's ``tags`` are lower-case dotted — ``attack.t1055.012``; the
LOLBin table and the API-to-technique rules give a bare ``technique_id``.
Every reader that counts what a tool asserted goes through here, so the
corroboration table, the persistence projection and the pack's rendering
agree on what fired.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, TypeGuard

# One technique id: ``T`` and four digits, and a sub-technique's three after a
# dot. Every reader below is built from it, and so is every other reader of the
# id in the codebase that needs its own boundaries (a claim line, a message).
ID_BODY = r"T\d{4}(?:\.\d{3})?"
TECHNIQUE_RE = re.compile(rf"\b{ID_BODY}\b", re.IGNORECASE)
# The same id as a word, in the case the platform writes it: the reader of a
# message or a cell the platform itself filled, where a lower-case ``t1055`` is
# not how an id was written.
TECHNIQUE_WORD_RE = re.compile(rf"\b{ID_BODY}\b")
# Anchored with ``\A`` and ``\Z``, not ``^`` and ``$``: ``$`` also matches before
# a final newline, so ``"T1055\n"`` read as one id under ``re.match``.
SIGMA_TAG_RE = re.compile(rf"\Aattack\.({ID_BODY})\Z", re.IGNORECASE)
# A whole string that is one id, for a field an agent wrote as the id itself.
TECHNIQUE_ID_EXACT_RE = re.compile(rf"\A{ID_BODY}\Z")

# The ``source_name`` values an external reference to an ATT&CK technique is
# filed under. A reference under any other source — CAPEC, a vendor's own
# catalogue — carries an ``external_id`` that is not a technique.
MITRE_ATTACK_SOURCES = frozenset(
    {"mitre-attack", "mitre attack", "mitre-mobile-attack", "mitre-ics-attack"}
)


# The words a producer writes in a technique field to say there is none. They
# are an answer — no technique — and a row made of one printed ``NONE`` in the
# ATT&CK table of a benign tool's report as an "unverified id".
NO_TECHNIQUE_WORDS = frozenset(
    {"NONE", "N/A", "NA", "NULL", "NIL", "UNKNOWN", "-", "NOT APPLICABLE"}
)


def says_no_technique(value: Any) -> bool:
    """Whether a technique field holds a word for "no technique" rather than an id."""
    return str(value or "").strip().upper() in NO_TECHNIQUE_WORDS


def is_technique_id(value: Any) -> TypeGuard[str]:
    """Whether ``value`` is one technique id and nothing else (``T1055``, ``T1055.012``).

    Exact and case-sensitive: a caller that accepts ``t1055`` upper-cases it
    first, and one that accepts surrounding space strips it first.
    """
    return isinstance(value, str) and TECHNIQUE_ID_EXACT_RE.match(value) is not None


def _attack_reference_ids(obj: Any) -> list[str]:
    """Every ``external_id`` an object files under an ATT&CK source, upper-cased, in order."""
    refs = obj.get("external_references") if isinstance(obj, dict) else None
    if refs is None and not isinstance(obj, dict):
        refs = getattr(obj, "external_references", None)
    found: list[str] = []
    for ref in refs or []:
        read = ref.get if isinstance(ref, dict) else lambda key, r=ref: getattr(r, key, "")
        source = str(read("source_name") or "").strip().lower()
        external = str(read("external_id") or "").strip()
        if source in MITRE_ATTACK_SOURCES and external:
            found.append(external.upper())
    return found


def declared_reference_id(obj: Any) -> str:
    """The ``external_id`` of an object's first ATT&CK reference, as written, or ``""``.

    Whatever its shape: the reader for a check that has to say an id is
    malformed (``TA0005`` is a tactic, ``T1055.1`` is no id), where
    :func:`attack_reference_id` would answer that the object names nothing.
    """
    found = _attack_reference_ids(obj)
    return found[0] if found else ""


def attack_reference_id(obj: Any) -> str:
    """The technique id an object's MITRE ATT&CK reference names, or ``""``.

    Only a reference filed under an ATT&CK source counts, and only an id
    shaped like a technique: an ATT&CK reference also files a tactic
    (``TA0005``), a software entry (``S0154``) or a group (``G0016``), and none
    of those is a technique. The first technique id found answers. Works on a
    dict or on a model.
    """
    return next((tid for tid in _attack_reference_ids(obj) if is_technique_id(tid)), "")


def name_technique_id(obj: Any) -> str:
    """The technique id an object's name opens with (``T1055 Process Injection``), or ``""``.

    The first word, upper-cased and without a trailing colon, and only when it
    is one id: a name that merely begins with a ``T`` (``Timestomp``,
    ``Token Impersonation``) names a behaviour, not a technique.
    """
    name = obj.get("name") if isinstance(obj, dict) else getattr(obj, "name", "")
    words = str(name or "").strip().upper().split(maxsplit=1)
    first = words[0].rstrip(":") if words else ""
    return first if is_technique_id(first) else ""


def declared_technique_id(obj: Any) -> str:
    """The technique an attack-pattern declares: its ATT&CK reference, else its name's id.

    A technique id or ``""``, for a reader that keys something by the
    technique (a credit, a remap).
    """
    return attack_reference_id(obj) or name_technique_id(obj)


def written_technique_id(obj: Any) -> str:
    """The id an attack-pattern writes: its ATT&CK reference as written, else its name's id.

    For a reader that shows or checks what was declared and marks a malformed
    id rather than hiding it (the validator's question, the capability matrix's
    invalid row): a ``TA0005`` reference comes back as ``TA0005``. A name
    counts only when it opens with a technique id, so "Token Impersonation"
    writes none.
    """
    return declared_reference_id(obj) or name_technique_id(obj)


def technique_ids_in(value: Any) -> list[str]:
    """Every technique id written anywhere in ``value``, first seen first.

    A string is searched; an iterable of strings is searched element by
    element; anything else names no technique. Ids come back upper-case and
    de-duplicated, in the order they were met.
    """
    found: list[str] = []
    for text in _strings(value):
        for match in TECHNIQUE_RE.findall(text):
            tid = match.upper()
            if tid not in found:
                found.append(tid)
    return found


def sigma_technique_ids(row: Mapping[str, Any] | None) -> list[str]:
    """The techniques one Sigma match names, from its ``attack.t…`` tags.

    ``tags`` is what ``tools.rules.sigma_match`` emits. A ``technique_ids``
    list on the row or under ``meta`` is read too, for a row written by hand.
    """
    if not isinstance(row, Mapping):
        return []
    found: list[str] = []
    for tag in _strings(row.get("tags")):
        match = SIGMA_TAG_RE.match(tag.strip())
        if match:
            tid = match.group(1).upper()
            if tid not in found:
                found.append(tid)
    meta = row.get("meta")
    for tid in technique_ids_in(row.get("technique_ids")) + technique_ids_in(
        meta.get("technique_ids") if isinstance(meta, Mapping) else None
    ):
        if tid not in found:
            found.append(tid)
    return found


# The readers of a declared technique field (``TechniqueField.format``), by
# format: a bare id or a decorated label (``attck``), and a Sigma tag
# (``sigma_tag``). A format no reader is named for is read as ``attck``: a
# technique id written anywhere in the value.
SIGMA_TAG_FORMAT = "sigma_tag"


def ids_in_field(value: Any, field_format: str) -> list[str]:
    """The technique ids a declared field's ``value`` names, read by the field's format."""
    if field_format == SIGMA_TAG_FORMAT:
        return sigma_technique_ids({"tags": value})
    return technique_ids_in(value)


def api_capability_hits(payload: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """The technique rules an ``api_capability`` result cleared, one row per rule.

    The tool answers per API and repeats a rule under every API it matched;
    here the matched APIs are pooled per rule and the rule counts only when
    they clear its own ``min_apis``. Each row: ``technique_id``, ``name``,
    ``rule``, ``matched_apis`` in first-seen order, and ``benign_rate`` —
    what share of a named benign corpus the rule fires on, which is the fact
    the platform states about a deterministic association and the thing a
    reader needs to weigh one. Corroboration and the report's projection both
    read this, so what one calls asserted the other shows.

    The rate is carried down here, and not looked up again later, because the
    answer that produced the row is the answer the run recorded: the report has
    to show what the catalogue said when the tool was asked, not what a
    catalogue edited since would say.

    **A row is a rule, not a technique.** Two rules can name one technique by
    two mechanisms — the catalogue's own name is on both, so the name does not
    tell them apart, and each carries its own ``min_apis``. Keyed by name
    alone they pooled: one rule's APIs counted toward the other's floor, so a
    technique could be asserted on a combination no single rule ever cleared.
    The rule's own label is part of the key, and is on the row so a reader can
    tell two rows for one technique apart. Corroboration keys on the technique
    id and is unchanged by the split.
    """
    if not isinstance(payload, Mapping):
        return []
    # The names the caller said it resolved at runtime rather than read in the
    # import table: a row whose matched names include them says which.
    resolved = {str(n) for n in (payload.get("resolved_at_runtime_from_hashes") or [])}
    corpus = ""
    corpora = payload.get("corpora")
    if isinstance(corpora, Mapping):
        corpus = str(corpora.get("benign") or "")
    rules: dict[tuple[str, str, str], tuple[int, list[str], str]] = {}
    for row in payload.get("capabilities") or []:
        if not isinstance(row, Mapping):
            continue
        for rule in row.get("techniques") or []:
            if not isinstance(rule, Mapping):
                continue
            ids = technique_ids_in(rule.get("technique_id"))
            if not ids:
                continue
            key = (ids[0], str(rule.get("name") or ""), str(rule.get("rule") or ""))
            _floor, apis, _rate = rules.setdefault(
                key, (_min_apis(rule), [], _benign_rate(rule, corpus))
            )
            for api in rule.get("matched") or []:
                name = str(api).strip()
                if name and name not in apis:
                    apis.append(name)
    out: list[dict[str, Any]] = []
    for (tid, name, label), (floor, apis, rate) in rules.items():
        if len(apis) < floor:
            continue
        row_out: dict[str, Any] = {
            "technique_id": tid,
            "name": name,
            "rule": label,
            "matched_apis": apis,
        }
        if rate:
            row_out["benign_rate"] = rate
        runtime = [api for api in apis if api in resolved]
        if runtime:
            row_out["resolved_apis"] = runtime
        out.append(row_out)
    return out


def _benign_rate(rule: Mapping[str, Any], corpus: str) -> str:
    """One sentence for how common a rule is in software that is not a sample.

    The sentence is written so it cannot be read as anything else. It says what
    the rule did — *fires on* — before it says a number, it names the corpus the
    number is a share of, and it carries the count behind the share, because a
    share rounded to one decimal place reads as zero for a rule that fires on
    one file in three thousand. It is emphatically not a probability that this
    sample is benign, and the value is persisted and read on its own, so the
    words that rule that reading out have to be inside the string rather than in
    the column it happens to be drawn in. A rule with no measurement gets no
    sentence rather than a zero.
    """
    measured = rule.get("measured")
    if not isinstance(measured, Mapping):
        return ""
    percent, files = measured.get("seen_on_benign_percent"), measured.get("seen_on_benign_files")
    if not isinstance(percent, int | float) or not isinstance(files, int):
        return ""
    of = f" of {corpus}" if corpus else " measured"
    sentence = f"fires on {percent:.1f}% of benign software ({files}{of})"
    # How thin the support is belongs beside how common the rule is, on the
    # same string, because the two are read together or not at all: a rule at
    # 1.0% of ordinary software reads well until you learn it has fired on no
    # malware the combination was not chosen on. Absent where the platform has
    # no malware corpus to count, which is not the same as a count of zero.
    support = measured.get("held_out_malware_profiles")
    if isinstance(support, int) and not isinstance(support, bool):
        one = support == 1
        sentence += (
            f"; {support} held-out malware {'profile supports' if one else 'profiles support'} it"
        )
    return sentence


def _min_apis(rule: Mapping[str, Any]) -> int:
    try:
        return max(1, int(rule.get("min_apis") or 1))
    except (TypeError, ValueError):
        return 1


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Iterable) and not isinstance(value, bytes | Mapping):
        for item in value:
            if isinstance(item, str):
                yield item
