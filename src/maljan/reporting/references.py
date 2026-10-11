"""The sample lookups a report links to: each from a source the run used, or one the operator set.

A tool server, a provider block or an in-process source declares the URL
templates it can look a sample up at (``reference_urls``: ``{sha256}``,
``{md5}``, ``{sha1}``, ``core.tool_declarations``). A report links a source's
lookups only when the run recorded an entry from that source: a run that never
asked a service publishes no link to it. The operator's own lookups
(``reporting.reference_urls``, shipped with the two every report linked
before) are linked on every report, first.

Read once, when the report is built, from the live declarations; the links are
stored with the report (``MalwareReport.references``), so a re-render reads
them as stored and never the reading process's settings.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from maljan.core.tool_declarations import REFERENCE_PLACEHOLDERS, ToolDeclarations

if TYPE_CHECKING:
    from maljan.reporting.models import ExternalReference

# What a sample lookup's link is said to be.
SAMPLE_LOOKUP_NOTE = "Sample lookup"


def filled(template: str, hashes: Any) -> str | None:
    """``template`` with each hash placeholder filled; ``None`` when a hash it names is unknown."""
    url = str(template)
    for placeholder in REFERENCE_PLACEHOLDERS:
        if placeholder not in url:
            continue
        value = str(getattr(hashes, placeholder.strip("{}"), "") or "").strip().lower()
        if not value or not value.isalnum():
            return None
        url = url.replace(placeholder, value)
    return url


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def used_sources(ledger: Iterable[Any] | None) -> list[str]:
    """Every source the ledger recorded an entry from (``mcp:<key>``, ``provider:<id>``), in order.

    An entry that recorded no source (written before sources were) is read by
    the tool server it names, as ``mcp:<server>``.
    """
    seen: dict[str, None] = {}
    for entry in ledger or ():
        source = ToolDeclarations.source_of(entry)
        if source is not None:
            seen.setdefault(str(source), None)
            continue
        server = str(_field(entry, "server") or "").strip()
        if server:
            seen.setdefault(f"mcp:{server}", None)
    return list(seen)


def _service_name(source: str, ledger: Iterable[Any], label: str) -> str:
    """What a source's link is named: the service its lookup's record names, else its label."""
    from maljan.core.reputation import reputation_of

    for entry in ledger:
        held = ToolDeclarations.source_of(entry)
        server = str(_field(entry, "server") or "")
        if (str(held) if held is not None else f"mcp:{server}") != source:
            continue
        record = reputation_of(entry)
        if record is not None and record.service:
            return str(record.service)
    return label


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except ValueError:
        return url


def declared_references(
    ledger: Iterable[Any] | None,
    hashes: Any,
    *,
    declared: ToolDeclarations | None = None,
    operator: Iterable[Any] = (),
) -> list[ExternalReference]:
    """The sample lookups a report links to: the operator's first, then each used source's.

    Each of the operator's lookups (``operator``: a template, or an object with
    ``url``, ``source`` and ``note``) gives one link, named by its ``source``
    (else the template's host) with its ``note`` (else "Sample lookup"); then
    each source that declares ``reference_urls`` and that the run recorded an
    entry from gives one link per template it could fill, in the order the
    sources are declared. A link already given is not given twice.
    """
    from maljan.reporting.models import ExternalReference

    rows = list(ledger or ())
    used = set(used_sources(rows))
    if declared is None:
        from maljan.core.declared_reading import declarations

        declared = declarations()
    refs: list[ExternalReference] = []
    given: set[str] = set()
    for lookup in operator:
        template = str(lookup if isinstance(lookup, str) else getattr(lookup, "url", ""))
        url = filled(template, hashes)
        if url and url not in given:
            given.add(url)
            name = "" if isinstance(lookup, str) else str(getattr(lookup, "source", "") or "")
            note = "" if isinstance(lookup, str) else str(getattr(lookup, "note", "") or "")
            sigma = False if isinstance(lookup, str) else bool(getattr(lookup, "sigma", False))
            refs.append(
                ExternalReference(
                    source=name or _host(url),
                    url=url,
                    note=note or SAMPLE_LOOKUP_NOTE,
                    sigma=sigma,
                )
            )
    for held in declared.sources():
        if not held.reference_urls or str(held.source) not in used:
            continue
        name = _service_name(str(held.source), rows, held.label)
        for template in held.reference_urls:
            url = filled(template, hashes)
            if url and url not in given:
                given.add(url)
                refs.append(ExternalReference(source=name, url=url, note=SAMPLE_LOOKUP_NOTE))
    return refs
