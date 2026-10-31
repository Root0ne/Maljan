"""Post-verdict enrichment sources, declared as data.

A source is one entry of ``api.enrichment_sources`` (or one the platform ships,
:mod:`maljan.enrichment.builtin_sources`): the indicator kinds it answers, how
it is asked, and where its answer's facts sit. It is asked one of two ways:

* **a declared tool server's tool** (``server``, and ``tool`` where it names
  one): a server tagged ``reputation`` whose tool takes the indicator in the
  argument its declaration names for that kind (``ToolFacts.arguments``,
  #266), or the one the source names in ``arguments``. A source that names
  no tool is asked through the server's indicator lookup for the kind: the
  first tool its tools list ticks whose declaration in force (its block's,
  its server's own, or what is read of its listing,
  ``core.derived_declarations``) is a lookup about an indicator
  (``core.reputation.INDICATOR_LOOKUP_KINDS``) and names an argument for the
  kind, and that sends nothing of the sample;
* **a REST endpoint** (``requests``): one request per kind, an https URL whose
  host is fixed by the declaration. ``{value}`` stands for the indicator (a
  URL-encoded path segment in the URL, as written in a query parameter or a
  JSON body) and ``{credential}`` for the source's credential, which may sit
  in a header, a query parameter or the body, never in the URL's path.

The credential is read from ``credential`` (a secret setting the platform
generates from a shipped source's declaration, :func:`credential_settings_of`)
or, where that is empty, from the source's own ``api_key``, stored encrypted
beside the map.

The answer is read through ``record``: each field names a path under
``answer_root`` (``core.tool_declarations.select`` paths) and how the value is
held. The record is the shape every reader of ``network.domains[].reputation``
and ``network.ips[].reputation`` already reads: ``source`` first, then the
declared fields in their order. ``malicious_when`` says which counts mark the
indicator malicious, and ``age_from`` which field holds the answer's date in
whole seconds since the epoch. A server source that declares no ``record``
is read as a reputation answer (:func:`read_reputation_record`): through the
paths its tool's declaration gives, else by the shape every reputation answer
has (``core.reputation.read_shape``), into the fields of
:data:`REPUTATION_RECORD_FIELDS`.

Nothing here names a service: the built-in sources are entries of the same
schema.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote, quote_plus, unquote, urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from maljan.core.logger import logger
from maljan.core.tool_declarations import first, parse_path, select
from maljan.tools.errors import error_parts

# The indicator kinds post-verdict enrichment asks about: the report holds a
# reputation slot for each (``network.domains``, ``network.ips``).
ASKED_KINDS: tuple[str, ...] = ("domain", "ip")
# Kinds an indicator has that enrichment does not ask about. The sample's own
# hash is asked by a declared reputation lookup tool (``core.reputation``).
UNASKED_KINDS: tuple[str, ...] = ("hash", "url")

# The placeholders a request template may hold.
VALUE = "{value}"
CREDENTIAL = "{credential}"

# A source's key: the shape a tool server's key has.
SOURCE_KEY_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
_KEY_RE = re.compile(SOURCE_KEY_PATTERN)
_FIELD_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_SETTING_RE = re.compile(r"^(api|core)\.[a-z0-9_]+(\.[a-z0-9_]+)*$")

# The longest indicator value sent to a source: the longest DNS name.
_MAX_VALUE_CHARS = 253
# A connection test is a person waiting at a button.
PROBE_TIMEOUT_SECONDS = 10.0
# How many times the age of a reputation must exceed this many days to be stale.
STALE_REPUTATION_DAYS = 90
# The fields a server source that declares no ``record`` stores, in order,
# each only where the answer gave it (:func:`read_reputation_record`): the
# engine counts, the labels, the dates and the link of a reputation answer,
# and the service it attributes them to. The counts are the ones its
# ``malicious_when`` may name.
REPUTATION_RECORD_COUNTS: tuple[str, ...] = ("malicious", "suspicious", "total", "engines")
REPUTATION_RECORD_FIELDS: tuple[str, ...] = (
    *REPUTATION_RECORD_COUNTS,
    "labels",
    "first_seen",
    "last_seen",
    "link",
    "service",
)
# How many labels such a record keeps, as a declared ``texts`` field's limit.
REPUTATION_RECORD_LABELS = 5


def check_source_key(key: str) -> str:
    if not _KEY_RE.match(key or ""):
        raise ValueError(
            f"source key {key!r} must be a lowercase slug (letters, digits, '-' and '_', "
            "starting with a letter, at most 32 characters)"
        )
    return key


def _holds(template: Any, placeholder: str) -> bool:
    if isinstance(template, str):
        return placeholder in template
    if isinstance(template, Mapping):
        return any(_holds(v, placeholder) for v in template.values())
    if isinstance(template, list | tuple):
        return any(_holds(v, placeholder) for v in template)
    return False


# Every placeholder a template may hold, found in one scan of the template.
_PLACEHOLDER = re.compile(r"\{(value|credential)\}")


def _filled(template: Any, value: str, credential: str) -> Any:
    """``template`` with each placeholder replaced in one pass over the template.

    The inserted text is never scanned again, so an indicator that holds
    ``{credential}`` (or any placeholder) is sent as the characters it is.
    """
    if isinstance(template, str):
        return _PLACEHOLDER.sub(lambda m: value if m.group(1) == "value" else credential, template)
    if isinstance(template, Mapping):
        return {k: _filled(v, value, credential) for k, v in template.items()}
    if isinstance(template, list | tuple):
        return [_filled(v, value, credential) for v in template]
    return template


class RestRequest(BaseModel):
    """One request a REST source is asked with."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["GET", "POST"] = "GET"
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None

    @field_validator("url")
    @classmethod
    def _an_https_url_with_a_fixed_host(cls, value: str) -> str:
        if CREDENTIAL in value:
            raise ValueError(
                "url may not hold {credential}: put it in a header, a query parameter or the body"
            )
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise ValueError("url must be an https URL")
        if not parsed.hostname or "{" in parsed.netloc or "}" in parsed.netloc:
            raise ValueError("url must name its host, without a placeholder")
        if "@" in parsed.netloc:
            raise ValueError("url may not hold a user name or password")
        return value

    @property
    def host(self) -> str:
        return str(urlparse(self.url).hostname or "")

    def holds_credential(self) -> bool:
        return (
            _holds(self.params, CREDENTIAL)
            or _holds(self.headers, CREDENTIAL)
            or _holds(self.json_body, CREDENTIAL)
        )

    def build(self, value: str, credential: str) -> dict[str, Any]:
        """The arguments of ``httpx.AsyncClient.request`` for ``value``.

        Each slot takes the value in its own encoding: URL-encoded as one path
        segment in the URL (which never holds the credential), as text in a
        query parameter (which the client URL-encodes), and as an opaque value
        in a header or the JSON body.

        Where the URL carries a query of its own and ``params`` are declared
        too, the client would send only ``params``; so the URL's own pairs are
        kept first, in order and repeated keys as written, and the declared
        ``params`` follow them.
        """
        url = _filled(self.url, quote(value, safe=""), "")
        built: dict[str, Any] = {
            "method": self.method,
            "url": url,
            "headers": _filled(self.headers, value, credential),
        }
        if self.params:
            params = list(_filled(self.params, value, credential).items())
            base, mark, query = url.partition("?")
            if mark:
                own = [pair.partition("=") for pair in query.split("&") if pair]
                params = [(unquote(k), unquote(v)) for k, _, v in own] + params
                built["url"] = base
            built["params"] = params
        if self.json_body is not None:
            built["json"] = _filled(self.json_body, value, credential)
        return built


class RecordField(BaseModel):
    """One field of the stored reputation record, read from the answer.

    ``read``: ``count`` is a whole number, written only when the answer gave
    one (an absent or unreadable count is not 0: nothing was counted);
    ``value`` the value as written, ``None`` when absent; ``whole`` a whole
    number written only when the answer gave one; ``texts`` the texts of an
    object's values or a list's items (the first ``limit``), written only
    when the answer gave either.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    path: str
    read: Literal["count", "value", "whole", "texts"] = "value"
    limit: int | None = Field(default=None, ge=1)

    @field_validator("name")
    @classmethod
    def _a_field_name(cls, value: str) -> str:
        if not _FIELD_RE.match(value) or value == "source":
            raise ValueError(f"record field {value!r} must be a lowercase word other than 'source'")
        return value

    @field_validator("path")
    @classmethod
    def _a_path(cls, value: str) -> str:
        if not value:
            raise ValueError("a record field needs a path")
        parse_path(value)
        return value


class Threshold(BaseModel):
    """A record field at or above ``at_least`` marks the indicator malicious."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    at_least: float


class EnrichmentSource(BaseModel):
    """One declared post-verdict enrichment source (see the module docstring)."""

    model_config = ConfigDict(extra="forbid")

    label: str = ""
    enabled: bool = True
    kinds: list[str] = Field(min_length=1)
    # Lower first: the first source of a kind that answers is the one kept.
    order: int = 100
    # A declared tool server's tool.
    server: str = ""
    tool: str = ""
    arguments: dict[str, str] = Field(default_factory=dict)
    # A REST endpoint.
    requests: dict[str, RestRequest] = Field(default_factory=dict)
    credential: str = ""
    api_key: SecretStr = SecretStr("")
    probe: RestRequest | None = None
    timeout_seconds: float = Field(default=30.0, gt=0)
    rate_limit_seconds: float = Field(default=0.0, ge=0)
    # The answer. A server source that declares no record is read as a
    # reputation answer (:func:`read_reputation_record`).
    answer_root: str = ""
    record: list[RecordField] = Field(default_factory=list)
    record_source: str = ""
    malicious_when: list[Threshold] = Field(default_factory=list)
    age_from: str = ""

    @field_validator("kinds")
    @classmethod
    def _each_kind_once(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("kinds names a kind twice")
        unasked = [k for k in value if k in UNASKED_KINDS]
        if unasked:
            raise ValueError(
                f"kinds {', '.join(unasked)}: post-verdict enrichment asks only about "
                f"{' and '.join(ASKED_KINDS)}; hash reputation is declared as a reputation "
                "lookup tool (a server tool of kind reputation that takes the hash), which "
                "the triage pack and the judge ask"
            )
        unknown = [k for k in value if k not in ASKED_KINDS]
        if unknown:
            raise ValueError(
                f"kinds {', '.join(unknown)}: an indicator kind is one of {', '.join(ASKED_KINDS)}"
            )
        return value

    @field_validator("server")
    @classmethod
    def _a_server_key(cls, value: str) -> str:
        if value and not _KEY_RE.match(value):
            raise ValueError("server must be the key of a server in mcp.servers")
        return value

    @field_validator("credential")
    @classmethod
    def _a_settings_key(cls, value: str) -> str:
        if value and not _SETTING_RE.match(value):
            raise ValueError(f"credential {value!r} must be a settings key (api.… or core.…)")
        return value

    @field_validator("answer_root")
    @classmethod
    def _a_root_path(cls, value: str) -> str:
        parse_path(value)
        return value

    @model_validator(mode="after")
    def _one_way_to_ask(self) -> EnrichmentSource:
        by_server = bool(self.server or self.tool)
        if by_server and self.requests:
            raise ValueError("declare either server and tool, or requests, not both")
        if by_server:
            if not self.server:
                raise ValueError("a server source needs server: the key of a server in mcp.servers")
            if self.arguments and not self.tool:
                raise ValueError(
                    "arguments name a tool's argument; name the tool too, or leave both out "
                    "to ask the server's indicator lookups"
                )
        elif not self.requests:
            raise ValueError("declare server and tool, or one request per kind in requests")
        elif not self.record:
            raise ValueError("a REST source needs record: the fields its answer is read into")
        else:
            missing = [k for k in self.kinds if k not in self.requests]
            extra = [k for k in self.requests if k not in self.kinds]
            if missing or extra:
                raise ValueError(
                    "requests must hold exactly one request per kind in kinds"
                    + (f"; missing {', '.join(missing)}" if missing else "")
                    + (f"; not in kinds {', '.join(extra)}" if extra else "")
                )
        if self.arguments and not by_server:
            raise ValueError("arguments name a server tool's argument; a REST source takes none")
        unused = [k for k in self.arguments if k not in self.kinds]
        if unused:
            raise ValueError(
                f"arguments name kinds the source does not answer: {', '.join(unused)}"
            )
        names = [f.name for f in self.record]
        if len(set(names)) != len(names):
            raise ValueError("record names a field twice")
        if self.record:
            counted: list[str] = names
        else:
            # Read as a reputation answer: its counts are the ones a threshold reads.
            counted = list(REPUTATION_RECORD_COUNTS)
            if self.answer_root:
                raise ValueError(
                    "answer_root names where a declared record is read; declare record"
                )
        unknown = [t.field for t in self.malicious_when if t.field not in counted]
        if unknown:
            raise ValueError(f"malicious_when names fields the record lacks: {', '.join(unknown)}")
        if self.age_from and self.age_from not in names:
            raise ValueError(f"age_from {self.age_from!r} is not a record field")
        return self

    def needs_credential(self) -> bool:
        """Whether any of its requests carries the credential."""
        return any(r.holds_credential() for r in self.requests.values())

    def title(self, key: str) -> str:
        return self.label or key


# ---------------------------------------------------------------------------
# The effective list
# ---------------------------------------------------------------------------


def merged_entries(stored: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """The built-in entries with each stored entry laid over its key, field by field.

    A stored entry under a built-in's key changes only the fields it names
    (``{"enabled": false}`` turns one off); any other key is a source of its
    own. The built-ins come first, in the order they ship, then the rest in
    stored order.
    """
    from maljan.enrichment.builtin_sources import builtin_source_entries

    out = builtin_source_entries()
    for key, entry in (stored or {}).items():
        if not isinstance(entry, Mapping):
            out[str(key)] = entry  # type: ignore[assignment]  # refused by validation
            continue
        out[str(key)] = {**out.get(str(key), {}), **dict(entry)}
    return out


def validate_sources(stored: Mapping[str, Any] | None) -> dict[str, str]:
    """Per source key, why its effective entry is refused; empty when every one validates."""
    from pydantic import ValidationError

    errors: dict[str, str] = {}
    if stored is not None and not isinstance(stored, Mapping):
        return {"": "enrichment sources are a map of source key to source"}
    for key, entry in merged_entries(stored).items():
        try:
            check_source_key(key)
            if not isinstance(entry, Mapping):
                raise ValueError("a source is an object")
            EnrichmentSource.model_validate(entry)
        except ValidationError as exc:
            errors[key] = "; ".join(
                f"{'.'.join(str(p) for p in e['loc']) or 'source'}: {e['msg']}"
                for e in exc.errors()
            )
        except ValueError as exc:
            errors[key] = str(exc)
    return errors


def effective_sources(stored: Mapping[str, Any] | None) -> dict[str, EnrichmentSource]:
    """Every source in force: built-ins under the stored entries, an invalid one left out."""
    from pydantic import ValidationError

    out: dict[str, EnrichmentSource] = {}
    for key, entry in merged_entries(stored if isinstance(stored, Mapping) else None).items():
        try:
            check_source_key(key)
            out[key] = EnrichmentSource.model_validate(entry)
        except (ValidationError, ValueError, TypeError):
            # The key is named only once it is a valid slug: one that is not
            # could carry anything into the log.
            if _KEY_RE.match(key):
                logger.warning("enrich: source %s is not a valid declaration; left out.", key)
            else:
                logger.warning("enrich: a source with an invalid key is left out.")
    return out


@dataclass(frozen=True)
class CredentialSetting:
    """The secret setting a source declaration reads its credential from, as the catalog lists it.

    Made from the declaration alone (:func:`credential_settings_of`): its
    title names the source by its label, and its description says what
    leaves the host once it is set, and for where.
    """

    path: str
    source: str
    label: str
    kinds: tuple[str, ...]
    hosts: tuple[str, ...]
    probe: bool

    @property
    def key(self) -> str:
        return f"api.{self.path}"

    @property
    def title(self) -> str:
        return f"{self.label} API key"

    @property
    def description(self) -> str:
        kinds = " and ".join(
            f"{kind}s" if kind == "domain" else f"{kind.upper()}s" for kind in self.kinds
        )
        hosts = ", ".join(self.hosts) or "the host its declaration names"
        return (
            f"The credential of the {self.label} enrichment source (`{self.source}`). While it is "
            f"set, the report's {kinds} are looked up at {hosts} and leave this host."
        )


def credential_settings_of(entries: Mapping[str, Any]) -> dict[str, CredentialSetting]:
    """Per ``api.*`` leaf, the secret setting the valid declarations of ``entries`` name.

    Read from each declaration's ``credential`` (a leaf directly under
    ``api``), in the entries' order; a leaf two sources name is the first's.
    A declaration that does not validate names none.
    """
    from pydantic import ValidationError

    out: dict[str, CredentialSetting] = {}
    for key, entry in entries.items():
        try:
            check_source_key(str(key))
            source = EnrichmentSource.model_validate(entry)
        except (ValidationError, ValueError, TypeError):
            continue
        namespace, _, path = source.credential.partition(".")
        if namespace != "api" or not path or "." in path or path in out:
            continue
        out[path] = CredentialSetting(
            path=path,
            source=str(key),
            label=source.title(str(key)),
            kinds=tuple(source.kinds),
            hosts=tuple(sorted({request.host for request in source.requests.values()})),
            probe=source.probe is not None,
        )
    return out


@dataclass(frozen=True)
class ReadySource:
    """A source in force with the credential it reads, and whether its server is on."""

    key: str
    source: EnrichmentSource
    credential: str = ""
    server_enabled: bool = True

    @property
    def configured(self) -> bool:
        """Enabled, holding the credential it needs, and its server on (for a server source)."""
        if not self.source.enabled:
            return False
        if self.source.server:
            return self.server_enabled
        return bool(self.credential) or not self.source.needs_credential()

    def answers(self, kind: str) -> bool:
        return kind in self.source.kinds

    @property
    def label(self) -> str:
        return self.source.title(self.key)


# ---------------------------------------------------------------------------
# Reading an answer
# ---------------------------------------------------------------------------


def _count(value: Any) -> int | None:
    """``value`` as a whole-number count, or ``None`` when it is no count.

    An absent or unreadable count stays absent: reading it as 0 would record
    "no engine flagged it" for an answer that counted nothing.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _document(output: Any) -> Any:
    if isinstance(output, dict | list):
        return output
    text = str(output or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def read_record(key: str, source: EnrichmentSource, answer: Any) -> dict[str, Any] | None:
    """The record ``source``'s answer gives, or ``None`` when it gives none.

    ``None`` when its root holds no object, or when no declared field found a
    value in it (an answer saying the service has nothing, or a shape the
    declaration does not read): a record of the source's name alone would
    mark the indicator as looked up, and stop the next source being asked,
    for an answer that said nothing.
    """
    document = _document(answer)
    root = first(document, source.answer_root) if source.answer_root else document
    if not isinstance(root, Mapping):
        return None
    record: dict[str, Any] = {"source": source.record_source or key}
    gave = False
    for spec in source.record:
        found = select(root, spec.path)
        value = found[0] if found else None
        gave = gave or value is not None
        if spec.read == "count":
            counted = _count(value)
            if counted is not None:
                record[spec.name] = counted
        elif spec.read == "value":
            record[spec.name] = value
        elif spec.read == "whole":
            if isinstance(value, int):
                record[spec.name] = value
        elif isinstance(value, Mapping | list):
            items = list(value.values()) if isinstance(value, Mapping) else list(value)
            record[spec.name] = [str(v) for v in items[: spec.limit]]
    return record if gave else None


def read_reputation_record(
    key: str, source: EnrichmentSource, facts: Any, answer: Any
) -> dict[str, Any] | None:
    """The record a server source that declares no ``record`` keeps, or ``None``.

    Its tool's answer read as every reputation answer is
    (``core.reputation.read_answer``): through the paths its declaration in
    force gives (``facts``), and where it gives none, by the answer's shape
    (``core.reputation.read_shape``). The record holds ``source`` (the
    source's ``record_source``, else its server's key) and each of
    :data:`REPUTATION_RECORD_FIELDS` the answer gave, never one it did not;
    ``service`` only where the answer names a service other than the source.
    ``None`` when the answer gave no count and no label: a call that returned
    is not an answer about the indicator.
    """
    from maljan.core.reputation import SHAPE_READER, declares_paths, read_answer
    from maljan.core.tool_declarations import ToolFacts

    if not isinstance(facts, ToolFacts):
        facts = ToolFacts.model_construct()
    if not declares_paths(facts.reputation):
        facts = facts.model_copy(update={"reader": SHAPE_READER})
    document = _document(answer)
    text = answer if isinstance(answer, str) else ""
    read = read_answer(facts, output=text, structured=document, server="")
    named = source.record_source or source.server or key
    record: dict[str, Any] = {"source": named}
    values: dict[str, Any] = {
        "malicious": read.malicious,
        "suspicious": read.suspicious,
        "total": read.total,
        "engines": read.engines,
        "labels": list(read.labels[:REPUTATION_RECORD_LABELS]) or None,
        "first_seen": read.first_seen,
        "last_seen": read.last_seen,
        "link": read.link,
        "service": read.service if read.service and read.service != named else None,
    }
    for name in REPUTATION_RECORD_FIELDS:
        if values[name] is not None:
            record[name] = values[name]
    said = any(record.get(name) is not None for name in REPUTATION_RECORD_COUNTS)
    return record if said or "labels" in record else None


def annotate_age(record: dict[str, Any], source: EnrichmentSource) -> None:
    """Add ``age_days`` (and ``stale``) from the field ``age_from`` names."""
    if not source.age_from:
        return
    ts = record.get(source.age_from)
    if isinstance(ts, int) and ts > 0:
        age_days = (time.time() - ts) / 86400.0
        record["age_days"] = round(age_days, 1)
        if age_days > STALE_REPUTATION_DAYS:
            record["stale"] = True


def declared_verdict(record: dict[str, Any] | None, source: EnrichmentSource) -> bool | None:
    """The source's own verdict on a fresh record, or ``None`` where it gives none.

    ``True`` when a threshold whose field holds a count is reached (the
    thresholds are alternatives, so one is enough). ``False`` only when every
    threshold's field holds a count and none is reached. ``None`` (unknown, never
    ``False``) in every other case: the source declares no threshold, the record
    is stale, or a threshold's field holds no count and no other threshold is reached.
    """
    if not isinstance(record, dict) or record.get("stale") or not source.malicious_when:
        return None
    counts = [(_count(record.get(t.field)), t.at_least) for t in source.malicious_when]
    if any(counted is not None and counted >= at_least for counted, at_least in counts):
        return True
    return False if all(counted is not None for counted, _ in counts) else None


def is_malicious(record: dict[str, Any] | None, source: EnrichmentSource) -> bool:
    """Whether a fresh record reaches any of the source's ``malicious_when`` thresholds."""
    return declared_verdict(record, source) is True


# ---------------------------------------------------------------------------
# Asking
# ---------------------------------------------------------------------------


def safe_value(kind: str, value: str) -> bool:
    """Whether ``value`` may be sent as an indicator of ``kind``."""
    if not value or len(value) > _MAX_VALUE_CHARS and kind != "url":
        return False
    if kind == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True
    if kind == "url":
        return len(value) <= 2048 and all(ord(ch) >= 0x20 and ch != " " for ch in value)
    return all(ord(ch) >= 0x20 and ch not in {" ", "/", "?", "#"} for ch in value)


ToolCaller = Callable[[str, str, dict[str, Any]], Awaitable[Any]]
# Told of each question about to be sent: ``(source, host, kind, server)``,
# the host for a REST source and the server's key for a server source. It may
# answer an awaitable, awaited before the question goes out, and may answer
# (or resolve to) a settle function, called with whether the question was
# answered once it was or failed (``settle_asked``).
AskListener = Callable[[str, str, str, str], Any]
Settle = Callable[..., None]


async def tell_listener(
    listener: AskListener | None, source: str, host: str, kind: str, server: str
) -> Settle | None:
    """Tell ``listener`` of a question about to go out; its settle function, or ``None``.

    Never raises: a listener that fails never costs a lookup.
    """
    if listener is None:
        return None
    try:
        said = listener(source, host, kind, server)
        if asyncio.iscoroutine(said) or isinstance(said, asyncio.Future):
            said = await said
        return said if callable(said) else None
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 — a listener never costs a lookup
        logger.debug("enrich: the ask listener failed (%s).", type(exc).__name__)
        return None


def settle_asked(settle: Settle | None, answered: bool, *, errored: bool = False) -> None:
    """Tell a question's settle function how it ended. Never raises.

    ``errored`` is a reply with an error status (refused, rate-limited, a
    fault): the question arrived, though it was not answered.
    """
    if settle is None:
        return
    try:
        if errored and not answered:
            settle(answered, True)
        else:
            settle(answered)
    except Exception as exc:  # noqa: BLE001
        logger.debug("enrich: the ask listener failed to settle (%s).", type(exc).__name__)


@dataclass
class SourceAsker:
    """Asks the ready sources, one HTTP client and one pace per source for a whole enrichment.

    ``on_ask`` is told of each question just before it is sent, for the run's
    disclosure block (``analysis.disclosure.with_enrichment_asked``).
    """

    http: httpx.AsyncClient
    tool_caller: ToolCaller | None = None
    tool_arguments: Callable[[str, str], Mapping[str, str]] | None = None
    on_ask: AskListener | None = None
    _paces: dict[str, asyncio.Semaphore] = field(default_factory=dict)

    async def _told(self, source: str, host: str, kind: str, server: str) -> Settle | None:
        return await tell_listener(self.on_ask, source, host, kind, server)

    async def ask(self, ready: ReadySource, kind: str, value: str) -> dict[str, Any] | None:
        """``ready``'s record for ``value``, or ``None`` on any failure (never raises)."""
        if not safe_value(kind, value):
            return None
        facts: Any = None
        try:
            if ready.source.server:
                answer, facts = await self._ask_server(ready, kind, value)
            else:
                answer = await self._ask_rest(ready, kind, value)
        except Exception as exc:  # noqa: BLE001 — one source's failure is no lookup
            logger.warning("enrich: source %s failed (%s).", ready.key, type(exc).__name__)
            return None
        if answer is None:
            return None
        failure = error_parts(answer)
        if failure is not None:
            # A tool's structured failure (not configured, rate-limited, a
            # refused argument) is no answer about the indicator, and its
            # JSON must not be read as a record of one.
            logger.warning(
                "enrich: source %s answered a failure (%s); not recorded.", ready.key, failure[0]
            )
            return None
        if not ready.source.record:
            return read_reputation_record(ready.key, ready.source, facts, answer)
        return read_record(ready.key, ready.source, answer)

    async def _lookups(self, ready: ReadySource, kind: str) -> list[tuple[str, str, Any]]:
        """The tools ``ready`` may be asked about ``kind`` through, in order, with their arguments.

        The source's own tool and arguments where it names them; the
        argument, and for a source that names no tool the tools too, as the
        caller reads the server's declarations in force (``indicator_lookups``,
        every candidate in the order to try them).
        """
        source = ready.source
        lookups = getattr(self.tool_caller, "indicator_lookups", None)
        tool, argument = source.tool, source.arguments.get(kind, "")
        found: list[tuple[str, str, Any]] = []
        if lookups is not None and (not tool or not argument or not source.record):
            found = list(await lookups(source.server, kind, tool))
        if tool:
            facts = found[0][2] if found else None
            argument = argument or (found[0][1] if found else "")
            if not argument and self.tool_arguments is not None:
                argument = self.tool_arguments(source.server, tool).get(kind, "")
            if not argument:
                logger.warning(
                    "enrich: source %s names no argument for a kind; not asked.", ready.key
                )
                return []
            return [(tool, argument, facts)]
        if not found:
            logger.info(
                "enrich: source %s's server declares no indicator lookup for a kind; not asked.",
                ready.key,
            )
        return found

    async def _ask_server(self, ready: ReadySource, kind: str, value: str) -> tuple[Any, Any]:
        """The first answer of ``ready``'s lookups for ``kind`` that is no failure, and its facts.

        A lookup that fails (no answer, or a structured failure) is followed
        by the next one, each told as its own question. A source paced by its
        ``rate_limit_seconds`` pauses after each question, as a REST source does.
        """
        source = ready.source
        if self.tool_caller is None:
            return None, None
        answer: Any = None
        facts: Any = None
        for tool, argument, facts in await self._lookups(ready, kind):
            # A tool its host withholds is never asked, so it is never told as a
            # question either: the caller records it as withheld, with its reason.
            withheld = getattr(self.tool_caller, "withheld_reason", None)
            if withheld is not None and await withheld(source.server, tool):
                continue
            pace = self._paces.setdefault(ready.key, asyncio.Semaphore(1))
            async with pace:
                settle = await self._told(ready.key, "", kind, source.server)
                answer = None
                try:
                    answer = await self.tool_caller(source.server, tool, {argument: value})
                finally:
                    # Answered only when the tool gave an answer that is not a failure.
                    settle_asked(settle, answer is not None and error_parts(answer) is None)
                if source.rate_limit_seconds:
                    await asyncio.sleep(source.rate_limit_seconds)
            if answer is not None and error_parts(answer) is None:
                return answer, facts
        return answer, facts

    async def _ask_rest(self, ready: ReadySource, kind: str, value: str) -> Any:
        source = ready.source
        request = source.requests[kind]  # type: ignore[index]
        built = request.build(value, ready.credential)
        if urlparse(built["url"]).hostname != request.host:
            logger.warning("enrich: source %s request left its declared host; refused.", ready.key)
            return None
        pace = self._paces.setdefault(ready.key, asyncio.Semaphore(1))
        async with pace:
            settle = await self._told(ready.key, request.host, kind, "")
            try:
                resp = await self.http.request(**built, timeout=source.timeout_seconds)
                # An error status (refused, rate-limited, a fault) is no answer
                # about the indicator, but it proves the indicator arrived; a 404
                # is an answer: the source has no record of it.
                answered = resp.status_code < 400 or resp.status_code == 404
                settle_asked(settle, answered, errored=not answered)
            except httpx.HTTPError as exc:
                settle_asked(settle, False)
                logger.warning(
                    "enrich: source %s request failed (%s).", ready.key, type(exc).__name__
                )
                return None
            if source.rate_limit_seconds:
                await asyncio.sleep(source.rate_limit_seconds)
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            logger.warning("enrich: source %s answered HTTP %d.", ready.key, int(resp.status_code))
            return None
        if urlparse(str(resp.request.url)).hostname != request.host:
            logger.warning("enrich: source %s answered from another host; discarded.", ready.key)
            return None
        try:
            data = resp.json()
        except ValueError:
            logger.warning("enrich: source %s answered something other than JSON.", ready.key)
            return None
        return data if isinstance(data, dict | list) else None


def masked(text: str, credential: str) -> str:
    """``text`` with ``credential`` masked in every form a request may carry it.

    Raw (a header, a JSON body), percent-encoded as a path or query character
    run (``quote``, ``quote_plus``) and base64 (a basic-auth style header): an
    error message that quotes the request shows it in one of these. In one
    pass with every secret value this process holds
    (``settings_masking.masked_values``), the last step, so a short
    credential and a held value that overlaps it are masked as one run.
    """
    from maljan.core.settings_masking import masked_values

    forms = (
        {
            credential,
            quote(credential, safe=""),
            quote_plus(credential),
            quote(credential),
            base64.b64encode(credential.encode()).decode(),
        }
        if credential
        else set()
    )
    return masked_values(text, "***", literals=forms)


async def probe_source(source: EnrichmentSource, credential: str) -> Any:
    """The source's declared connection test: one request, ok below HTTP 400."""
    from maljan.core.settings_overrides import redact_url
    from maljan.providers.base import ProviderProbe

    t0 = time.perf_counter()

    def _ms() -> int:
        return int((time.perf_counter() - t0) * 1000)

    if source.probe is None:
        return ProviderProbe(False, "this source declares no connection test", 0)
    built = source.probe.build("", credential)
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
            answer = await client.request(**built)
    except httpx.TimeoutException:
        return ProviderProbe(False, f"timeout after {int(PROBE_TIMEOUT_SECONDS)} s", _ms())
    except httpx.HTTPError as exc:
        return ProviderProbe(
            False,
            masked(redact_url(f"{type(exc).__name__}: {exc}", by_value=False), credential),
            _ms(),
        )
    return ProviderProbe(answer.status_code < 400, f"HTTP {answer.status_code}", _ms())
