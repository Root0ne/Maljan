"""Enrichment sources are data: the shipped two make their calls, an invented one works too."""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from pydantic import ValidationError

from maljan.enrichment.declared import (
    EnrichmentSource,
    ReadySource,
    SourceAsker,
    effective_sources,
    probe_source,
    read_record,
    validate_sources,
)
from maljan.enrichment.orchestrator import enrich_malware_report


def _key(*parts: str) -> str:
    """A credential-shaped value built at run time."""
    return "-".join(parts)


def _host(*labels: str) -> str:
    return ".".join(labels)


INVENTED_HOST = _host("rep", "example", "org")


def _invented(**extra: Any) -> dict[str, Any]:
    """A domain reputation REST endpoint no code names, declared only as data."""
    return {
        "label": "Domain reputation",
        "kinds": ["domain"],
        "order": 5,
        "requests": {
            "domain": {
                "url": f"https://{INVENTED_HOST}/v1/domain/{{value}}",
                "headers": {"Authorization": "Bearer {credential}"},
            }
        },
        "probe": {
            "url": f"https://{INVENTED_HOST}/v1/ping",
            "headers": {"Authorization": "Bearer {credential}"},
        },
        "answer_root": "/result",
        "record": [
            {"name": "malicious", "path": "/votes/bad", "read": "count"},
            {"name": "suspicious", "path": "/votes/odd", "read": "count"},
            {"name": "harmless", "path": "/votes/good", "read": "count"},
            {"name": "undetected", "path": "/votes/none", "read": "count"},
            {"name": "last_analysis_date_unix", "path": "/seen", "read": "whole"},
        ],
        "malicious_when": [{"field": "malicious", "at_least": 1}],
        "age_from": "last_analysis_date_unix",
        **extra,
    }


class _Wire:
    def __init__(self, answer: Any = None, status: int = 200) -> None:
        self.answer = answer
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.answer, Exception):
            raise self.answer
        if isinstance(self.answer, bytes):
            return httpx.Response(self.status, content=self.answer)
        return httpx.Response(self.status, json=self.answer)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self))


def _ready(key: str, credential: str, stored: dict[str, Any] | None = None) -> ReadySource:
    return ReadySource(key=key, source=effective_sources(stored or {})[key], credential=credential)


async def _ask(ready: ReadySource, kind: str, value: str, wire: _Wire) -> dict[str, Any] | None:
    async with wire.client() as http:
        with patch("maljan.enrichment.declared.asyncio.sleep") as slept:
            record = await SourceAsker(http).ask(ready, kind, value)
    _ask.slept = [c.args[0] for c in slept.call_args_list]  # type: ignore[attr-defined]
    return record


# ---------------------------------------------------------------------------
# The shipped sources make the calls and store the records they always did
# ---------------------------------------------------------------------------


VT_ANSWER = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 10,
                "suspicious": 3,
                "harmless": 2,
                "undetected": 5,
            },
            "reputation": -42,
            "categories": {"vendor_a": "malware", "vendor_b": "phishing"},
            "last_analysis_date": 1_700_000_000,
        }
    }
}
# What the VirusTotal client stored for that answer, key for key, in order.
VT_RECORD = [
    ("source", "virustotal"),
    ("malicious", 10),
    ("suspicious", 3),
    ("harmless", 2),
    ("undetected", 5),
    ("reputation", -42),
    ("categories", ["malware", "phishing"]),
    ("last_analysis_date_unix", 1_700_000_000),
]


@pytest.mark.asyncio
async def test_the_shipped_domain_lookup_makes_the_same_call_and_stores_the_same_record() -> None:
    credential = _key("vt", "k")
    wire = _Wire(VT_ANSWER)
    record = await _ask(_ready("virustotal", credential), "domain", "evil.com", wire)
    (request,) = wire.requests
    assert request.method == "GET"
    assert str(request.url) == "https://www.virustotal.com/api/v3/domains/evil.com"
    assert request.headers["x-apikey"] == credential
    assert request.headers["accept"] == "application/json"
    assert request.extensions["timeout"]["read"] == 30.0
    assert record is not None and list(record.items()) == VT_RECORD
    # Paced at its free tier: 16 s after each call.
    assert _ask.slept == [16.0]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_the_shipped_address_lookup_makes_the_same_call() -> None:
    wire = _Wire({"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}})
    record = await _ask(_ready("virustotal", _key("vt", "k")), "ip", "1.2.3.4", wire)
    assert str(wire.requests[0].url) == "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"
    # Counts the answer left out stay absent: nothing counted them.
    assert record == {"source": "virustotal", "malicious": 1}


@pytest.mark.asyncio
async def test_the_shipped_abuse_check_makes_the_same_call_and_stores_the_same_record() -> None:
    credential = _key("ab", "k")
    wire = _Wire(
        {
            "data": {
                "abuseConfidenceScore": 88,
                "countryCode": "RU",
                "isp": "EvilNet",
                "domain": "evilnet.example",
                "totalReports": 42,
            }
        }
    )
    record = await _ask(_ready("abuseipdb", credential), "ip", "1.2.3.4", wire)
    (request,) = wire.requests
    assert (
        str(request.url)
        == "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90"
    )
    assert request.headers["Key"] == credential
    assert request.headers["Accept"] == "application/json"
    assert request.extensions["timeout"]["read"] == 20.0
    assert record is not None and list(record.items()) == [
        ("source", "abuseipdb"),
        ("abuse_confidence", 88),
        ("country", "RU"),
        ("isp", "EvilNet"),
        ("domain", "evilnet.example"),
        ("total_reports", 42),
    ]
    assert _ask.slept == []  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_the_shipped_tests_make_the_same_calls() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    real = httpx.AsyncClient

    def client(**kwargs: Any) -> httpx.AsyncClient:
        return real(transport=httpx.MockTransport(handler), **kwargs)

    credential = _key("t", "k")
    with patch("maljan.enrichment.declared.httpx.AsyncClient", client):
        vt = await probe_source(effective_sources({})["virustotal"], credential)
        abuse = await probe_source(effective_sources({})["abuseipdb"], credential)
    assert vt.ok and abuse.ok
    assert str(seen[0].url) == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    assert seen[0].headers["x-apikey"] == credential
    assert (
        str(seen[1].url)
        == "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1"
    )
    assert seen[1].headers["Key"] == credential


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "status"),
    [
        (None, 404),
        (None, 429),
        (None, 500),
        (b"not json", 200),
        (httpx.ConnectError("no route"), 200),
    ],
)
async def test_a_failed_answer_is_no_record(answer: Any, status: int) -> None:
    assert (
        await _ask(_ready("virustotal", _key("k")), "domain", "evil.com", _Wire(answer, status))
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("domain", ""),
        ("domain", "evil\x00.com"),
        ("domain", "a/b"),
        ("ip", "not-an-ip"),
        ("domain", "a" * 300),
    ],
)
async def test_an_unsafe_value_is_never_sent(kind: str, value: str) -> None:
    wire = _Wire({})
    assert await _ask(_ready("virustotal", _key("k")), kind, value, wire) is None
    assert wire.requests == []


def test_the_indicator_never_moves_the_host() -> None:
    source = effective_sources({})["virustotal"]
    built = source.requests["domain"].build("evil.com/../x" + chr(64) + "other", "")
    assert httpx.URL(built["url"]).host == "www.virustotal.com"


# A sample controls the names it resolves: each of these is a value a hostile
# sample can hand the enrichment as a domain.
HOSTILE_VALUES = [
    "{credential}.evil-c2.com",
    "{value}{credential}.evil-c2.com",
    "%7Bcredential%7D.evil-c2.com",
    "{credential}",
    "a\r\nX-Injected: {credential}.evil-c2.com",
]


def _echoing_source() -> EnrichmentSource:
    """A source that takes the value in every slot, and whose service echoes what it got."""
    return EnrichmentSource.model_validate(
        {
            "kinds": ["domain"],
            "requests": {
                "domain": {
                    "method": "POST",
                    "url": f"https://{INVENTED_HOST}/v1/{{value}}/lookup",
                    "params": {"q": "{value}", "key": "{credential}"},
                    "headers": {"Authorization": "Bearer {credential}", "X-Query": "{value}"},
                    "json_body": {"query": "{value}", "nested": ["{value}"]},
                }
            },
            "answer_root": "/echo",
            "record": [
                {"name": "path", "path": "/path"},
                {"name": "q", "path": "/q"},
                {"name": "header", "path": "/header"},
                {"name": "body", "path": "/body"},
            ],
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("value", HOSTILE_VALUES)
async def test_a_hostile_indicator_never_carries_the_credential_anywhere(
    value: str, caplog: pytest.LogCaptureFixture
) -> None:
    import json as _json
    import logging

    caplog.set_level(logging.DEBUG)
    secret = _key("sec", "r3t", "v4lue")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        echo = {
            "path": request.url.path,
            "q": request.url.params.get("q"),
            "header": request.headers.get("X-Query"),
            "body": _json.loads(request.content),
        }
        return httpx.Response(200, json={"echo": echo})

    ready = ReadySource(key="echo", source=_echoing_source(), credential=secret)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        record = await SourceAsker(http).ask(ready, "domain", value)

    if "\r" in value or "\n" in value:
        # A value with a line break is never sent at all.
        assert seen == [] and record is None
        return
    (request,) = seen
    url = str(request.url)
    # The credential sits only where the declaration put it: the key parameter
    # and the Authorization header, once each.
    assert url.count(secret) == 1 and request.url.params.get("key") == secret
    assert request.url.path.count(secret) == 0
    assert request.headers["Authorization"] == f"Bearer {secret}"
    assert request.headers["X-Query"] == value
    assert secret not in request.content.decode()
    # Each slot received the indicator as written, in its own encoding.
    assert request.url.params.get("q") == value
    assert _json.loads(request.content) == {"query": value, "nested": [value]}
    assert record is not None and secret not in _json.dumps(record)
    assert record["q"] == value and record["header"] == value
    assert secret not in caplog.text


@pytest.mark.asyncio
async def test_a_url_s_own_query_is_kept_beside_the_declared_params() -> None:
    source = EnrichmentSource.model_validate(
        _invented(
            requests={
                "domain": {
                    "url": f"https://{INVENTED_HOST}/v1/lookup?a=1&a=2&fmt=j%20son&v={{value}}",
                    "params": {"b": "{value}", "key": "{credential}"},
                }
            }
        )
    )
    wire = _Wire({"result": {"votes": {"bad": 0}}})
    secret = _key("q", "k")
    record = await _ask(
        ReadySource(key="domainrep", source=source, credential=secret), "domain", "evil.com", wire
    )
    (request,) = wire.requests
    # The URL's pairs first, in order, repeated keys as written; then the declared params.
    assert list(request.url.params.multi_items()) == [
        ("a", "1"),
        ("a", "2"),
        ("fmt", "j son"),
        ("v", "evil.com"),
        ("b", "evil.com"),
        ("key", secret),
    ]
    assert record is not None


def test_a_url_s_own_query_alone_is_sent_as_written() -> None:
    source = EnrichmentSource.model_validate(
        _invented(requests={"domain": {"url": f"https://{INVENTED_HOST}/v1?x=1&v={{value}}"}})
    )
    built = source.requests["domain"].build("evil.com", "")
    assert built["url"] == f"https://{INVENTED_HOST}/v1?x=1&v=evil.com"
    assert "params" not in built


@pytest.mark.asyncio
async def test_a_failing_source_is_named_by_its_key_in_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    caplog.set_level(logging.WARNING)
    await _ask(_ready("virustotal", _key("k")), "domain", "evil.com", _Wire(None, 500))
    assert "enrich: source virustotal answered HTTP 500." in caplog.text


def test_every_placeholder_is_filled_in_one_pass() -> None:
    from maljan.enrichment.declared import _filled

    assert _filled("{value}|{credential}", "{credential}", "S") == "{credential}|S"
    assert _filled({"a": ["{value}"]}, "{value}", "S") == {"a": ["{value}"]}


def test_a_probe_error_masks_the_credential_in_every_encoding() -> None:
    import base64
    from urllib.parse import quote, quote_plus

    from maljan.enrichment.declared import masked

    secret = _key("a+b/c=d", "e f")
    for form in (
        secret,
        quote(secret, safe=""),
        quote_plus(secret),
        base64.b64encode(secret.encode()).decode(),
    ):
        said = masked(f"ConnectError: https://x/?key={form} refused", secret)
        assert form not in said and "***" in said
    assert masked("nothing here", "") == "nothing here"


# ---------------------------------------------------------------------------
# A source declared only as data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_invented_source_is_asked_and_its_record_reaches_the_report_and_the_renderer() -> (
    None
):
    credential = _key("own", "k")
    stored = {"domainrep": _invented(api_key=credential)}
    sources = [
        ReadySource(key=k, source=s, credential=s.api_key.get_secret_value())
        for k, s in effective_sources(stored).items()
    ]
    seen_at = int(time.time()) - 60
    answer = {"result": {"votes": {"bad": 4, "odd": 1, "good": 9, "none": 6}, "seen": seen_at}}
    wire = _Wire(answer)
    report = {"network": {"domains": [{"fqdn": "evil.com", "source": "sandbox"}], "ips": []}}
    async with wire.client() as http:
        await enrich_malware_report(report, sources=sources, http_client=http)

    (request,) = wire.requests  # the shipped sources hold no credential and are not asked
    assert str(request.url) == f"https://{INVENTED_HOST}/v1/domain/evil.com"
    assert request.headers["Authorization"] == f"Bearer {credential}"
    domain = report["network"]["domains"][0]
    rep = domain["reputation"]
    assert rep["source"] == "domainrep"
    assert (rep["malicious"], rep["suspicious"], rep["harmless"], rep["undetected"]) == (4, 1, 9, 6)
    assert rep["age_days"] >= 0 and "stale" not in rep
    assert domain["is_suspicious"] is True

    # The Markdown renderer reads the record as it reads VirusTotal's.
    from maljan.reporting.models import NetworkDomain
    from maljan.reporting.renderers.markdown import _reputations

    rendered = _reputations(
        SimpleNamespace(network=SimpleNamespace(domains=[NetworkDomain(**domain)], ips=[]))  # type: ignore[arg-type]
    )
    assert rendered["evil.com"].startswith("domainrep: 4 of 20 engines flag it as malicious")


@pytest.mark.asyncio
async def test_a_server_source_asks_the_tool_with_the_argument_its_declaration_names() -> None:
    stored = {
        "intel": {
            "label": "Intel server",
            "kinds": ["ip"],
            "server": "intelsrv",
            "tool": "lookup_address",
            "record": [{"name": "abuse_confidence", "path": "/score", "read": "count"}],
            "malicious_when": [{"field": "abuse_confidence", "at_least": 50}],
        }
    }
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def caller(server: str, tool: str, args: dict[str, Any]) -> str:
        calls.append((server, tool, args))
        return '{"score": 70}'

    sources = [ReadySource(key="intel", source=effective_sources(stored)["intel"])]
    report = {"network": {"domains": [], "ips": [{"address": "8.8.4.4", "source": "sandbox"}]}}
    async with _Wire({}).client() as http:
        with patch("maljan.enrichment.orchestrator.WhoisClient") as whois:
            whois.return_value.asn_lookup = _none
            whois.return_value.geoip = lambda _a: None
            await enrich_malware_report(
                report,
                sources=sources,
                http_client=http,
                tool_caller=caller,
                tool_arguments=lambda server, tool: {"ip": "ip_address"},
            )
    assert calls == [("intelsrv", "lookup_address", {"ip_address": "8.8.4.4"})]
    ip = report["network"]["ips"][0]
    assert ip["reputation"] == {"source": "intel", "abuse_confidence": 70}
    assert ip["is_suspicious"] is True


async def _none(_address: str) -> None:
    return None


def test_a_stored_entry_under_a_shipped_key_changes_only_what_it_names() -> None:
    sources = effective_sources({"virustotal": {"enabled": False}})
    assert sources["virustotal"].enabled is False
    assert sources["virustotal"].credential == "api.virustotal_api_key"


@pytest.mark.parametrize(
    ("entry", "says"),
    [
        (_invented(requests={"domain": {"url": f"http://{INVENTED_HOST}/{{value}}"}}), "https"),
        (
            _invented(requests={"domain": {"url": f"https://{INVENTED_HOST}/{{credential}}"}}),
            "credential",
        ),
        (_invented(kinds=["domain", "ip"]), "missing ip"),
        (_invented(server="x"), "not both"),
        (_invented(malicious_when=[{"field": "nope", "at_least": 1}]), "nope"),
        (_invented(record=[{"name": "source", "path": "/a"}]), "source"),
        (_invented(surprise=True), "surprise"),
        (_invented(kinds=["hash"]), "hash reputation is declared as a reputation lookup tool"),
        (_invented(kinds=["domain", "url"]), "asks only about domain and ip"),
        (_invented(kinds=["email"]), "an indicator kind is one of domain, ip"),
        (_invented(requests={}, server="Bad\nName", tool="t"), "server must be the key"),
        (_invented(arguments={"domain": "q"}), "a REST source takes none"),
        (
            _invented(requests={}, server="srv", tool="t", arguments={"ip": "addr"}),
            "arguments name kinds the source does not answer: ip",
        ),
    ],
)
def test_a_declaration_that_cannot_work_is_refused_in_words(
    entry: dict[str, Any], says: str
) -> None:
    errors = validate_sources({"domainrep": entry})
    assert "domainrep" in errors and says in errors["domainrep"]


def test_a_bad_key_is_refused() -> None:
    assert "Bad Key" in validate_sources({"Bad Key": _invented()})


def test_a_shipped_source_is_a_valid_declaration() -> None:
    assert validate_sources({}) == {}
    with pytest.raises(ValidationError):
        EnrichmentSource.model_validate({"kinds": [], "record": []})


def test_reading_an_answer_is_linear_in_its_size() -> None:
    source = EnrichmentSource.model_validate(
        _invented(
            record=[{"name": "labels", "path": "/**/label", "read": "texts", "limit": 5}],
            malicious_when=[],
            age_from="",
        )
    )

    def answer(n: int) -> dict[str, Any]:
        return {"result": {"rows": [{"label": "x" * 8, "more": [{"k": i}]} for i in range(n)]}}

    def timed(n: int) -> float:
        doc = answer(n)
        t0 = time.perf_counter()
        read_record("domainrep", source, doc)
        return time.perf_counter() - t0

    small, large = timed(2_000), timed(20_000)
    assert large < max(small, 0.001) * 40
