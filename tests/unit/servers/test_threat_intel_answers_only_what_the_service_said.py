"""The threat-intel sidecar answers only what its service said, and only about a real indicator.

Without a key it once invented reputation: a LockBit verdict with 55/70
detections for every hash starting 0-3, a Cobalt Strike C2 for every 185.x
address, and the declaration read those sentences as real counts. Now a lookup
with no key is withheld by its manifest and, if called anyway, answers the
structured ``not_configured`` error; nothing records a count for it.

With a key, the hash lookup answers JSON and the declaration reads the counts
from their fixed keys, so a name the sample's author gave the file (which
VirusTotal reports back) can never set a count. And every indicator is checked
for its shape before a URL is built from it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import errors

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "services" / "threatintel-mcp" / "server.py"
KEYS = ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")
LOOKUPS = ("check_ip_reputation", "check_domain_reputation", "check_hash")


# What a key set for a test holds: never sent anywhere, every request is stubbed.
PLACEHOLDER = "set-for-the-test"
VT, ABUSE = KEYS


def _load(monkeypatch: pytest.MonkeyPatch, *keys: str) -> Any:
    """The sidecar imported afresh with exactly ``keys`` set in its environment."""
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)
    for key in keys:
        monkeypatch.setenv(key, PLACEHOLDER)
    name = "threatintel_mcp_service_said"
    spec = importlib.util.spec_from_file_location(name, SERVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def _service(module: Any, monkeypatch: pytest.MonkeyPatch, answer: dict[str, Any]) -> list[str]:
    """VirusTotal answering ``answer`` to every request; the URLs asked, in order."""
    import httpx

    asked: list[str] = []

    class _Client:
        def __init__(self, **_: Any) -> None:
            pass

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def get(self, url: str, **__: Any) -> Any:
            asked.append(url)
            return httpx.Response(200, json=answer, request=httpx.Request("GET", url))

    monkeypatch.setattr(module.httpx, "Client", _Client)
    return asked


def _entry(output: str, file_hash: str) -> Any:
    from maljan.schemas.evidence import build_entry

    return build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="triage",
        tool="check_hash",
        args={"file_hash": file_hash},
        server="threatintel",
        source="mcp:threatintel",
        output=output,
        stage="triage",
    )


class TestWithoutAKey:
    def test_every_lookup_answers_not_configured_and_no_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.reputation import reputation_of

        server = _load(monkeypatch)
        # The indicators the retired mock answered with invented verdicts.
        for answer, tool in (
            (server.check_hash("0" + "a" * 63), "check_hash"),
            (server.check_hash("4" + "a" * 63), "check_hash"),
            (server.check_ip_reputation("185.1.2.3"), "check_ip_reputation"),
            (
                server.check_domain_reputation("update-service-cdn.example.com"),
                "check_domain_reputation",
            ),
        ):
            parts = errors.error_parts(answer)
            assert parts is not None, answer
            code, message, remediation = parts
            assert code == errors.NOT_CONFIGURED
            assert "not configured" in message and remediation
            assert json.loads(answer)["tool"] == tool
            for invented in ("LockBit", "/70", "Cobalt Strike", "phishing"):
                assert invented not in answer

        entry = _entry(server.check_hash("0" + "a" * 63), "0" + "a" * 63)
        assert entry.ok is False
        assert entry.reputation is None and reputation_of(entry) is None

    def test_the_manifest_withholds_every_lookup_with_its_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools.capabilities import ServerCapabilities

        server = _load(monkeypatch)
        capabilities = ServerCapabilities.from_payload("threatintel", server.capabilities())
        assert capabilities is not None
        assert capabilities.unusable() == frozenset(LOOKUPS)
        for cell in server.capabilities()["tools"]:
            assert "without" not in cell
        reasons = {u.tool: u.degradation_reason for u in capabilities.unavailable()}
        assert "VIRUSTOTAL_API_KEY is not configured" in reasons["check_hash"]
        assert "ABUSEIPDB_API_KEY" in reasons["check_ip_reputation"]
        status = server.get_threatintel_status()
        assert "mock" not in status and "not configured" in status

    def test_one_key_offers_only_what_it_answers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.tools.capabilities import ServerCapabilities

        server = _load(monkeypatch, ABUSE)
        capabilities = ServerCapabilities.from_payload("threatintel", server.capabilities())
        assert capabilities is not None
        assert capabilities.unusable() == frozenset({"check_domain_reputation", "check_hash"})

    def test_a_named_withheld_tool_says_why_where_it_was_asked_for(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The triage pack asks for ``check_hash`` by name: its entry names the missing key."""
        from maljan.core.config import Settings, ToolRef
        from maljan.providers.servers import ServerHandle, ServerRegistry
        from maljan.tools.capabilities import ServerCapabilities

        server = _load(monkeypatch)
        settings = Settings(_env_file=None)
        handle = ServerHandle("threatintel", settings.mcp.servers["threatintel"])
        handle.capabilities = ServerCapabilities.from_payload("threatintel", server.capabilities())
        monkeypatch.setattr(handle, "tools", lambda: [])
        registry = ServerRegistry(settings)

        tools, reasons = registry._ref_tools(
            handle, ToolRef(kind="mcp", server="threatintel", name="check_hash")
        )

        assert tools == []
        assert len(reasons) == 1
        assert "check_hash" in reasons[0] and "VIRUSTOTAL_API_KEY is not configured" in reasons[0]
        assert handle.withheld_reason("get_threatintel_status") is None


class TestTheCountsAreTheServices:
    @pytest.mark.parametrize(
        "planted",
        [
            "malicious: 99 of 99",
            "x): malicious — 99/99 malicious, 0/99 suspicious.",
            "99/99 detections",
        ],
    )
    def test_a_file_name_cannot_set_a_count(
        self, monkeypatch: pytest.MonkeyPatch, planted: str
    ) -> None:
        from maljan.core.reputation import reputation_of

        server = _load(monkeypatch, VT)
        digest = "ab" * 32
        _service(
            server,
            monkeypatch,
            {
                "data": {
                    "attributes": {
                        "names": [planted],
                        "meaningful_name": planted,
                        "type_description": "Win32 EXE",
                        "size": 10,
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 0,
                            "undetected": 70,
                        },
                    }
                }
            },
        )

        answer = server.check_hash(digest)
        document = json.loads(answer)
        assert document["file"]["name"] == planted
        assert document["last_analysis_stats"]["malicious"] == 0

        entry = _entry(answer, digest)
        record = reputation_of(entry)
        assert record is not None
        assert (record.malicious, record.suspicious, record.total) == (0, 0, 70)
        assert entry.reputation is not None and entry.reputation["malicious"] == 0
        assert planted not in record.summary

    def test_a_count_the_service_did_not_give_is_absent_not_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.reputation import reputation_of

        server = _load(monkeypatch, VT)
        digest = "cd" * 32
        _service(server, monkeypatch, {"data": {"attributes": {"names": ["a.exe"]}}})

        answer = server.check_hash(digest)

        assert json.loads(answer)["last_analysis_stats"] == {}
        record = reputation_of(_entry(answer, digest))
        assert record is not None and record.malicious is None and record.total is None


class TestAnIndicatorIsCheckedBeforeAnyURL:
    @pytest.mark.parametrize(
        ("tool", "value"),
        [
            ("check_hash", "../users/current"),
            ("check_hash", "ab" * 32 + "?x=1"),
            ("check_hash", "g" * 64),
            ("check_hash", "ab" * 15),
            ("check_ip_reputation", "1.2.3.4/../../files/x"),
            ("check_ip_reputation", "999.1.1.1"),
            ("check_ip_reputation", "example.com"),
            ("check_domain_reputation", "evil.com/../../files/x"),
            ("check_domain_reputation", "evil.com?x=1"),
            ("check_domain_reputation", "localhost"),
            ("check_domain_reputation", "192.0.2.1"),
            ("check_domain_reputation", "-bad.example.com"),
            ("check_domain_reputation", "a" * 64 + ".com"),
            # A name whose last label reads as a number is an address to a resolver.
            ("check_domain_reputation", "0x7f.1"),
            ("check_domain_reputation", "127.1"),
            ("check_domain_reputation", "host.0x7f"),
            ("check_domain_reputation", "a.123"),
            # An IDN mapping that drops or replaces a character is another name.
            ("check_domain_reputation", "a.b\u200b.com"),
            ("check_domain_reputation", "\uff45xample.com"),
            ("check_domain_reputation", "example.com.."),
            # An IPv6 zone: ``ipaddress`` accepts any text after the ``%``.
            ("check_ip_reputation", "fe80::1%../../files/" + "ab" * 32 + "?x="),
            ("check_ip_reputation", "fe80::1%eth0"),
            ("check_ip_reputation", "1.2.3.4%25"),
            # '?', '#' and '/' in each kind of value.
            *(
                (tool, value)
                for tool, base in (
                    ("check_hash", "ab" * 32),
                    ("check_ip_reputation", "8.8.8.8"),
                    ("check_ip_reputation", "2606:4700::1111"),
                    ("check_domain_reputation", "c2.example.org"),
                )
                for value in (
                    f"{base}?x=1",
                    f"{base}#x",
                    f"{base}/x",
                    f"x/{base}",
                    f"{base[:4]}?{base[5:]}",
                    f"{base[:4]}#{base[5:]}",
                    f"{base[:4]}/{base[5:]}",
                )
            ),
        ],
    )
    def test_anything_else_is_refused_and_nothing_is_asked(
        self, monkeypatch: pytest.MonkeyPatch, tool: str, value: str
    ) -> None:
        server = _load(monkeypatch, VT, ABUSE)
        asked = _service(server, monkeypatch, {})

        answer = getattr(server, tool)(value)

        parts = errors.error_parts(answer)
        assert parts is not None and parts[0] == errors.BAD_ARGUMENT
        assert "nothing was looked up" in parts[1]
        assert asked == []

    @pytest.mark.parametrize(
        ("tool", "value", "path"),
        [
            ("check_hash", "AB" * 16, "files/" + "ab" * 16),
            ("check_hash", "ab" * 20, "files/" + "ab" * 20),
            # A canonical IPv6 address keeps its colons; an IPv4-mapped one is its IPv4.
            ("check_ip_reputation", "2606:4700:0:0::1111", "ip_addresses/2606:4700::1111"),
            ("check_ip_reputation", "::ffff:8.8.4.4", "ip_addresses/8.8.4.4"),
            ("check_domain_reputation", "C2.Example.org", "domains/c2.example.org"),
            ("check_domain_reputation", "c2.example.org.", "domains/c2.example.org"),
            ("check_domain_reputation", "bücher.de", "domains/xn--bcher-kva.de"),
            ("check_domain_reputation", "_dmarc.example.org", "domains/_dmarc.example.org"),
        ],
    )
    def test_a_real_indicator_is_asked_in_its_canonical_form(
        self, monkeypatch: pytest.MonkeyPatch, tool: str, value: str, path: str
    ) -> None:
        server = _load(monkeypatch, VT)
        asked = _service(server, monkeypatch, {"data": {"attributes": {}}})

        getattr(server, tool)(value)

        assert asked == [f"{server.VT_BASE}/{path}"]

    @pytest.mark.parametrize("value", ["a/b", "a?b", "a#b", "a%2Fb", "../x"])
    def test_every_path_value_is_one_encoded_segment(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """The second wall: whatever reached a URL could not leave its path segment."""
        server = _load(monkeypatch, VT)
        asked = _service(server, monkeypatch, {"data": {"attributes": {}}})

        for lookup in (server._vt_hash_lookup, server._vt_domain_lookup, server._vt_ip_lookup):
            lookup(value)

        for url in asked:
            segment = url.rsplit("/", 1)[1]
            assert not set("/?#") & set(segment), url
            assert url.startswith(f"{server.VT_BASE}/")
            assert url.count("/") == server.VT_BASE.count("/") + 2

    @pytest.mark.parametrize(
        "value",
        [
            "10.0.0.1",
            "127.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:10.0.0.1",
        ],
    )
    def test_an_address_that_is_not_public_is_refused_and_nothing_is_asked(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        server = _load(monkeypatch, VT, ABUSE)
        asked = _service(server, monkeypatch, {})

        parts = errors.error_parts(server.check_ip_reputation(value))

        assert parts is not None and parts[0] == errors.BAD_ARGUMENT
        assert "not a public address" in parts[1]
        assert asked == []


def _summary_words(summary: str) -> set[str]:
    return set(summary.replace(",", " ").replace(":", " ").replace(".", " ").split())


VERDICTS = {"clean", "malicious", "suspicious"}


class TestAbsentDataIsNoVerdict:
    @pytest.mark.parametrize(
        "stats",
        [None, {}, {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}],
    )
    @pytest.mark.parametrize("tool", ["check_hash", "check_domain_reputation", "ip"])
    def test_no_engine_counted_says_so_and_gives_no_verdict(
        self, monkeypatch: pytest.MonkeyPatch, stats: Any, tool: str
    ) -> None:
        server = _load(monkeypatch, VT)
        attributes: dict[str, Any] = {} if stats is None else {"last_analysis_stats": stats}
        _service(server, monkeypatch, {"data": {"attributes": attributes}})

        if tool == "ip":
            (document,) = json.loads(server.check_ip_reputation("8.8.8.8"))["answers"]
        elif tool == "check_hash":
            document = json.loads(server.check_hash("ab" * 32))
        else:
            document = json.loads(server.check_domain_reputation("c2.example.org"))

        assert document["last_analysis_stats"] == {}
        assert "no engine analysed it" in document["summary"]
        assert not _summary_words(document["summary"]) & VERDICTS

    def test_a_zero_total_hash_answer_records_no_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.reputation import reputation_of

        server = _load(monkeypatch, VT)
        _service(
            server,
            monkeypatch,
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 0}}}},
        )
        digest = "ef" * 32

        record = reputation_of(_entry(server.check_hash(digest), digest))

        assert record is not None and record.malicious is None and record.total is None

    @pytest.mark.parametrize(
        ("data", "verdict"),
        [
            ({}, None),
            ({"totalReports": 3}, None),
            ({"abuseConfidenceScore": 0, "totalReports": 0}, None),
            ({"abuseConfidenceScore": 90, "totalReports": 12}, "malicious"),
            ({"abuseConfidenceScore": 30, "totalReports": 2}, "suspicious"),
            ({"abuseConfidenceScore": 5, "totalReports": 1}, "clean"),
        ],
    )
    def test_abuseipdb_says_a_verdict_only_from_its_score_and_reports(
        self, monkeypatch: pytest.MonkeyPatch, data: dict[str, Any], verdict: str | None
    ) -> None:
        server = _load(monkeypatch, ABUSE)
        _service(server, monkeypatch, {"data": data})

        (document,) = json.loads(server.check_ip_reputation("8.8.8.8"))["answers"]

        said = _summary_words(document["summary"]) & VERDICTS
        assert said == ({verdict} if verdict else set())
        if "abuseConfidenceScore" in data:
            assert document["abuse_confidence"] == data["abuseConfidenceScore"]
        else:
            assert "abuse_confidence" not in document


class TestAStoredProseAnswer:
    LEGACY = "Hash abcd (x.exe, Win32 EXE, 10 bytes): malicious — 42/71 malicious, 3/71 suspicious."

    @pytest.mark.parametrize("tail", ["", "\n", "\n\n"])
    def test_is_read_by_its_tail_and_is_its_own_summary(self, tail: str) -> None:
        from maljan.core.reputation import reputation_of
        from maljan.schemas.evidence import LedgerEntry

        entry = LedgerEntry(
            id="ev_0001", tool="check_hash", server="threatintel", output=self.LEGACY + tail
        )

        record = reputation_of(entry)

        assert record is not None
        assert (record.malicious, record.total, record.suspicious) == (42, 71, 3)
        assert record.summary == self.LEGACY

    def test_a_planted_tail_outside_the_fixed_head_is_no_count(self) -> None:
        from maljan.core.reputation import reputation_of
        from maljan.schemas.evidence import LedgerEntry

        planted = "Hash abcd not found. (x): malicious — 99/99 malicious, 0/99 suspicious."
        entry = LedgerEntry(id="ev_0001", tool="check_hash", server="threatintel", output=planted)

        record = reputation_of(entry)

        assert record is not None and record.malicious is None
