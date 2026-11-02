"""A drafted rule prints in the analyst report only where it matches its sample by content.

The analyst report printed a template YARA rule that matched its own sample by
its sha256 and import hash only, none of its five strings found: the strings
were the published indicators, which the sample keeps encoded. A rule like that
says nothing a hash lookup does not. What is held here:

* a file rule prints its body in the analyst report only where its strings
  clause held on the sample; one that matched by a hash alone, was not checked,
  or was stored before the check is named with the reason and printed in the
  evidence bundle, and every printed rule carries a Precision line;
* the values the sample stores as they are — a decoder's seed, a
  function-name hash — are read from the ledger by the answer's kind
  (``reporting.code_constants``) and drafted as a group of their own, which the
  engine finds in the sample's bytes where the published strings are encoded;
* one hunting query, built from the published user agents and URL paths, leaves
  the published hosts out;
* a run that drafted no rule renders byte for byte as before.
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from maljan.reporting import detection_signatures as drafts
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.code_constants import code_constants_from_ledger, little_endian
from maljan.reporting.detection_signatures import (
    NOT_PRINTED_HASH_ONLY,
    NOT_PRINTED_NOT_CHECKED,
    NOT_PRINTED_STORED_BEFORE,
    OwnSample,
    analyst_print_gate,
    build_detection_rules,
    hunting_query,
    precision_line,
)
from maljan.reporting.models import (
    CodeConstant,
    DetectionRule,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
    SampleString,
)
from maljan.reporting.renderers import MarkdownRenderer
from maljan.reporting.renderers.layout import ANALYST, BUNDLE, FULL
from maljan.schemas.evidence import LedgerEntry
from tests.unit.reporting._no_rule_reports import no_rule_reports
from tests.unit.reporting._report_inventory import stored_runs

needs_engine = pytest.mark.skipif(not drafts._YARA_AVAILABLE, reason="yara-python is not installed")

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "reporting" / "no_rules.json"
HOST = "gate9.example.org"
URL = f"https://{HOST}/live/"
AGENT = "Mozilla/4.0 (compatible; Tob 1.1)"
BODY = 'rule Maljan_AutoGen_loader { strings: $s0 = "gate9" condition: $s0 }'
BUDGET = 60
SEED = "0x33629d40"
HASHES = ("0x2ec21d6c", "0xc24fa5f4", "0x447d086b")


def _report(*rules: DetectionRule) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)),
        verdict="Malware",
        malware_category="loader",
        generated_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        network=NetworkIOCs(
            domains=[NetworkDomain(fqdn=HOST, source="sandbox")],
            urls=[NetworkURL(url=URL, method="POST", user_agent=AGENT, source="sandbox")],
        ),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    report.detection_signatures = list(rules)
    return report


def _yara(**check: Any) -> DetectionRule:
    return DetectionRule(kind="yara", name="Maljan_AutoGen_loader", body=BODY, **check)


def _analyst(report: MalwareReport) -> str:
    return MarkdownRenderer(layout=ANALYST).render(report)


def _rule_line(markdown: str, kind: str) -> str:
    return next(line for line in markdown.splitlines() if line.startswith(f"- **{kind}**"))


HASH_ONLY = {
    "matches_sample": True,
    "matched_by": ["sha256", "imphash"],
    "sample_strings": [SampleString(identifier="$s0")],
}
BY_CONTENT = {
    "matches_sample": True,
    "matched_by": ["strings"],
    "sample_strings": [
        SampleString(identifier="$s0", offset=16),
        SampleString(identifier="$c0", offset=64),
    ],
}


class TestOnlyAContentMatchPrintsItsBody:
    def test_a_rule_matching_by_its_hashes_only_is_named_with_the_reason(self) -> None:
        report = _report(_yara(**HASH_ONLY))
        analyst = _analyst(report)
        line = _rule_line(analyst, "YARA")

        assert BODY not in analyst
        assert line.endswith(
            "Not printed here: "
            + NOT_PRINTED_HASH_ONLY.format(clauses="sha256 and imphash")
            + "; its body is in the bundle."
        )
        assert "Precision:" not in line
        # Nothing is dropped: the bundle prints the body and the check.
        bundle = MarkdownRenderer(layout=BUNDLE).render(report)
        assert BODY in bundle
        assert "matches it by its sha256 and imphash only" in bundle

    def test_a_rule_whose_strings_match_prints_with_its_precision(self) -> None:
        analyst = _analyst(_report(_yara(**BY_CONTENT)))
        line = _rule_line(analyst, "YARA")

        assert BODY in analyst.split("## Appendix", 1)[1]
        assert line.endswith(
            "Precision: its strings match the sample it was drafted from (2 of 2 found), not "
            "its hash alone; not run against any other file (no retro-hunt), so how often it "
            "fires elsewhere is not measured."
        )

    @pytest.mark.parametrize(
        ("check", "reason"),
        [
            ({"sample_not_checked": "yara-python is not installed"}, NOT_PRINTED_NOT_CHECKED),
            ({}, NOT_PRINTED_STORED_BEFORE),
        ],
        ids=["not-checked", "stored-before-the-check"],
    )
    def test_a_rule_whose_content_match_is_not_shown_is_not_printed(
        self, check: dict[str, Any], reason: str
    ) -> None:
        analyst = _analyst(_report(_yara(**check)))

        assert BODY not in analyst
        assert f"Not printed here: {reason}; its body is in the bundle." in analyst

    def test_a_behaviour_and_a_traffic_rule_print_with_their_precision(self) -> None:
        sigma = DetectionRule(kind="sigma", name="Maljan_AutoGen_Sigma_loader", body="title: s")
        suricata = DetectionRule(kind="suricata", name="Maljan_AutoGen_Suricata_loader", body="#")
        analyst = _analyst(_report(sigma, suricata))

        assert analyst_print_gate(sigma) is None and analyst_print_gate(suricata) is None
        assert _rule_line(analyst, "SIGMA").endswith(precision_line(sigma))
        assert _rule_line(analyst, "SURICATA").endswith(precision_line(suricata))
        assert "not run against any other log" in precision_line(sigma)
        assert "not run against any other traffic" in precision_line(suricata)

    def test_the_single_file_report_still_prints_every_body(self) -> None:
        full = MarkdownRenderer(layout=FULL).render(_report(_yara(**HASH_ONLY)))

        assert BODY in full


def _decoder(*seeds: str, entry: str = "ev_0021", **args: Any) -> LedgerEntry:
    rows = [
        {
            "text": f"text {n}",
            "offset": hex(0xCE00 + 0x40 * n),
            "scheme": "xor8_rolling_header",
            "parameters": {"seed": seed, "first_key": "0x41"},
        }
        for n, seed in enumerate(seeds)
    ]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="decode_string_blobs",
        args={"path": "sample.exe", **args},
        structured={"tool": "decode_string_blobs", "results": rows},
    )


def _resolver(*values: str, names: tuple[str, ...] = (), entry: str = "ev_0020") -> LedgerEntry:
    hits = [
        {
            "value": value,
            "readings": [{"set": "exports", "name": name} for name in names] or [],
            "occurrences": [{"offset": hex(0x8400 + 0x20 * n), "section": ".text"}],
        }
        for n, value in enumerate(values)
    ]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="resolve_api_hashes",
        args={"path": "sample.exe"},
        structured={
            "tool": "resolve_api_hashes",
            "hits": hits,
            "lone_hits": [{"value": "0x7a5b3c1d", "occurrences": [{"offset": "0x10"}]}],
        },
    )


class TestTheStoredValuesAreReadByTheAnswersKind:
    def test_a_seed_is_read_once_with_its_count_then_each_hash(self) -> None:
        constants = code_constants_from_ledger(
            [_resolver(*HASHES, names=("InternetOpenW",)), _decoder(SEED, SEED, SEED)]
        )

        assert [c.value for c in constants] == [SEED, *HASHES]
        seed = constants[0]
        assert (seed.entry, seed.places, seed.first_offset) == ("ev_0021", 3, "0xce00")
        assert seed.meaning == (
            "the decoder seed stored in the header of 3 encoded strings, xor8_rolling_header"
        )
        assert constants[1].meaning == "a function-name hash (InternetOpenW)"

    def test_a_lone_hit_a_carved_file_a_failed_call_and_a_plain_value_are_not_read(
        self,
    ) -> None:
        failed = _decoder("0x5a17c0de", entry="ev_0030").model_copy(update={"ok": False})
        constants = code_constants_from_ledger(
            [
                _decoder("0x11223344", entry="ev_0031", carved_path="carved/0.bin"),
                failed,
                _decoder("0x00001234", "0x01000100", "0x0000ffff", entry="ev_0032"),
                _resolver("0x2ec21d6c"),
            ]
        )

        assert [c.value for c in constants] == ["0x2ec21d6c"]

    def test_a_hostile_name_is_one_clean_capped_line(self) -> None:
        name = "Evil`|name\n**x**" + "A" * 200
        (constant,) = code_constants_from_ledger([_resolver(HASHES[0], names=(name,))])

        assert "\n" not in constant.meaning and "`" not in constant.meaning
        assert "|" not in constant.meaning and "*" not in constant.meaning
        assert len(constant.meaning) < 120

    def test_a_value_is_stored_little_endian(self) -> None:
        assert little_endian(SEED) == bytes.fromhex("409d6233")
        assert little_endian("not a number") is None


def _constants(*values: str) -> list[CodeConstant]:
    return [CodeConstant(value=value, meaning="m", entry="ev_0021") for value in values]


def _sample(tmp_path: Path, blob: bytes) -> OwnSample:
    path = tmp_path / "sample.bin"
    path.write_bytes(blob)
    return OwnSample(path=str(path), budget_seconds=BUDGET)


def _drafted_yara(report: MalwareReport, sample: OwnSample | None) -> DetectionRule:
    return next(rule for rule in build_detection_rules(report, sample) if rule.kind == "yara")


class TestTheDraftMatchesTheStoredValues:
    def test_each_value_is_declared_as_its_bytes_in_a_group_of_its_own(self) -> None:
        report = _report()
        report.code_constants = _constants(SEED, *HASHES)
        rule = _drafted_yara(report, None)

        assert "$c0 = { 40 9d 62 33 }  // 0x33629d40: m; ev_0021" in rule.body
        assert "or ((2 of ($s*)) or (3 of ($c*)))\n" in rule.body
        assert "constant:0x33629d40:ev_0021" in rule.source_evidence

    def test_one_value_alone_makes_no_group_and_a_draft_without_any_reads_as_before(
        self,
    ) -> None:
        bare = _report()
        alone = _report()
        alone.code_constants = _constants(SEED)

        assert _drafted_yara(alone, None).body == _drafted_yara(bare, None).body
        assert "$c" not in _drafted_yara(bare, None).body

    def test_values_past_the_draft_s_room_are_said_to_be_left_out(self) -> None:
        report = _report()
        report.code_constants = _constants(
            *(f"{0x10203040 + n * 0x01010101:#010x}" for n in range(15))
        )
        body = _drafted_yara(report, None).body

        assert "$c11 = " in body and "$c12 = " not in body
        assert body.rstrip().endswith(
            "// 3 more stored values the run read are not in this draft; the report's JSON "
            "(code_constants) carries every one."
        )

    @needs_engine
    def test_a_sample_keeping_its_indicators_encoded_matches_by_its_stored_values(
        self, tmp_path: Path
    ) -> None:
        # The published names are nowhere in the bytes; the seed and the hashes are.
        values = (SEED, *HASHES)
        blob = b"\x90" * 32 + b"".join(little_endian(v) + b"\xcc" * 9 for v in values)
        report = _report()
        report.identity.hashes.sha256 = hashlib.sha256(blob).hexdigest()
        report.code_constants = _constants(*values)
        report.detection_signatures = [_drafted_yara(report, _sample(tmp_path, blob))]
        (rule,) = report.detection_signatures

        assert rule.matched_by == ["sha256", "strings"]
        assert analyst_print_gate(rule) is None
        found = {s.identifier for s in rule.sample_strings or [] if s.offset is not None}
        assert found == {"$c0", "$c1", "$c2", "$c3"}
        analyst = _analyst(report)
        assert rule.body.rstrip() in analyst
        assert "Precision: its strings match the sample it was drafted from (4 of " in analyst

    @needs_engine
    def test_the_probe_answers_as_the_draft_does_over_both_groups(self, tmp_path: Path) -> None:
        rng = random.Random(11)
        names = ("gate9.example.org", "relay4.example.net", "Global\\MtxQ7")
        values = (SEED, *HASHES, "0x8a749fa7")
        path = tmp_path / "sample.bin"
        for trial in range(120):
            strings = [(f"$s{n}", v) for n, v in enumerate(rng.sample(names, rng.randint(0, 3)))]
            stored = rng.sample(values, rng.randint(2, 5))
            raws = [(f"$c{n}", little_endian(v) or b"") for n, v in enumerate(stored)]
            chunks = [rng.randbytes(rng.randint(0, 24))]
            for _slot, raw in raws:
                if rng.random() < 0.6:
                    chunks.extend([raw, rng.randbytes(rng.randint(0, 8))])
            for _slot, text in strings:
                if rng.random() < 0.6:
                    chunks.append(text.encode())
            blob = b"".join(chunks)
            path.write_bytes(blob)
            rendered = drafts._render_yara(
                rule_name="Maljan_AutoGen_loader",
                sha256="c" * 64,
                imphash=None,
                strings=strings,
                family="loader",
                verdict="Malware",
                generated_at_iso="2000-01-01T00:00:00+00:00",
                constants=raws,
            )
            slots = [slot for slot, _v in strings] + [slot for slot, _r in raws]
            check = drafts._run_on_sample(
                rendered, slots, OwnSample(path=str(path), budget_seconds=BUDGET)
            )
            import yara

            whole = yara.compile(source=rendered.draft, includes=False).match(data=blob)
            assert check.matches is bool(whole), (trial, strings, stored, blob)
            assert check.matched_by == (["strings"] if whole else []), trial


class TestTheHuntingQuery:
    def test_it_asks_for_the_agent_and_the_path_on_any_other_host(self) -> None:
        report = _report(_yara(**HASH_ONLY))
        report.network.user_agents = [AGENT]
        report.consolidated_iocs = _published_agent(report)

        assert hunting_query(report) == [
            f'user_agent = "{AGENT}"',
            'and url_path = "/live/"',
            f'and not host = "{HOST}"',
        ]
        analyst = _analyst(report)
        section = analyst.split("### 8.3 Hunting guidance", 1)[1].split("## 9.", 1)[0]
        assert "Hunting query: the requests the sample's code sends" in section
        assert f'and not host = "{HOST}"' in section, "printed live, as the rule bodies are"

    def test_a_path_that_stands_in_any_site_s_traffic_is_not_asked(self) -> None:
        report = _report(_yara(**HASH_ONLY))
        report.network.urls = [NetworkURL(url=f"https://{HOST}/a/", source="sandbox")]
        report.consolidated_iocs = build_consolidated_iocs(report)

        assert hunting_query(report) is None
        assert "Hunting query" not in _analyst(report)

    def test_a_hostile_value_stays_one_quoted_line(self) -> None:
        report = _report(_yara(**HASH_ONLY))
        report.network.urls = [
            NetworkURL(url=f'https://{HOST}/li"ve\\x/', source="sandbox"),
        ]
        report.consolidated_iocs = build_consolidated_iocs(report)
        query = hunting_query(report) or []

        assert any(line.startswith("url_path = ") for line in query)
        assert all("\n" not in line for line in query)
        assert '\\"' in query[0] and "\\\\" in query[0]

    def test_a_run_that_drafted_no_rule_asks_nothing(self) -> None:
        assert hunting_query(_report()) is None


def _published_agent(report: MalwareReport) -> list[Any]:
    """The IOC table with the user agent published, as a code-bound agent is."""
    rows = build_consolidated_iocs(report)
    for row in rows:
        if row.kind == "user_agent":
            row.published = "yes: the code passes it to InternetOpenW as argument 1"
    return rows


class TestARunThatDraftedNoRuleReadsAsBefore:
    @pytest.mark.parametrize("name", sorted(no_rule_reports()))
    @pytest.mark.parametrize("layout", [ANALYST, FULL])
    def test_byte_for_byte(self, name: str, layout: str) -> None:
        report = no_rule_reports()[name]

        assert (
            MarkdownRenderer(layout=layout).render(report)
            == json.loads(GOLDEN.read_text())[f"{name}.{layout}"]
        )


def _stored(run: str) -> Path:
    base = stored_runs()
    if base is None or not (base / run / "report.json").is_file():
        pytest.skip(f"the stored run {run} is not on this machine")
    return base / run


@pytest.mark.parametrize("run", ["haiku7", "haiku8"])
def test_a_stored_run_s_hash_only_draft_is_named_and_its_facts_stay(run: str) -> None:
    """Over the stored runs: the draft that matched 0 of 5 strings is not printed, and the
    mutex's binding chain its comment carried is in the indicator table instead."""
    directory = _stored(run)
    report = MalwareReport.model_validate(json.loads((directory / "report.json").read_text()))
    analyst = _analyst(report)
    (yara,) = [rule for rule in report.detection_signatures if rule.kind == "yara"]

    assert yara.body.rstrip() not in analyst
    assert (
        "Not printed here: it matches the sample by its sha256 and imphash only, not by its "
        "content; its body is in the bundle." in analyst
    )
    table = analyst.split("### 8.1", 1)[1].split("### 8.2", 1)[0]
    assert "loaded at 0x3935 in the function at 0x3868" in table
    query = analyst.split("Hunting query: ", 1)[1].split("## 9.", 1)[0]
    assert 'url_path = "/live/"' in query
    assert 'and not host in ("skinnyjeanso.com", "titnovacrion.top")' in query


def test_the_stored_ledger_s_seed_and_hashes_are_read() -> None:
    directory = _stored("haiku8")
    items = json.loads((directory / "evidence.json").read_text())["items"]
    ledger = [LedgerEntry.model_validate({**item, "id": item["entry_id"]}) for item in items]
    constants = code_constants_from_ledger(ledger)

    assert constants[0].value == SEED
    assert constants[0].entry == "ev_0021"
    assert {c.value for c in constants} >= {"0x2ec21d6c", "0xc24fa5f4"}
