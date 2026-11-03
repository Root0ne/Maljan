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
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from maljan.reporting import detection_signatures as drafts
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.code_constants import code_constants_from_ledger, little_endian
from maljan.reporting.detection_signatures import (
    NO_STORED_GROUP_FEW_HASHES,
    NO_STORED_GROUP_NO_SEED,
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
    BoundValue,
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
        SampleString(identifier="$s0"),
        SampleString(identifier="$d0", offset=64),
        SampleString(identifier="$h0", offset=96),
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
            "Precision: its strings match the sample it was drafted from (0 of 1 published "
            "strings, 2 of 2 stored values found), not its hash alone; not run against any other "
            "file (no retro-hunt), so how often it fires elsewhere is not measured."
        )

    def test_a_rule_of_published_strings_alone_counts_them_alone(self) -> None:
        rule = _yara(
            matches_sample=True,
            matched_by=["strings"],
            sample_strings=[SampleString(identifier="$s0", offset=3)],
        )

        assert "(1 of 1 published strings found), not its hash alone" in precision_line(rule)

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

    def test_the_stored_values_the_draft_leaves_out_are_counted_on_its_line(self) -> None:
        report = _report(_yara(**HASH_ONLY))
        report.code_constants = _seeds(SEED) + _hashes(*_many(15))
        line = _rule_line(_analyst(report), "YARA")

        assert line.endswith(
            " 3 stored values the run read are left out of the draft; the report's JSON lists "
            "every one."
        )
        report.code_constants = _hashes(*HASHES)
        assert _rule_line(_analyst(report), "YARA").endswith(
            f" 3 stored values the run read are left out of the draft ({NO_STORED_GROUP_NO_SEED})"
            "; the report's JSON lists every one."
        )


ALGORITHM = "crc32_ascii"


def _decoder(*seeds: Any, entry: str = "ev_0021", **args: Any) -> LedgerEntry:
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


def _resolver(
    *values: str,
    names: tuple[str, ...] = ("InternetOpenW",),
    algorithms: tuple[str, ...] | None = None,
    entry: str = "ev_0020",
) -> LedgerEntry:
    hits = [
        {
            "value": value,
            "readings": [
                {"set": "exports", "name": name, "algorithm": algorithm}
                for name in names
                for algorithm in ([algorithms[n]] if algorithms else [ALGORITHM])
            ],
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
        constants = code_constants_from_ledger([_resolver(*HASHES), _decoder(SEED, SEED, SEED)])

        assert [(c.value, c.role) for c in constants] == [
            (SEED, "seed"),
            *((value, "hash") for value in HASHES),
        ]
        seed = constants[0]
        assert (seed.entry, seed.places, seed.first_offset) == ("ev_0021", 3, "0xce00")
        assert seed.meaning == (
            "the decoder seed stored in the header of 3 encoded strings, xor8_rolling_header"
        )
        assert constants[1].meaning == "a function-name hash (InternetOpenW)"

    def test_a_carved_file_a_failed_call_and_a_plain_value_are_not_read(self) -> None:
        failed = _decoder("0x5a17c0de", entry="ev_0030").model_copy(update={"ok": False})
        constants = code_constants_from_ledger(
            [
                _decoder("0x11223344", entry="ev_0031", carved_path="carved/0.bin"),
                failed,
                _decoder("0x00001234", "0x01000100", "0x0000ffff", entry="ev_0032"),
                _resolver(*HASHES[:2]),
            ]
        )

        assert [c.value for c in constants] == list(HASHES[:2])

    def test_a_hash_its_algorithm_resolves_alone_in_the_answer_is_not_read(self) -> None:
        # Asked about given values, the resolver lists no lone hits of its own:
        # a value is read only when one of its algorithms resolves another.
        alone = code_constants_from_ledger(
            [_resolver(*HASHES, algorithms=("crc32_ascii", "ror13", "djb2"))]
        )
        paired = code_constants_from_ledger(
            [_resolver(*HASHES, algorithms=("crc32_ascii", "ror13", "crc32_ascii"))]
        )

        assert alone == []
        assert [c.value for c in paired] == [HASHES[0], HASHES[2]]

    def test_a_value_is_read_as_an_int_as_hexadecimal_or_as_decimal(self) -> None:
        constants = code_constants_from_ledger(
            [_decoder(0x33629D40, entry="ev_0021"), _decoder("0x5a17c0de", entry="ev_0022")]
            + [_decoder(str(0x7B3D1E2F), entry="ev_0023"), _decoder("deadbeef", entry="ev_0024")]
        )

        assert [c.value for c in constants] == [SEED, "0x5a17c0de", "0x7b3d1e2f"]

    def test_the_declared_pointers_are_read_where_a_declaration_points_them(self) -> None:
        entry = LedgerEntry(
            id="ev_0040",
            agent="static",
            tool="unpack_strings",
            source="mcp:foreign",
            args={"path": "sample.exe"},
            facts={
                "v": 1,
                "kind": "decoded_strings",
                "rows": "/found/*",
                "values": {"text": "/plain", "seed": "/header/key"},
                "arguments": {"path": "path"},
            },
            structured={"found": [{"plain": "x", "header": {"key": "0x5a17c0de"}}]},
        )

        assert [c.value for c in code_constants_from_ledger([entry])] == ["0x5a17c0de"]

    def test_a_hostile_name_is_one_clean_capped_line(self) -> None:
        name = "Evil`|name\n**x**" + "A" * 200
        constant = code_constants_from_ledger([_resolver(*HASHES[:2], names=(name,))])[0]

        assert "\n" not in constant.meaning and "`" not in constant.meaning
        assert "|" not in constant.meaning and "*" not in constant.meaning
        assert len(constant.meaning) < 120

    def test_a_value_is_stored_little_endian(self) -> None:
        assert little_endian(SEED) == bytes.fromhex("409d6233")
        assert little_endian("not a number") is None


def _seeds(*values: str) -> list[CodeConstant]:
    return [CodeConstant(value=v, role="seed", meaning="m", entry="ev_0021") for v in values]


def _hashes(*values: str) -> list[CodeConstant]:
    return [CodeConstant(value=v, role="hash", meaning="h", entry="ev_0020") for v in values]


def _many(count: int) -> list[str]:
    return [f"{0x10203040 + n * 0x01010101:#010x}" for n in range(count)]


def _sample(tmp_path: Path, blob: bytes) -> OwnSample:
    path = tmp_path / "sample.bin"
    path.write_bytes(blob)
    return OwnSample(path=str(path), budget_seconds=BUDGET)


def _drafted_yara(report: MalwareReport, sample: OwnSample | None) -> DetectionRule:
    return next(rule for rule in build_detection_rules(report, sample) if rule.kind == "yara")


class TestTheDraftMatchesTheStoredValues:
    def test_the_seed_and_the_hashes_are_one_group_every_seed_with_the_hashes(self) -> None:
        report = _report()
        report.code_constants = _seeds(SEED) + _hashes(*HASHES)
        rule = _drafted_yara(report, None)

        assert "$d0 = { 40 9d 62 33 }  // 0x33629d40: m; ev_0021" in rule.body
        assert "$h2 = { 6b 08 7d 44 }  // 0x447d086b: h; ev_0020" in rule.body
        assert "or ((2 of ($s*)) or (all of ($d*) and all of ($h*)))\n" in rule.body
        assert "constant:0x33629d40:ev_0021" in rule.source_evidence

    @pytest.mark.parametrize(
        ("constants", "why"),
        [
            (_hashes(*HASHES), NO_STORED_GROUP_NO_SEED),
            (_seeds(SEED) + _hashes(HASHES[0]), NO_STORED_GROUP_FEW_HASHES),
        ],
        ids=["hashes-without-a-seed", "a-seed-with-one-hash"],
    )
    def test_without_a_seed_and_two_hashes_no_group_is_drafted_and_the_draft_says_so(
        self, constants: list[CodeConstant], why: str
    ) -> None:
        bare = _drafted_yara(_report(), None).body
        report = _report()
        report.code_constants = constants
        body = _drafted_yara(report, None).body

        assert "$d" not in body and "$h" not in body
        rest = len(constants)
        assert body == bare + (
            f"\n// {rest} stored values the run read are not in this draft ({why}); the "
            "report's JSON (code_constants) carries every one."
        )

    def test_values_past_the_draft_s_room_are_said_to_be_left_out(self) -> None:
        report = _report()
        report.code_constants = _seeds(SEED) + _hashes(*_many(15))
        body = _drafted_yara(report, None).body

        assert "$h11 = " in body and "$h12 = " not in body
        assert "(all of ($d*) and 6 of ($h*))" in body
        assert body.rstrip().endswith(
            "// 3 stored values the run read are not in this draft; the report's JSON "
            "(code_constants) carries every one."
        )

    @needs_engine
    def test_a_sample_keeping_its_indicators_encoded_matches_by_its_stored_values(
        self, tmp_path: Path
    ) -> None:
        # The published names are nowhere in the bytes; the seed and the hashes are.
        blob = b"\x90" * 32 + b"".join(little_endian(v) + b"\xcc" * 9 for v in (SEED, *HASHES))
        report = _report()
        report.identity.hashes.sha256 = hashlib.sha256(blob).hexdigest()
        report.code_constants = _seeds(SEED) + _hashes(*HASHES)
        report.detection_signatures = [_drafted_yara(report, _sample(tmp_path, blob))]
        (rule,) = report.detection_signatures

        assert rule.matched_by == ["sha256", "strings"]
        assert analyst_print_gate(rule) is None
        found = {s.identifier for s in rule.sample_strings or [] if s.offset is not None}
        assert found == {"$d0", "$h0", "$h1", "$h2"}
        analyst = _analyst(report)
        assert rule.body.rstrip() in analyst
        assert "(0 of 2 published strings, 4 of 4 stored values found)" in analyst

    @needs_engine
    def test_a_file_holding_the_hashes_without_the_seed_does_not_match(
        self, tmp_path: Path
    ) -> None:
        # Any program resolving the same functions by the same public algorithm
        # holds the hashes; without the seed they are no match by content.
        blob = b"\x90" * 32 + b"".join(little_endian(v) + b"\xcc" * 9 for v in HASHES)
        report = _report()
        report.identity.hashes.sha256 = hashlib.sha256(blob).hexdigest()
        report.code_constants = _seeds(SEED) + _hashes(*HASHES)
        rule = _drafted_yara(report, _sample(tmp_path, blob))

        assert rule.matched_by == ["sha256"]
        assert analyst_print_gate(rule) == NOT_PRINTED_HASH_ONLY.format(clauses="sha256")

    @needs_engine
    def test_the_probe_answers_as_the_draft_does_over_both_groups(self, tmp_path: Path) -> None:
        import yara

        rng = random.Random(11)
        names = ("gate9.example.org", "relay4.example.net", "Global\\MtxQ7")
        seeds = (SEED, "0x5a17c0de")
        hashes = (*HASHES, "0x8a749fa7", "0xe5191d24")
        path = tmp_path / "sample.bin"
        for trial in range(160):
            strings = [(f"$s{n}", v) for n, v in enumerate(rng.sample(names, rng.randint(0, 3)))]
            on_seeds = [
                (f"$d{n}", little_endian(v) or b"")
                for n, v in enumerate(rng.sample(seeds, rng.randint(1, 2)))
            ]
            on_hashes = [
                (f"$h{n}", little_endian(v) or b"")
                for n, v in enumerate(rng.sample(hashes, rng.randint(2, 5)))
            ]
            chunks = [rng.randbytes(rng.randint(0, 24))]
            for _slot, raw in [*on_seeds, *on_hashes]:
                if rng.random() < 0.75:
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
                seeds=on_seeds,
                hashes=on_hashes,
            )
            slots = [slot for slot, _v in [*strings, *on_seeds, *on_hashes]]
            check = drafts._run_on_sample(
                rendered, slots, OwnSample(path=str(path), budget_seconds=BUDGET)
            )
            whole = yara.compile(source=rendered.draft, includes=False).match(data=blob)
            assert check.matches is bool(whole), (trial, strings, blob)
            assert check.matched_by == (["strings"] if whole else []), trial


class TestABoundValueSaysWhereTheCodeLoadsIt:
    MUTEX = "runnung"
    CONTEXT = "argument 3 (lpName) of CreateMutexW at 0x3962"

    def _report(self) -> MalwareReport:
        report = _report(_yara(**HASH_ONLY))
        report.overall_confidence = 0.9
        report.bound_values = [
            BoundValue(
                value=self.MUTEX,
                kind="mutex",
                role="mutex_name",
                role_words="the name of the mutex the call creates or opens",
                api="CreateMutexW",
                argument=3,
                parameter="lpName",
                entry="ev_0021",
                tool="decode_string_blobs",
                offset="0xd800",
                site="0x3935",
                function="0x3868",
                decoder_call="0x3939",
                call_at="0x3962",
                slot="0x10c60",
                named_by="ev_0025",
                fall_through=True,
            )
        ]
        report.consolidated_iocs = build_consolidated_iocs(report)
        return report

    def test_its_cell_adds_only_what_its_context_does_not_say(self) -> None:
        analyst = _analyst(self._report())
        row = next(line for line in analyst.splitlines() if f"`{self.MUTEX}`" in line)
        cell = row.split(" | ")[2]

        assert re.fullmatch(
            re.escape(
                f"{self.CONTEXT}; decoded from the blob at file offset 0xd800, loaded at 0x3935 "
                "in the function at 0x3868 and given to the routine called at 0x3939, the call "
                "made through the slot 0x10c60"
            )
            + r"\[\[\d+\]\]\(evidence-bundle\.html#cite-\d+\) \|",
            cell,
        ), cell
        assert "the frame slot" not in row and "CreateMutexW as argument" not in row

    def test_a_row_bound_to_no_call_reads_as_before(self) -> None:
        analyst = _analyst(self._report())

        assert "| Domain | `gate9[.]example[.]org` | - |" in analyst.splitlines()


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

    def test_a_format_or_separator_character_is_dropped(self) -> None:
        quoted = drafts._hunt_quoted("/li‮ve‍/x y z")

        assert quoted == '"/live/xyz"'

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
