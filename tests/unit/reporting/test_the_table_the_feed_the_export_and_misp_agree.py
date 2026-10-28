"""The IOC table, ``/iocs``, the STIX export and the MISP attributes read one decision.

The feed was built from the network block, the judge's values and the
analysts' rows, and was a subset of the table: a dropped file's digest, a
spawned command line and every path, key, mutex and service row the table
held had no row in it, and those rows carried no publish answer at all, so the
feed, the table and the export could not agree on them. The export named the
sample by its SHA-256 alone while the table and the feed published its MD5 and
SHA-1 as the sample's own. And no build step wrote the report's MISP
attributes, so the console's MISP export was always empty.

Now every row is asked the one publish rule under the source that recorded
it — a sandbox's file, digest, key or mutex only as an indicator the judge
names, and then on its record naming a process of the sample's tree or on the
judge's answer to the question that told it the record names none — the feed
is the table's rows, the export
carries every observed host row the table publishes and every identity digest
of the sample, and the MISP attributes are the table's published rows and the
published techniques.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import pytest
from stix2validator import ValidationOptions, validate_instance

from app.services.report_service import (
    OLD_RULE_STIX_NOTE,
    ReportService,
    ioc_feed_rows,
    with_current_iocs,
)
from maljan.memory.attck_loader import technique_entry
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.misp import build_misp_attributes
from maljan.reporting.models import (
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    PersistenceMechanism,
    ProcessNode,
    RegistryMod,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
    TTPMapping,
)
from maljan.reporting.renderers import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import (
    PLATFORM_INDICATES_EDGE,
    ExtendedSTIXRenderer,
    pattern_values,
    publishes,
)
from maljan.schemas.stix_models import Bundle

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"
SHA1 = "e456eb06758c7349a3636c15c91e1a9c30bb7927"
MD5 = "71d29d71641017e51b3685ce2f417796"
IMPHASH = "db7aeb75528663639689f852fd366243"
SSDEEP = "3072:Zk1aBcD+eF/gH:Zk1aBcDeFgH"
TLSH = "T1" + "A" * 70
DROPPED = "d4e60617c2afab8263febabe7f14f18595715078d71307a8cefe0707dae76dee"
DROPPED_SHA1 = "b" * 40
STRAY = "e" * 64
CARVED = "7c21835f01895c1ee4e12f81e71ef06a0f6e2b9281de493ff8ec95f913e9680d"
WRITTEN = "C:\\Users\\Public\\updater.exe"
OUTSIDE = "C:\\Windows\\Temp\\other.dat"
RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
PERSIST_KEY = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
MUTEX = "Global\\ExampleMutex"
COMMAND = "cmd.exe /c whoami"
SERVICE = "ExampleUpdater"
TASK = "ExampleTask"
SECRET = "example-secret-value"
C2 = "185.220.101.5"
SWEPT = "crl.example-authority.org"
OWNER = "0f1e2d3c-4b5a-4968-8776-655443332211"


def _report(**over: Any) -> MalwareReport:
    fields: dict[str, Any] = {
        "identity": SampleIdentity(
            hashes=FileHashes(sha256=SHA256, sha1=SHA1, md5=MD5, imphash=IMPHASH),
            file_name="sample.exe",
        ),
        # A host row the sandbox recorded is published only as an indicator
        # the judge names: these are the judge's.
        "judge_indicators": [
            JudgeIndicator(kind="hash", value=DROPPED, algorithm="SHA-256"),
            JudgeIndicator(kind="path", value=WRITTEN),
            JudgeIndicator(kind="hash", value=DROPPED_SHA1, algorithm="SHA-1"),
            JudgeIndicator(kind="mutex", value=MUTEX),
        ],
        "verdict": "Malware",
        "malware_category": "loader",
        "static": StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="domain", value=SWEPT),
                StringIOC(kind="secret", value=SECRET),
            ],
            embedded_resources=[{"id": "RCDATA/101", "carved": True, "sha256": CARVED}],
        ),
        "dynamic": DynamicBehavior(
            process_tree=[
                ProcessNode(
                    pid=100,
                    name="sample.exe",
                    children=[ProcessNode(pid=200, name="cmd.exe", command_line=COMMAND)],
                )
            ],
            file_operations=[
                # Written by a process of the sample's tree, named by pid.
                {"operation": "write", "path": WRITTEN, "sha256": DROPPED, "pid": 200},
                # A digest of SHA-1's length the record calls a SHA-256.
                {"operation": "write", "name": "b.bin", "sha256": DROPPED_SHA1, "pid": 100},
                # Named by no process at all.
                {"operation": "write", "name": "stray.bin", "sha256": STRAY},
                # Named by a process outside the tree.
                {"operation": "write", "path": OUTSIDE, "process": "explorer.exe"},
                {"operation": "mutex", "name": MUTEX, "process": "sample.exe"},
            ],
            registry_mods=[
                RegistryMod(hive="HKCU", key=RUN_KEY, value_name="Updater", operation="modify"),
                RegistryMod(hive="HKCU", key=RUN_KEY, value_name="Helper", operation="create"),
            ],
        ),
        "persistence": [
            PersistenceMechanism(kind="registry_run", target=PERSIST_KEY),
            PersistenceMechanism(kind="service", target=SERVICE),
            PersistenceMechanism(kind="scheduled_task", target=TASK),
        ],
        "network": NetworkIOCs(
            ips=[NetworkIP(address=C2, source="sandbox", sample_process_tree=True)],
            domains=[NetworkDomain(fqdn=SWEPT, source="strings")],
        ),
        "ttp_mappings": [
            TTPMapping(technique_id="T1547.001", technique_name="Run keys"),
            TTPMapping(technique_id="T1059.003", technique_name="Windows Command Shell"),
            TTPMapping(technique_id="T9999", technique_name=""),
        ],
    }
    fields.update(over)
    return MalwareReport(**fields)


def _rows(report: MalwareReport) -> dict[str, Any]:
    return {row.value: row for row in build_consolidated_iocs(report)}


def _bare(value: str) -> str:
    """A feed value without the algorithm a digest is written after."""
    head, sep, tail = value.partition(":")
    return tail if sep and head in {"md5", "sha1", "sha256", "imphash"} else value


UNSAID = "no: the sandbox report does not say which process {did} it"
OUTSIDE_THE_TREE = (
    "no: the sandbox report attributes it to a process outside the sample's process tree"
)
KEPT_FROM_THE_TREE = (
    "yes: kept as an indicator by the judge's indicator; the sandbox recorded it from the "
    "sample's process tree"
)
NOT_NAMED = (
    "no: the sandbox recorded it, and a file, digest, key or mutex the sandbox recorded is "
    "published only as an indicator the judge names"
)


class TestEveryRowHasAPublishAnswer:
    def test_no_row_is_left_unanswered(self) -> None:
        rows = build_consolidated_iocs(_report())

        assert rows
        assert all(str(row.published).startswith(("yes", "no:")) for row in rows), [
            (row.type, row.value, row.published) for row in rows if not row.published
        ]

    @pytest.mark.parametrize(
        ("value", "answer"),
        [
            (DROPPED, KEPT_FROM_THE_TREE),
            (WRITTEN, KEPT_FROM_THE_TREE),
            (MUTEX, KEPT_FROM_THE_TREE),
            (STRAY, UNSAID.format(did="wrote")),
            (OUTSIDE, OUTSIDE_THE_TREE),
            (RUN_KEY, UNSAID.format(did="wrote")),
            (CARVED, "yes: a file a static tool carved out of the sample"),
            (PERSIST_KEY, "yes: a persistence mechanism this run recorded"),
            (COMMAND, "no: a command line is not an indicator this run publishes"),
            (SERVICE, "no: the export has no object for this kind"),
            (TASK, "no: the export has no object for this kind"),
            (MD5, "yes: the sample's own digest"),
        ],
    )
    def test_each_row_kind_is_answered_by_the_source_that_recorded_it(
        self, value: str, answer: str
    ) -> None:
        assert _rows(_report())[value].published == answer

    def test_a_record_s_pid_decides_over_an_image_name_the_tree_also_runs(self) -> None:
        # pid 999 is no process of the tree; cmd.exe is one of its images.
        report = _report(
            dynamic=DynamicBehavior(
                process_tree=[
                    ProcessNode(
                        pid=100, name="sample.exe", children=[ProcessNode(pid=200, name="cmd.exe")]
                    )
                ],
                file_operations=[
                    {"operation": "write", "path": OUTSIDE, "pid": 999, "process": "cmd.exe"},
                    {"operation": "mutex", "name": MUTEX, "process": "cmd.exe"},
                ],
            )
        )

        rows = _rows(report)

        assert rows[OUTSIDE].published == OUTSIDE_THE_TREE
        # With no pid, the image name decides.
        assert rows[MUTEX].published == KEPT_FROM_THE_TREE

    def test_a_row_of_the_sample_s_tree_the_judge_did_not_name_is_withheld(self) -> None:
        # The guest writes temporary files, zone keys and mutexes under the
        # sample's own processes too: the record alone marks nothing.
        report = _report(judge_indicators=[])

        rows = _rows(report)
        feed = {_bare(row["value"]): row for row in ioc_feed_rows(report.model_dump(mode="json"))}
        exported = json.dumps(_export(report))

        for value in (DROPPED, DROPPED_SHA1, WRITTEN, MUTEX):
            assert rows[value].published == NOT_NAMED, value
            assert not publishes(feed[value]["publish_answer"]), value
            assert value.replace("\\", "\\\\") not in exported, value

    def test_a_judge_keep_is_no_second_source_for_an_unattributed_row(self) -> None:
        from maljan.reporting.models import JudgeIndicator

        report = _report(
            judge_indicators=[JudgeIndicator(kind="hash", value=STRAY, algorithm="SHA-256")]
        )

        answer = _rows(report)[STRAY].published

        # The judge was never asked with the sandbox's fact: its keep publishes
        # nothing, and the row's own sandbox record corroborates nothing.
        assert answer == (
            "no: the sandbox report does not say which process wrote it; the judge's indicator "
            "names it, and no question with this fact is recorded for this run, so its keep "
            "publishes nothing"
        )
        assert STRAY not in json.dumps(_export(report))

    def test_a_judge_keep_against_the_sandbox_s_fact_publishes_it_naming_both(self) -> None:
        from maljan.pipeline.validation import UNATTRIBUTED_INDICATOR_CODE
        from maljan.reporting.models import JudgeIndicator

        asked = {
            "code": UNATTRIBUTED_INDICATOR_CODE,
            "subject": f"hash:{STRAY}",
            "answered": "true",
        }
        report = _report(
            judge_indicators=[JudgeIndicator(kind="hash", value=STRAY, algorithm="SHA-256")],
            run_summary={"validation": {"unresolved": [asked]}},
        )

        assert _rows(report)[STRAY].published == (
            "yes: kept as an indicator by the judge when asked with the sandbox's fact; the "
            "sandbox report does not say which process wrote it"
        )
        assert STRAY in json.dumps(_export(report))

    def test_a_judge_hash_for_a_stored_run_s_unattributed_dropped_file_stays_withheld(
        self,
    ) -> None:
        from maljan.reporting.models import JudgeIndicator
        from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import (
            _benchmark,
        )

        root = _benchmark()
        if root is None or not (root / "haiku4" / "report.json").is_file():
            pytest.skip("the stored benchmark runs are not on this machine")
        dropped = "7c21835f01895c1ee4e12f81e71ef06a0f6e2b9281de493ff8ec95f913e9680d"
        report = MalwareReport.model_validate(
            json.loads((root / "haiku4" / "report.json").read_text())
        )
        report.judge_indicators = [
            *report.judge_indicators,
            JudgeIndicator(kind="hash", value=dropped, algorithm="SHA-256"),
        ]

        (row,) = [r for r in build_consolidated_iocs(report) if r.value == dropped]

        assert row.source == "sandbox"
        assert str(row.published).startswith(
            "no: the sandbox report does not say which process wrote it; the judge's indicator"
        )
        assert dropped not in json.dumps(_export(report))

    def test_the_values_written_under_a_key_are_the_key_row_s_context(self) -> None:
        row = _rows(_report())[RUN_KEY]

        assert row.context == "modify value Updater; create value Helper"
        assert not [value for value in _rows(_report()) if value.startswith(f"{RUN_KEY} (")]

    def test_a_key_a_persistence_mechanism_names_is_its_row(self) -> None:
        mods = [RegistryMod(hive="HKLM", key=PERSIST_KEY, value_name="x", operation="create")]
        report = _report(dynamic=DynamicBehavior(registry_mods=mods))

        row = _rows(report)[PERSIST_KEY]

        assert (row.source, row.context) == ("persistence", "run key; create value x")
        assert publishes(row.published)

    def test_a_digest_is_typed_by_its_length(self) -> None:
        rows = _rows(_report())

        assert (rows[DROPPED].type, rows[DROPPED_SHA1].type) == ("SHA-256", "SHA-1")
        odd = _report(
            dynamic=DynamicBehavior(
                process_tree=[ProcessNode(pid=1, name="sample.exe")],
                file_operations=[{"operation": "write", "sha256": "ab" * 20 + "c", "pid": 1}],
            )
        )
        (row,) = [
            r for r in build_consolidated_iocs(odd) if r.source == "sandbox" and r.kind == "hash"
        ]
        assert (row.type, row.published) == ("Hash", "no: not a whole digest")


class TestTheFeedIsTheTable:
    def test_every_row_of_the_table_is_a_row_of_the_feed_with_its_decision(self) -> None:
        report = _report()
        table = [r for r in build_consolidated_iocs(report) if r.kind != "secret"]
        feed = ioc_feed_rows(report.model_dump(mode="json"))

        assert [(row["kind"], _bare(row["value"]), row["publish_answer"]) for row in feed] == [
            (row.kind, row.value, row.published) for row in table
        ]
        assert [row["published"] for row in feed] == [publishes(row.published) for row in table]

    def test_a_digest_is_written_after_its_algorithm(self) -> None:
        values = {row["value"] for row in ioc_feed_rows(_report().model_dump(mode="json"))}

        assert {f"md5:{MD5}", f"sha1:{SHA1}", f"imphash:{IMPHASH}", f"sha256:{DROPPED}"} <= values
        assert f"sha1:{DROPPED_SHA1}" in values

    def test_a_kind_filter_keeps_that_kind_alone(self) -> None:
        feed = ioc_feed_rows(_report().model_dump(mode="json"), "registry")

        assert [row["value"] for row in feed] == [RUN_KEY, PERSIST_KEY]

    def test_a_secret_is_served_only_to_a_filter_that_names_its_kind(self) -> None:
        stored = _report().model_dump(mode="json")

        assert SECRET not in {row["value"] for row in ioc_feed_rows(stored)}
        assert [row["value"] for row in ioc_feed_rows(stored, "secret")] == [SECRET]

    def test_only_an_analyst_s_host_row_carries_the_answer_as_its_note(self) -> None:
        feed = ioc_feed_rows(_report().model_dump(mode="json"))

        assert all(row["notes"] is None for row in feed if row["source"] != "analyst")

    def test_a_report_the_model_cannot_read_serves_the_rows_it_stored(self) -> None:
        stored = _report().model_dump(mode="json")
        stored["consolidated_iocs"] = [
            row.model_dump(mode="json") for row in build_consolidated_iocs(_report())
        ]
        stored["verdict"] = {"not": "a verdict"}

        feed = ioc_feed_rows(stored)

        assert {_bare(row["value"]) for row in feed} >= {DROPPED, RUN_KEY, COMMAND}


def _feed(report: MalwareReport, include: str) -> list[dict[str, Any]]:
    service = ReportService(db=None)  # type: ignore[arg-type]
    stored = report.model_dump(mode="json")

    async def _stored(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return stored

    service.get_malware_report = _stored  # type: ignore[method-assign]
    rows = asyncio.run(
        service.get_malware_report_iocs(uuid.uuid4(), None, include=include)  # type: ignore[arg-type]
    )
    assert rows is not None
    return rows


class TestTheDefaultFeed:
    def test_is_exactly_the_published_rows_of_include_all(self) -> None:
        report = _report()
        everything = _feed(report, "all")

        assert _feed(report, "published") == [row for row in everything if row["published"]]
        assert _feed(report, "unpublished") == [row for row in everything if not row["published"]]

    def test_carries_the_attributed_host_rows_and_withholds_the_rest(self) -> None:
        values = {_bare(row["value"]) for row in _feed(_report(), "published")}

        assert {DROPPED, WRITTEN, MUTEX, PERSIST_KEY, MD5, SHA1, IMPHASH} <= values
        assert not {COMMAND, SERVICE, TASK, SWEPT, STRAY, OUTSIDE, RUN_KEY, SECRET} & values


def _judge(*objects: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--0f1e2d3c-4b5a-4968-8776-655443332211",
        "objects": list(objects),
    }


def _indicator(pattern: str, suffix: str = "12") -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433322{suffix}",
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-01T00:00:00Z",
        "name": "sample",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "valid_from": "2026-01-01T00:00:00Z",
    }


MALWARE = {
    "type": "malware",
    "spec_version": "2.1",
    "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332299",
    "created": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "name": "ExampleLoader",
    "is_family": True,
}
INDICATES = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--0f1e2d3c-4b5a-4968-8776-655443332288",
    "created": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "relationship_type": "indicates",
    "source_ref": "indicator--0f1e2d3c-4b5a-4968-8776-655443332212",
    "target_ref": MALWARE["id"],
}


def _export(report: MalwareReport, judge: dict[str, Any] | None = None) -> dict[str, Any]:
    base = Bundle.model_validate(judge) if judge is not None else None
    return ExtendedSTIXRenderer().render(report, base).model_dump(mode="json")


def _exported(bundle: dict[str, Any]) -> set[str]:
    return {
        value.value.lower()
        for obj in bundle["objects"]
        if obj["type"] == "indicator"
        for value in pattern_values(obj["pattern"])
    }


def _sample(bundle: dict[str, Any]) -> dict[str, Any]:
    (sample,) = [o for o in bundle["objects"] if o.get("name", "").startswith("Sample hash")]
    return sample


class TestTheExport:
    def test_names_the_sample_by_its_identity_digests_and_passes_the_validator(self) -> None:
        bundle = _export(_report())

        assert _sample(bundle)["pattern"] == (
            f"[file:hashes.'SHA-256' = '{SHA256}' OR file:hashes.'SHA-1' = '{SHA1}' OR "
            f"file:hashes.'MD5' = '{MD5}']"
        )
        result = validate_instance(bundle, ValidationOptions(version="2.1"))
        assert result.is_valid, [str(error) for error in result.errors]

    def test_the_similarity_digests_are_an_indicator_that_claims_no_malice(self) -> None:
        hashes = FileHashes(
            sha256=SHA256, sha1=SHA1, md5=MD5, sha512="ab" * 64, imphash=IMPHASH,
            ssdeep=SSDEEP, tlsh=TLSH,
        )  # fmt: skip
        bundle = _export(_report(identity=SampleIdentity(hashes=hashes)))
        sample = _sample(bundle)
        (similar,) = [o for o in bundle["objects"] if o.get("name", "").startswith("Files like")]

        assert "file:hashes.'SHA-512' = '" in sample["pattern"]
        assert sample["indicator_types"] == ["malicious-activity"]
        for absent in ("imphash", "SSDEEP", "TLSH"):
            assert absent not in sample["pattern"]
        assert similar["pattern"] == (
            f"[file:extensions.'windows-pebinary-ext'.imphash = '{IMPHASH}' OR "
            f"file:hashes.'SSDEEP' = '{SSDEEP}' OR file:hashes.'TLSH' = '{TLSH}']"
        )
        assert similar["indicator_types"] == ["anomalous-activity"]
        result = validate_instance(bundle, ValidationOptions(version="2.1"))
        assert result.is_valid, [str(error) for error in result.errors]

    def test_carries_every_published_row_of_the_table_and_no_withheld_one(self) -> None:
        report = _report()
        exported = _exported(_export(report))
        table = build_consolidated_iocs(report)

        published = {row.value.lower() for row in table if publishes(row.published)}
        withheld = {row.value.lower() for row in table if not publishes(row.published)}
        assert published <= exported | {IMPHASH}
        assert not withheld & exported

    @pytest.mark.parametrize(
        "pattern",
        [f"[file:hashes.'SHA-256' = '{SHA256}']", f"[file:hashes.MD5 = '{MD5}']"],
        ids=["quoted", "unquoted"],
    )
    def test_a_judge_indicator_for_the_sample_s_digest_is_folded_with_its_edge(
        self, pattern: str
    ) -> None:
        judge = _judge(MALWARE, _indicator(pattern), INDICATES)

        bundle = _export(_report(), judge)

        sample = _sample(bundle)
        assert not [
            o
            for o in bundle["objects"]
            if o["type"] == "indicator" and o is not sample and (SHA256 in o["pattern"])
        ]
        assert INDICATES["source_ref"] not in json.dumps(bundle)
        # The edges the platform adds for the other indicators aside: the
        # judge's edge is the sample's one edge.
        edges = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship"
            and o["relationship_type"] == "indicates"
            and o.get("description") != PLATFORM_INDICATES_EDGE
        ]
        assert [(e["source_ref"], e["target_ref"]) for e in edges] == [
            (sample["id"], MALWARE["id"])
        ]

    def test_the_judge_s_bundle_is_unchanged_and_renders_the_same_twice(self) -> None:
        judge = _judge(MALWARE, _indicator(f"[file:hashes.'SHA-256' = '{SHA256}']"), INDICATES)
        base = Bundle.model_validate(judge)
        before = base.model_dump_json()
        report = _report()

        first = ExtendedSTIXRenderer().render(report, base).model_dump(mode="json")
        second = ExtendedSTIXRenderer().render(report, base).model_dump(mode="json")

        assert base.model_dump_json() == before
        for bundle in (first, second):
            sample = _sample(bundle)
            assert [
                o["target_ref"]
                for o in bundle["objects"]
                if o["type"] == "relationship"
                and o["relationship_type"] == "indicates"
                and o["source_ref"] == sample["id"]
            ] == [MALWARE["id"]]

    def test_a_folded_indicator_s_sets_are_merged_onto_the_sample_s(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import judge_postprocess

        merged: list[tuple[str, str]] = []
        real = judge_postprocess._merge_indicator_sets

        def _spy(kept: Any, duplicate: Any) -> None:
            merged.append((str(kept.name), str(duplicate.id)))
            real(kept, duplicate)

        monkeypatch.setattr(judge_postprocess, "_merge_indicator_sets", _spy)
        judge = _judge(MALWARE, _indicator(f"[file:hashes.MD5 = '{MD5}']"), INDICATES)

        _export(_report(), judge)

        assert merged == [(f"Sample hash {SHA256[:12]}", INDICATES["source_ref"])]


# PyMISP's describeTypes.json, ``category_type_mappings``: for each category
# the attribute builder writes, the types MISP accepts in it, restricted to the
# types it writes. Copied from the published file, not inferred.
MISP_CATEGORY_TYPES: dict[str, set[str]] = {
    "Payload delivery": {
        "domain", "email-dst", "filename", "imphash", "ip-dst", "ja3-fingerprint-md5", "md5",
        "sha1", "sha256", "sha512", "ssdeep", "text", "tlsh", "url", "user-agent",
    },
    "Artifacts dropped": {
        "filename", "imphash", "md5", "mutex", "named pipe", "regkey", "sha1", "sha256",
        "sha512", "ssdeep", "text", "windows-scheduled-task", "windows-service-name",
    },
    "Payload installation": {
        "filename", "imphash", "md5", "sha1", "sha256", "sha512", "ssdeep", "text", "tlsh",
    },
    "Persistence mechanism": {"filename", "regkey", "text"},
    "Network activity": {
        "domain", "email-dst", "ip-dst", "ja3-fingerprint-md5", "text", "url", "user-agent",
    },
    "External analysis": {
        "domain", "filename", "ip-dst", "ja3-fingerprint-md5", "md5", "regkey", "sha1",
        "sha256", "text", "url", "user-agent",
    },
    "Other": {"text"},
}  # fmt: skip


class TestTheMispAttributes:
    def _attributes(self, report: MalwareReport | None = None) -> list[dict[str, Any]]:
        report = report or _report()
        return build_misp_attributes(report, build_consolidated_iocs(report), owner=OWNER)

    def test_each_type_is_one_misp_accepts_in_its_category(self) -> None:
        hashes = FileHashes(
            sha256=SHA256, sha1=SHA1, md5=MD5, sha512="ab" * 64, imphash=IMPHASH,
            ssdeep=SSDEEP, tlsh=TLSH,
        )  # fmt: skip
        attributes = self._attributes(
            _report(identity=SampleIdentity(hashes=hashes, file_name="sample.exe"))
        )

        assert attributes
        for attribute in attributes:
            assert attribute["type"] in MISP_CATEGORY_TYPES[attribute["category"]], attribute

    def test_a_category_misp_refuses_the_type_in_falls_back_to_payload_delivery(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting import misp
        from maljan.reporting.models import ConsolidatedIOC

        # The sample's own digests filed as dropped artifacts: MISP takes an
        # MD5 there and a TLSH not.
        monkeypatch.setitem(misp._HASH_CATEGORIES, "identity", "Artifacts dropped")
        tlsh = ConsolidatedIOC(type="TLSH", kind="hash", value=TLSH, source="identity")
        md5 = ConsolidatedIOC(type="MD5", kind="hash", value=MD5, source="identity")

        assert misp.misp_type(tlsh) == ("tlsh", "Payload delivery")
        assert misp.misp_type(md5) == ("md5", "Artifacts dropped")
        assert "tlsh" not in MISP_CATEGORY_TYPES["Artifacts dropped"]

    def test_a_kind_misp_has_no_type_for_is_text_and_never_for_ids(self) -> None:
        from maljan.reporting.models import ConsolidatedIOC

        # A capture's JA3S is published by no rule (it names no process), so
        # the typing is read off a row given as published.
        row = ConsolidatedIOC(
            type="JA3S",
            kind="ja3s",
            value="e35df3e00ca4ef31d42b34bebaa2f86e",
            source="sandbox",
            published="yes: a test row",
        )
        attributes = build_misp_attributes(_report(), [row], owner=OWNER)
        (ja3s,) = [a for a in attributes if a["value"] == "e35df3e00ca4ef31d42b34bebaa2f86e"]

        assert (ja3s["type"], ja3s["category"], ja3s["to_ids"]) == ("text", "Other", False)
        assert ja3s["comment"].startswith("JA3S")

    def test_each_published_row_is_one_attribute_of_misp_s_type(self) -> None:
        typed = {(a["type"], a["value"]): a for a in self._attributes()}

        assert typed[("md5", MD5)]["category"] == "Payload delivery"
        assert typed[("sha1", SHA1)]["category"] == "Payload delivery"
        assert typed[("sha256", SHA256)]["category"] == "Payload delivery"
        assert typed[("imphash", IMPHASH)]["category"] == "Payload delivery"
        assert typed[("sha256", DROPPED)]["category"] == "Artifacts dropped"
        assert typed[("sha1", DROPPED_SHA1)]["category"] == "Artifacts dropped"
        assert typed[("sha256", CARVED)]["category"] == "Payload installation"
        assert typed[("filename", WRITTEN)]["category"] == "Artifacts dropped"
        assert typed[("regkey", PERSIST_KEY)]["category"] == "Persistence mechanism"
        assert typed[("mutex", MUTEX)]["category"] == "Artifacts dropped"
        assert typed[("ip-dst", C2)]["category"] == "Network activity"

    def test_to_ids_follows_the_publish_decision_and_spares_the_similarity_digests(
        self,
    ) -> None:
        hashes = FileHashes(sha256=SHA256, md5=MD5, imphash=IMPHASH, ssdeep=SSDEEP, tlsh=TLSH)
        attributes = self._attributes(
            _report(identity=SampleIdentity(hashes=hashes, file_name="sample.exe"))
        )
        flags = {a["type"]: a["to_ids"] for a in attributes if a["category"] != "External analysis"}

        assert (flags["sha256"], flags["md5"], flags["mutex"]) == (True, True, True)
        assert (flags["imphash"], flags["ssdeep"], flags["tlsh"]) == (False, False, False)
        assert "the sandbox recorded it from the sample's process tree" in next(
            a["comment"] for a in attributes if a["value"] == DROPPED
        )

    def test_a_withheld_value_is_no_attribute(self) -> None:
        values = {a["value"] for a in self._attributes()}

        assert not {COMMAND, SERVICE, TASK, SWEPT, STRAY, OUTSIDE, RUN_KEY, SECRET} & values

    def test_a_technique_is_tagged_by_the_name_att_ck_gives_it(self) -> None:
        techniques = [a for a in self._attributes() if a["category"] == "External analysis"]
        canonical = technique_entry("T1547.001")
        assert canonical is not None and canonical.name

        assert [(a["value"], a["to_ids"]) for a in techniques][0] == (
            f"T1547.001 {canonical.name}",
            False,
        )
        assert techniques[0]["Tag"] == [
            {"name": f'misp-galaxy:mitre-attack-pattern="{canonical.name} - T1547.001"'}
        ]
        unknown = next(a for a in techniques if a["value"].startswith("T9999"))
        assert unknown["value"] == "T9999" and "Tag" not in unknown

    def test_the_same_report_builds_the_same_attributes_and_another_owner_others(
        self,
    ) -> None:
        first, second = self._attributes(), self._attributes()
        report = _report()
        other = build_misp_attributes(report, build_consolidated_iocs(report), owner="another")

        assert first == second
        assert len({a["uuid"] for a in first}) == len(first)
        expected = uuid.uuid5(
            uuid.uuid5(uuid.NAMESPACE_URL, "maljan:misp-attribute"), f"{OWNER}|md5|{MD5}"
        )
        assert next(a["uuid"] for a in first if a["value"] == MD5) == str(expected)
        assert not {a["uuid"] for a in first} & {a["uuid"] for a in other}

    def test_the_build_writes_them_into_the_report(self) -> None:
        from maljan.reporting.builder import MalwareReportBuilder

        report = MalwareReportBuilder(
            file_hash=SHA256,
            file_name="sample.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.9,
            judge_assessment=None,
            malware_category="loader",
            evidence_ledger=[],
            job_id=OWNER,
        ).build_deterministic()

        assert isinstance(report.misp_attributes, list)
        (attribute,) = [a for a in report.misp_attributes if a["value"] == SHA256]
        expected = uuid.uuid5(
            uuid.uuid5(uuid.NAMESPACE_URL, "maljan:misp-attribute"), f"{OWNER}|sha256|{SHA256}"
        )
        assert attribute["uuid"] == str(expected)


class TestAReportStoredBeforeTheseFields:
    def _stored(self) -> dict[str, Any]:
        stored = _report().model_dump(mode="json")
        stored.pop("misp_attributes", None)
        stored["consolidated_iocs"] = [
            {"type": "Command line", "value": COMMAND, "kind": "command", "source": "sandbox"}
        ]
        return stored

    def test_still_reads_feeds_and_renders(self) -> None:
        stored = self._stored()

        report = MalwareReport.model_validate(stored)
        feed = ioc_feed_rows(stored)

        assert report.misp_attributes is None
        assert {_bare(row["value"]) for row in feed} >= {DROPPED, COMMAND}
        assert all(isinstance(row["published"], bool) for row in feed)
        assert COMMAND in MarkdownRenderer().render(report)

    def test_is_served_with_the_table_the_feed_serves_and_its_misp_attributes(self) -> None:
        stored = self._stored()

        served, note = with_current_iocs(stored, OWNER)

        assert [row["value"] for row in served["consolidated_iocs"]] == [
            row.value for row in build_consolidated_iocs(MalwareReport.model_validate(stored))
        ]
        assert [(r["value"], r["published"]) for r in ioc_feed_rows(stored, "hash")] == [
            (
                f"{row['type'].lower().replace('-', '')}:{row['value']}"
                if row["type"] != "Hash"
                else row["value"],
                publishes(row["published"]),
            )
            for row in served["consolidated_iocs"]
            if row["kind"] == "hash"
        ]
        assert ("md5", MD5) in {(a["type"], a["value"]) for a in served["misp_attributes"]}
        assert note == OLD_RULE_STIX_NOTE
        assert stored.get("misp_attributes") is None

    def test_a_report_built_under_the_rule_carries_no_note(self) -> None:
        stored = _report(misp_attributes=[]).model_dump(mode="json")

        served, note = with_current_iocs(stored, OWNER)

        assert note is None and served["misp_attributes"] == []
