"""A sandbox report format is recognised, read and rated from its declaration.

The built-in declarations are held against the code they replaced, kept here
as the oracle: the same name, task id and target hash for every payload shape
that code distinguished. A format declared only as data is recognised and read
with no code of its own, a declared built-in name replaces the built-in, a
declaration the platform cannot read is refused when it is saved, and every
read stays linear on a hostile payload.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from maljan.core.config import SandboxConfig, Settings
from maljan.core.report_formats import (
    BUILTIN_REPORT_FORMATS,
    FORMAT_NAME_MAX,
    ReportFormat,
    SignatureScale,
    effective_formats,
    format_named,
    sniff,
)
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.formats import sniff_format
from maljan.providers.sandbox.upload import UploadSandboxProvider
from tests.unit.providers._cape_fixture import FIXTURE_PATH, first_cape_report

ROOT = Path(__file__).resolve().parents[4]
SANDBOX_FIXTURES = ROOT / "tests" / "fixtures" / "sandbox"


# ---------------------------------------------------------------------------
# The oracle: the sniffer and the upload route's two readers as they were coded
# ---------------------------------------------------------------------------


def _coded_sniff(payload: Any) -> str:
    if not isinstance(payload, dict) or not payload:
        return "unknown"
    analysis = payload.get("analysis")
    tasks = payload.get("tasks")
    if isinstance(analysis, dict) and isinstance(tasks, list | dict) and tasks:
        return "triage"
    if isinstance(payload.get("CAPE"), dict | list):
        return "cape2"
    info_field = payload.get("info")
    info = info_field if isinstance(info_field, dict) else {}
    version = str(info.get("version") or "")
    if "cape" in version.lower():
        return "cape2"
    if isinstance(payload.get("behavior"), dict) and info:
        return "cuckoo"
    return "unknown"


def _coded_task_id(payload: dict[str, Any], fmt: str) -> str | None:
    if fmt == "triage":
        sample = payload.get("sample")
        return str(sample.get("id")) if isinstance(sample, dict) and sample.get("id") else None
    info = payload.get("info")
    return str(info.get("id")) if isinstance(info, dict) and info.get("id") is not None else None


def _coded_target_sha(payload: dict[str, Any], fmt: str) -> str:
    if fmt == "triage":
        block = payload.get("sample")
        return str(block.get("sha256") or "") if isinstance(block, dict) else ""
    target = payload.get("target")
    if not isinstance(target, dict):
        return ""
    file_block = target.get("file")
    if isinstance(file_block, dict) and file_block.get("sha256"):
        return str(file_block["sha256"])
    return str(target.get("sha256") or "")


SHA = "a" * 64
OTHER = "b" * 64


def _payloads() -> list[Any]:
    """Every shape the coded readers told apart, and the real fixtures."""
    out: list[Any] = [
        first_cape_report(),
        json.loads(FIXTURE_PATH.read_text(encoding="utf-8")),
        *(
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SANDBOX_FIXTURES.glob("*.json"))
        ),
        {},
        {"hello": "world"},
        [],
        "text",
        {"analysis": {"score": 1}, "tasks": []},
        {"analysis": {"score": 1}, "tasks": {}},
        {
            "analysis": {"score": 1},
            "tasks": [{"name": "t"}],
            "sample": {"id": "260903-x", "sha256": SHA},
        },
        {"analysis": {}, "tasks": {"t1": {}}, "sample": {"id": "", "sha256": ""}},
        {"analysis": {}, "tasks": {"t1": {}}, "sample": ["not", "a", "block"]},
        {"analysis": [], "tasks": [1]},
        {"CAPE": {"payloads": []}, "info": {"id": 4242}, "target": {"sha256": SHA}},
        {"CAPE": [], "info": {"id": None}, "target": {"file": {"sha256": SHA}, "sha256": OTHER}},
        {"CAPE": "string", "info": {"version": "2.0"}, "behavior": {}},
        {
            "info": {"version": "CAPEv2 2.4", "id": 0},
            "target": {"file": {"sha256": ""}, "sha256": SHA},
        },
        {"info": {"version": "capev2"}, "target": "flat"},
        {
            "info": {"version": 2.4, "id": 7},
            "behavior": {"processes": []},
            "target": {"file": {"sha256": SHA}},
        },
        {"info": {"version": None, "id": "12"}, "behavior": {}},
        {"info": {}, "behavior": {}},
        {"info": [], "behavior": {}},
        {"info": {"id": 9}, "behavior": []},
        {"info": {"id": 9}, "behavior": {}, "target": {"file": [], "sha256": SHA}},
        {"info": {"id": 9}, "behavior": {}, "target": {"file": {"sha256": None}}},
    ]
    return out


@pytest.mark.parametrize("payload", _payloads(), ids=lambda p: type(p).__name__)
def test_the_built_ins_name_every_payload_as_the_coded_sniffer_did(payload: Any) -> None:
    assert sniff_format(payload) == _coded_sniff(payload)


@pytest.mark.parametrize("payload", [p for p in _payloads() if _coded_sniff(p) != "unknown"])
def test_the_built_ins_read_the_task_id_and_target_hash_as_the_route_did(payload: Any) -> None:
    fmt = sniff(payload)
    assert fmt is not None
    assert fmt.task_id(payload) == _coded_task_id(payload, fmt.name)
    assert fmt.target_sha256(payload) == _coded_target_sha(payload, fmt.name)


def test_the_built_ins_are_tried_most_specific_first() -> None:
    assert [fmt.name for fmt in BUILTIN_REPORT_FORMATS] == ["triage", "cape2", "cuckoo"]
    assert [fmt.reader for fmt in BUILTIN_REPORT_FORMATS] == ["triage", "cape2", "cuckoo"]


def test_each_built_in_declares_its_documented_signature_scale() -> None:
    scales = {fmt.name: fmt.signature_scale for fmt in BUILTIN_REPORT_FORMATS}
    assert scales["cape2"] is not None and scales["cape2"].record() == {
        "name": "CAPE 1–3",
        "max": 3,
        "rungs": ["Low", "Medium", "High"],
    }
    assert scales["cuckoo"] is not None and scales["cuckoo"].rungs == ["Low", "Medium", "High"]
    triage = scales["triage"]
    assert triage is not None and triage.max == 10
    assert triage.rungs[0] == "Informational" and triage.rungs[5] == "Medium"
    assert triage.rungs[7] == "High" and triage.rungs[9] == "Critical"


# ---------------------------------------------------------------------------
# A format declared only as data
# ---------------------------------------------------------------------------

INVENTED = {
    "name": "acme",
    "detect": [
        [{"path": "/producer/name", "contains": "acme"}, {"path": "/run", "types": ["object"]}]
    ],
    "task_id_paths": ["/run/ticket"],
    "target_sha256_paths": ["/subject/digests/sha256", "/subject/sha256"],
    "reader": "cape2",
    "signature_scale": {"name": "Acme 1–4", "rungs": ["Low", "Medium", "High", "Critical"]},
}


def _declared(*formats: dict[str, Any]) -> list[ReportFormat]:
    """``formats`` as ``sandbox.report_formats`` validates them."""
    return SandboxConfig.model_validate({"report_formats": list(formats)}).report_formats


def _acme_payload(sha: str = SHA) -> dict[str, Any]:
    return {
        "producer": {"name": "ACME detonator 3"},
        "run": {"ticket": "T-77"},
        "subject": {"digests": {"sha256": sha}},
        "behavior": {"processes": [], "apistats": {}, "generic": []},
        "info": {"id": 1},
        "signatures": [{"name": "s", "description": "d", "severity": 3}],
    }


def test_a_declared_format_is_recognised_and_read_with_no_code_of_its_own() -> None:
    formats = effective_formats(_declared(INVENTED))
    payload = _acme_payload()
    fmt = sniff(payload, formats)
    assert fmt is not None and fmt.name == "acme"
    assert sniff_format(payload, formats) == "acme"
    assert fmt.task_id(payload) == "T-77"
    assert fmt.target_sha256(payload) == SHA
    # Without the declaration the same payload is the built-in it resembles.
    assert sniff_format(payload) == "cuckoo"


def test_a_declared_format_is_tried_before_the_built_ins() -> None:
    assert [fmt.name for fmt in effective_formats(_declared(INVENTED))] == [
        "acme",
        "triage",
        "cape2",
        "cuckoo",
    ]


def test_a_declared_built_in_name_is_merged_over_that_built_in_field_by_field() -> None:
    shipped = BUILTIN_REPORT_FORMATS[1]
    formats = effective_formats(
        _declared({"name": "cape2", "signature_scale": {"name": "Fork 1–5", "rungs": ["Low"] * 5}})
    )
    assert [fmt.name for fmt in formats] == ["triage", "cape2", "cuckoo"]
    merged = format_named("cape2", formats)
    assert merged is not None and merged is not shipped
    assert merged.signature_scale is not None and merged.signature_scale.name == "Fork 1–5"
    # Every field the declaration left out keeps the shipped value.
    assert merged.detect == shipped.detect
    assert merged.task_id_paths == shipped.task_id_paths
    assert merged.target_sha256_paths == shipped.target_sha256_paths
    assert merged.reader == shipped.reader
    assert format_named("cape2") is shipped


def test_a_built_in_field_set_to_nothing_is_kept_as_set() -> None:
    merged = format_named(
        "cape2", effective_formats(_declared({"name": "cape2", "signature_scale": None}))
    )
    assert merged is not None and merged.signature_scale is None
    assert merged.detect == BUILTIN_REPORT_FORMATS[1].detect


def test_a_new_format_must_say_how_it_is_recognised() -> None:
    with pytest.raises(ValidationError, match="needs detect"):
        _declared({k: v for k, v in INVENTED.items() if k != "detect"})


def test_settings_carry_a_declared_format_through_a_round_trip() -> None:
    settings = Settings.model_validate({"sandbox": {"report_formats": [INVENTED]}})
    dumped = settings.sandbox.model_dump(mode="json")
    again = SandboxConfig.model_validate(dumped)
    assert again.report_formats == settings.sandbox.report_formats


def test_a_format_name_fits_the_upload_rows_column() -> None:
    from app.models.sandbox_report import SandboxReportRow

    assert SandboxReportRow.__table__.c.format.type.length == FORMAT_NAME_MAX
    assert ReportFormat.model_validate({**INVENTED, "name": "a" * FORMAT_NAME_MAX}).name


def test_a_task_id_or_hash_is_a_string_or_a_number_and_anything_else_is_absent() -> None:
    fmt = ReportFormat.model_validate(
        {
            **INVENTED,
            "task_id_paths": ["/ids/*"],
            "target_sha256_paths": ["/hashes/*"],
        }
    )
    payload = {
        "ids": [None, "", False, True, [], {}, ["x"], {"a": 1}, 0],
        "hashes": [[SHA], {"s": SHA}, True, SHA],
    }
    assert fmt.task_id(payload) == "0"
    assert fmt.target_sha256(payload) == SHA
    assert fmt.task_id({"ids": [False, {"a": 1}]}) is None
    assert fmt.target_sha256({"hashes": [0, [SHA]]}) == ""


@pytest.mark.parametrize(
    ("change", "says"),
    [
        ({"name": "unknown"}, "no format recognises"),
        ({"name": "Acme"}, "pattern"),
        ({"name": "a" * (FORMAT_NAME_MAX + 1)}, "pattern"),
        ({"detect": []}, "at least one group"),
        ({"detect": [[{"path": "/**/marker"}]]}, "may not hold '**'"),
        ({"task_id_paths": ["/**"]}, "may not hold '**'"),
        ({"target_sha256_paths": ["/a/**2/sha256"]}, "may not hold '**'"),
        ({"detect": [[]]}, "at least one test"),
        ({"detect": [[{"path": "producer"}]]}, "must start with '/'"),
        ({"detect": [[{"path": ""}]]}, "needs a path"),
        ({"detect": [[{"path": "/a", "types": ["map"]}]]}, "literal_error"),
        ({"task_id_paths": ["/**/a/**/b"]}, "holds it 2 times"),
        ({"target_sha256_paths": [""]}, "names nothing"),
        ({"reader": "acme"}, "literal_error"),
        ({"signature_scale": {"name": "x", "rungs": []}}, "at least 1"),
        ({"signature_scale": {"name": "x", "rungs": ["Severe"]}}, "literal_error"),
        ({"signature_scale": {"name": " ", "rungs": ["Low"]}}, "needs a name"),
        ({"extra": 1}, "extra_forbidden"),
    ],
)
def test_a_declaration_the_platform_cannot_read_is_refused(
    change: dict[str, Any], says: str
) -> None:
    with pytest.raises(ValidationError) as caught:
        ReportFormat.model_validate({**INVENTED, **change})
    text = str(caught.value) + " ".join(str(e.get("type")) for e in caught.value.errors())
    assert says in text


def test_two_declarations_under_one_name_are_refused() -> None:
    with pytest.raises(ValidationError, match="declared twice"):
        _declared(INVENTED, INVENTED)


# ---------------------------------------------------------------------------
# The upload provider reads the declaration
# ---------------------------------------------------------------------------


def _provider(formats: list[dict[str, Any]], allowed: list[str]) -> UploadSandboxProvider:
    settings = Settings.model_validate(
        {
            "sandbox": {
                "provider": "upload",
                "report_formats": formats,
                "upload": {"allowed_formats": allowed},
            }
        }
    )
    return UploadSandboxProvider.from_settings(settings)


def test_the_upload_provider_reads_a_declared_format_through_its_reader() -> None:
    provider = _provider([INVENTED], ["acme"])
    blob = json.dumps(_acme_payload()).encode()
    provider.set_pending_blob(blob)
    assert provider.capabilities.report_format == "cape2"
    run = provider.fetch("uploaded")
    assert run.report.source_format == "cape2"
    assert [s.name for s in run.report.signatures] == ["s"]
    scale = provider.signature_scale(run)
    assert scale is not None and scale.name == "Acme 1–4"


def test_a_declared_format_without_a_reader_is_refused_in_words() -> None:
    provider = _provider([{**INVENTED, "reader": ""}], ["acme"])
    provider.set_pending_blob(json.dumps(_acme_payload()).encode())
    assert provider.capabilities.report_format == "generic"
    with pytest.raises(ProviderError, match="declared without a reader"):
        provider.fetch("uploaded")


def test_a_recorded_format_is_read_as_recorded_and_never_sniffed_again() -> None:
    # A report the built-ins would sniff as Cuckoo, recorded as cape2, is read
    # by the cape2 reader with the cape2 scale: the row,
    # not a second sniff, says what the bytes are.
    provider = _provider([], ["cape2", "cuckoo"])
    provider.set_pending_blob(json.dumps(_acme_payload()).encode(), report_format="cape2")
    assert provider.capabilities.report_format == "cape2"
    run = provider.fetch("uploaded")
    assert run.report.source_format == "cape2"
    scale = provider.signature_scale(run)
    assert scale is not None and scale.name == "CAPE 1–3"


def test_a_recorded_format_no_longer_declared_is_refused_in_words() -> None:
    provider = _provider([], ["acme"])
    with pytest.raises(ProviderError, match="no longer declared"):
        provider.set_pending_blob(json.dumps(_acme_payload()).encode(), report_format="acme")


def test_a_recorded_format_now_declared_without_a_reader_is_refused_in_words() -> None:
    provider = _provider([{**INVENTED, "reader": ""}], ["acme"])
    with pytest.raises(ProviderError, match="declared without a reader"):
        provider.set_pending_blob(json.dumps(_acme_payload()).encode(), report_format="acme")


def test_a_declared_format_not_in_the_allowed_list_is_refused() -> None:
    provider = _provider([INVENTED], ["cape2"])
    with pytest.raises(ProviderError, match="sniffed as 'acme'"):
        provider.attach_report(json.dumps(_acme_payload()).encode())


# ---------------------------------------------------------------------------
# Linear on a hostile payload
# ---------------------------------------------------------------------------


def _hostile(n: int) -> dict[str, Any]:
    """A wide, deep payload no format recognises until its last leaf."""
    nested: Any = {"leaf": "x"}
    for _ in range(min(n, 200)):
        nested = {"next": nested, "pad": list(range(5))}
    return {
        "info": {f"k{i}": {"version": "2.0", "id": i} for i in range(n)},
        "rows": [{"producer": {"name": "nobody"}, "values": list(range(10))} for _ in range(n)],
        "deep": nested,
        "behavior": [],
    }


def _read_all(payload: dict[str, Any], formats: tuple[ReportFormat, ...]) -> None:
    sniff(payload, formats)
    for fmt in formats:
        fmt.task_id(payload)
        fmt.target_sha256(payload)


def _seconds(payload: dict[str, Any], formats: tuple[ReportFormat, ...]) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        _read_all(payload, formats)
        best = min(best, time.perf_counter() - start)
    return best


def test_every_read_is_linear_on_a_hostile_payload() -> None:
    wide_format = ReportFormat.model_validate(
        {
            "name": "wide",
            "detect": [[{"path": "/rows/*/producer/name", "contains": "acme"}]],
            "task_id_paths": ["/rows/*/ticket", "/info/*/id"],
            "target_sha256_paths": ["/rows/*/digest", "/info/*/sha256"],
        }
    )
    formats = effective_formats([wide_format])
    small, large = _hostile(2_000), _hostile(20_000)
    assert sniff(large, formats) is None
    ratio = _seconds(large, formats) / max(_seconds(small, formats), 1e-6)
    assert ratio < 30, f"ten times the payload took {ratio:.1f} times as long"


def test_a_signature_scale_reports_its_own_size() -> None:
    assert SignatureScale(name="x", rungs=["Low", "High"]).max == 2
