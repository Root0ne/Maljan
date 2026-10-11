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

from maljan.core.config import SandboxUploadConfig, Settings
from maljan.core.report_formats import (
    BUILTIN_REPORT_FORMATS,
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
    upload = SandboxUploadConfig.model_validate({"formats": [INVENTED]})
    formats = effective_formats(upload.formats)
    payload = _acme_payload()
    fmt = sniff(payload, formats)
    assert fmt is not None and fmt.name == "acme"
    assert sniff_format(payload, formats) == "acme"
    assert fmt.task_id(payload) == "T-77"
    assert fmt.target_sha256(payload) == SHA
    # Without the declaration the same payload is the built-in it resembles.
    assert sniff_format(payload) == "cuckoo"


def test_a_declared_format_is_tried_before_the_built_ins() -> None:
    upload = SandboxUploadConfig.model_validate({"formats": [INVENTED]})
    assert [fmt.name for fmt in effective_formats(upload.formats)] == [
        "acme",
        "triage",
        "cape2",
        "cuckoo",
    ]


def test_a_declared_built_in_name_replaces_that_built_in_in_its_place() -> None:
    own_cape = {**INVENTED, "name": "cape2", "task_id_paths": ["/run/ticket"]}
    upload = SandboxUploadConfig.model_validate({"formats": [own_cape]})
    formats = effective_formats(upload.formats)
    assert [fmt.name for fmt in formats] == ["triage", "cape2", "cuckoo"]
    assert format_named("cape2", formats) is upload.formats[0]
    assert format_named("cape2") is BUILTIN_REPORT_FORMATS[1]


def test_settings_carry_a_declared_format_through_a_round_trip() -> None:
    settings = Settings.model_validate({"sandbox": {"upload": {"formats": [INVENTED]}}})
    dumped = settings.sandbox.upload.model_dump(mode="json")
    again = SandboxUploadConfig.model_validate(dumped)
    assert again.formats == settings.sandbox.upload.formats


@pytest.mark.parametrize(
    ("change", "says"),
    [
        ({"name": "unknown"}, "no format recognises"),
        ({"name": "Acme"}, "pattern"),
        ({"detect": []}, "at least 1"),
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
        SandboxUploadConfig.model_validate({"formats": [INVENTED, INVENTED]})


# ---------------------------------------------------------------------------
# The upload provider reads the declaration
# ---------------------------------------------------------------------------


def _provider(formats: list[dict[str, Any]], allowed: list[str]) -> UploadSandboxProvider:
    settings = Settings.model_validate(
        {
            "sandbox": {
                "provider": "upload",
                "upload": {"formats": formats, "allowed_formats": allowed},
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
    deep_format = ReportFormat.model_validate(
        {
            "name": "deep",
            "detect": [[{"path": "/**/producer/name", "contains": "acme"}]],
            "task_id_paths": ["/**/ticket"],
            "target_sha256_paths": ["/rows/*/digest", "/**/sha256"],
        }
    )
    formats = effective_formats([deep_format])
    small, large = _hostile(2_000), _hostile(20_000)
    assert sniff(large, formats) is None
    ratio = _seconds(large, formats) / max(_seconds(small, formats), 1e-6)
    assert ratio < 30, f"ten times the payload took {ratio:.1f} times as long"


def test_a_signature_scale_reports_its_own_size() -> None:
    assert SignatureScale(name="x", rungs=["Low", "High"]).max == 2
