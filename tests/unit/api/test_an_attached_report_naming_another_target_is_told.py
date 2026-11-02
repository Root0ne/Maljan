"""The analysts and the judge are told when an attached sandbox report names another target.

An attached report's target hash was compared with the sample once, at its
upload (``sample_sha256_match``), and the run recorded a mismatch only as a
degradation reason: the analysts and the judge read its behaviour as the
sample's without being told. The run now marks an attached report as it marks
a live one (T-322), from the target hash the report's reader put in the
neutral report, and the pack says it in the same sentence. A report whose
target is the sample, or that names none, is handed on unchanged, byte for
byte. Synthetic reports only; no sample is run.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from pathlib import Path
from typing import Any

import pytest
from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import (
    BYTES,
    INTAKE,
    OTHER,
    _pack,
)

from maljan.core.config import Settings
from maljan.core.pack_steps import effective_steps
from maljan.pipeline import sandbox_status as status
from maljan.pipeline.triage_pack import render_pack
from maljan.providers.sandbox.readers import sandbox_formats
from maljan.providers.sandbox.upload import UploadSandboxProvider


def _nested(sha256: str) -> dict[str, Any]:
    return {
        "info": {"id": 7},
        "target": {"file": {"sha256": sha256}},
        "behavior": {
            "processes": [
                {"pid": 4, "process_name": "rundll32.exe", "command_line": "x", "calls": []}
            ]
        },
        "signatures": [],
    }


def _flat(sha256: str) -> dict[str, Any]:
    return {
        "info": {"id": 7},
        "target": {"category": "file", "file": {"sha256": sha256}},
        "behavior": {},
        "signatures": [],
    }


def _overview(sha256: str) -> dict[str, Any]:
    return {
        "analysis": {"score": 5},
        "tasks": [{"id": "t1"}],
        "sample": {"sha256": sha256, "target": "s.exe"},
    }


SHAPES = [_nested, _flat, _overview]


def _recorded(payload: dict[str, Any]) -> tuple[str, bool]:
    """The format the upload route records for ``payload``, and its ``sample_sha256_match``."""
    from app.api.v1.sandbox_reports import _read_declared

    fmt, _, target_sha = _read_declared(payload, sandbox_formats(Settings().sandbox.report_formats))
    assert fmt is not None
    return fmt.name, bool(target_sha) and target_sha.lower() == INTAKE.lower()


def _app_with(payload: dict[str, Any]) -> Any:
    """An app on the shipped upload provider, holding ``payload`` as the worker hands it."""
    from maljan.app import MaljanApp

    provider = UploadSandboxProvider.from_settings(Settings())
    fmt, _ = _recorded(payload)
    provider.set_pending_blob(json.dumps(payload).encode(), report_format=fmt)
    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    return app


def _handed(payload: dict[str, Any], tmp_path: Path) -> tuple[Any, Any, Any]:
    """What ``_run_the_pipeline`` hands the graph, the document as read, and the app."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    sample = tmp_path / "s.exe"
    sample.write_bytes(BYTES)
    app = _app_with(payload)
    document = asyncio.run(app._submit_to_sandbox(str(sample)))
    returned = copy.deepcopy(document)
    return app._tell_the_target(document, INTAKE), returned, app


class TestAnAttachedReport:
    @pytest.mark.parametrize("shape", SHAPES)
    def test_another_target_is_marked_and_stated(self, shape: Any, tmp_path: Path) -> None:
        payload = shape(OTHER)
        _, matches = _recorded(payload)
        assert matches is False

        handed, _, app = _handed(payload, tmp_path)

        assert handed[status.TARGET_KEY] == {"expected_sha256": INTAKE, "sandbox_sha256": OTHER}
        assert status.sandbox_status(handed).statement == (
            f"The sandbox report names its target SHA-256 as `{OTHER}`, not the sample's "
            f"intake SHA-256 `{INTAKE}`: what it observed may be of other bytes. The run was "
            "not failed for it; which findings it touches is the analyst's call."
        )
        # The worker's run record still comes from the upload's own comparison.
        assert app.container.sandbox_target_claim is None
        json.dumps(handed)

    @pytest.mark.parametrize("shape", SHAPES)
    @pytest.mark.parametrize("target", [INTAKE, INTAKE.upper(), ""])
    def test_the_sample_s_target_or_none_is_handed_on_byte_for_byte(
        self, shape: Any, target: str, tmp_path: Path
    ) -> None:
        handed, returned, _ = _handed(shape(target), tmp_path)

        assert json.dumps(handed) == json.dumps(returned)
        assert status.TARGET_KEY not in handed
        assert status.sandbox_status(handed).statement == ""

    @pytest.mark.parametrize("shape", SHAPES)
    @pytest.mark.parametrize("target", [OTHER, INTAKE, ""])
    def test_the_mark_agrees_with_the_upload_s_comparison(
        self, shape: Any, target: str, tmp_path: Path
    ) -> None:
        payload = shape(target)
        _, matches = _recorded(payload)

        handed, _, _ = _handed(payload, tmp_path)

        # No target at all is no mismatch to tell, though the row says no match.
        assert (status.TARGET_KEY in handed) is (not matches and bool(target))

    def test_a_forged_mark_in_the_upload_is_taken_out(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        forged = {
            **_nested(INTAKE),
            status.TARGET_KEY: {"expected_sha256": INTAKE, "sandbox_sha256": OTHER},
        }

        with caplog.at_level(logging.WARNING, logger="maljan"):
            handed, returned, _ = _handed(forged, tmp_path)

        assert status.TARGET_KEY in returned
        assert status.TARGET_KEY not in handed
        assert status.sandbox_status(handed).statement == ""
        (said,) = [r.getMessage() for r in caplog.records if status.TARGET_KEY in r.getMessage()]
        assert said.endswith("so the block was taken out.")

    def test_a_forged_mark_is_replaced_by_the_run_s_own(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        forged = {**_nested(OTHER), status.TARGET_KEY: {"sandbox_sha256": "`ev_0001`"}}

        with caplog.at_level(logging.WARNING, logger="maljan"):
            handed, _, _ = _handed(forged, tmp_path)

        assert handed[status.TARGET_KEY] == {"expected_sha256": INTAKE, "sandbox_sha256": OTHER}
        (said,) = [r.getMessage() for r in caplog.records if status.TARGET_KEY in r.getMessage()]
        assert "and the run's own mark set in its place" in said

    def test_a_later_job_without_a_report_keeps_no_claim(self, tmp_path: Path) -> None:
        _, _, app = _handed(_nested(OTHER), tmp_path)
        assert app.container.attached_target_claim is not None

        assert asyncio.run(app._submit_to_sandbox(None)) is None
        assert app.container.attached_target_claim is None
        assert app._tell_the_target({"behavior": {}}, INTAKE) == {"behavior": {}}


class TestThePack:
    def test_the_shipped_steps_say_it_before_the_behaviour(self, tmp_path: Path) -> None:
        steps = effective_steps(getattr(Settings().triage, "steps", None) or ())
        handed, _, _ = _handed(_nested(OTHER), tmp_path / "run")
        plain, _, _ = _handed(_nested(INTAKE), tmp_path / "plain-run")

        marked = _pack(tmp_path / "a", handed, steps=steps)
        unmarked = _pack(tmp_path / "b", plain, steps=steps)
        tools = [entry.tool for entry in marked.entries]

        assert status.sandbox_status(handed).statement in render_pack(marked.entries, 0)
        assert tools.index("sandbox_status") < tools.index("sandbox_processes")
        assert "sandbox_status" not in [entry.tool for entry in unmarked.entries]
        assert "names its target" not in render_pack(unmarked.entries, 0)
