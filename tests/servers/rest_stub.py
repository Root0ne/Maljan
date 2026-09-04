"""A sandbox that does not exist, so the REST provider can be driven for real.

Deliberately not shaped like CAPE or Triage: field names, paths and the state
progression are all its own, because a stub that resembled a sandbox we
already support would pass with a mapping that only happens to work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "rest_mapping" / "xyz_report.json"
)


@dataclass
class StubState:
    submitted: list[str] = field(default_factory=list)
    states: list[str] = field(default_factory=lambda: ["queued", "running", "finished"])
    report: dict[str, Any] = field(
        default_factory=lambda: json.loads(FIXTURE.read_text(encoding="utf-8"))
    )
    pcap: bytes = b"\xd4\xc3\xb2\xa1" + b"\0" * 64


def build_stub_app(state: StubState) -> FastAPI:
    app = FastAPI()

    @app.post("/xyz/submit")
    async def submit(request: Request) -> dict[str, Any]:
        form = await request.form()
        upload = form["binary"]
        state.submitted.append(getattr(upload, "filename", "unknown"))
        return {"task": {"ref": "XYZ-1"}}

    @app.get("/xyz/task/{task_id}")
    async def status(task_id: str) -> dict[str, Any]:
        current = state.states[0] if len(state.states) == 1 else state.states.pop(0)
        return {"task": {"ref": task_id, "state": current}}

    @app.get("/xyz/task/{task_id}/result")
    async def report(task_id: str) -> dict[str, Any]:
        return state.report

    @app.get("/xyz/task/{task_id}/capture")
    async def pcap(task_id: str) -> bytes:
        from fastapi.responses import Response

        return Response(content=state.pcap, media_type="application/vnd.tcpdump.pcap")

    return app
