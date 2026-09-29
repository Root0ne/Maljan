"""A Ghidra that answers the pack's REST calls in-process, for the tests of its anti-analysis pass.

It speaks the shapes the Ghidra server answers in: a load, a switch, an
analysis, the program's image base and the anti-analysis scan.
"""

from __future__ import annotations

from typing import Any

import httpx

X64_BASE = 0x140000000


class FakeGhidra:
    """The endpoints the pass calls, and a record of every request."""

    def __init__(
        self,
        *,
        image_base: int = X64_BASE,
        load: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        self.image_base = image_base
        self.load = load if load is not None else {"success": True, "program": "s.exe"}
        self.findings = findings if findings is not None else []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/load_program":
            return httpx.Response(200, json=self.load)
        if path == "/switch_program":
            return httpx.Response(200, json={"success": True})
        if path == "/run_analysis":
            return httpx.Response(200, json={"success": True, "total_functions": 3})
        if path == "/get_current_program_info":
            return httpx.Response(200, json={"image_base": f"{self.image_base:08x}"})
        if path == "/find_anti_analysis_techniques":
            return httpx.Response(
                200,
                json={
                    "total_findings": len(self.findings),
                    "summary": {"by_category": {}, "by_severity": {}},
                    "findings": self.findings,
                },
            )
        return httpx.Response(200, json={"error": f"unknown endpoint {path}"})
