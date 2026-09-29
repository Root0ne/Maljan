"""A Ghidra that answers the passes' REST endpoints in-process, for the tests of those passes.

It speaks the shapes the Ghidra server answers in: a load, a switch, an
analysis, the program's image base, the anti-analysis scan, and an emulation
that runs a routine of the tests' own (a rotate-and-add over the name's bytes,
a scheme none of the platform's published algorithms is) when it is asked at
the routine's address with the name's address where the fake's convention puts
it.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from maljan.analysis.ghidra_passes import STACK
from tests.unit.tools.synthetic_pe import TEXT_RVA

X64_BASE = 0x140000000
X86_BASE = 0x400000
ROUTINE = TEXT_RVA + 0x200


def routine_output(name: bytes) -> int:
    value = 0x2B
    for byte in name:
        value = ((value << 7) | (value >> 25)) & 0xFFFFFFFF
        value = (value + byte * 3) & 0xFFFFFFFF
    return value


class FakeGhidra:
    """The endpoints the passes call, and a record of every request."""

    def __init__(
        self,
        *,
        image_base: int = X64_BASE,
        convention: str = "rcx",
        load: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
        constant_output: bool = False,
        routine: Any = None,
        stall_after: int | None = None,
    ) -> None:
        self.image_base = image_base
        self.convention = convention
        self.load = load if load is not None else {"success": True, "program": "s.exe"}
        self.findings = findings if findings is not None else []
        self.constant_output = constant_output
        self.routine = routine or routine_output
        self.stall_after = stall_after
        self.requests: list[httpx.Request] = []
        self.emulations = 0

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
        if path == "/emulate_function":
            return self._emulate(json.loads(request.content))
        return httpx.Response(200, json={"error": f"unknown endpoint {path}"})

    def _emulate(self, body: dict[str, Any]) -> httpx.Response:
        self.emulations += 1
        if self.stall_after is not None and self.emulations > self.stall_after:
            raise httpx.ReadTimeout("no answer")
        # Ghidra reads an address as plain hex; a register value as 0x-hex.
        assert all(not r["address"].startswith("0x") for r in body["memory"])
        assert not body["address"].startswith("0x")
        memory: dict[int, int] = {}
        for region in body["memory"]:
            for index, byte in enumerate(bytes.fromhex(region["hex"])):
                memory[int(region["address"], 16) + index] = byte
        registers = {k: int(v, 16) for k, v in (body.get("registers") or {}).items()}
        if self.convention in ("rcx", "rcx and rdx"):
            pointer, length = registers.get("RCX", 0), registers.get("RDX", 0)
        elif self.convention == "stack":
            pointer = int.from_bytes(
                bytes(memory.get(STACK + 4 + i, 0) for i in range(4)), "little"
            )
            length = int.from_bytes(bytes(memory.get(STACK + 8 + i, 0) for i in range(4)), "little")
        else:
            pointer, length = registers.get("ECX", 0), registers.get("EDX", 0)
        if self.convention == "rcx and rdx":
            # A routine that reads exactly the length it is given, terminator or not.
            name = bytes(memory.get(pointer + i, 0) for i in range(length))
        else:
            name = bytearray()
            while memory.get(pointer + len(name), 0):
                name.append(memory[pointer + len(name)])
        if int(body["address"], 16) != self.image_base + ROUTINE:
            return httpx.Response(200, json={"error": f"No function at address: {body['address']}"})
        value = 0x1234 if self.constant_output else self.routine(bytes(name))
        return httpx.Response(
            200,
            json={
                "success": True,
                "hit_return": True,
                "registers": {"EAX": hex(value)},
            },
        )
