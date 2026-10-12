"""The validation harness's own checks: offline, no run, no server, a second or two.

``python scripts/validation/run.py --self-check`` runs them. They hold the
harness pieces to what the plan says they do — the stub's argument filling
(H3), the report hand-over and the static paths (H1, H2), the reach reading
(H5), the registered memory backend (H7) and the result directory rule — so a
validation run that misses a gate misses it for the product, not for the
harness. A script rather than test cases: the suite's live count stays put.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

CHECKS: list[tuple[str, Callable[[], None]]] = []


def check(fn: Callable[[], None]) -> Callable[[], None]:
    CHECKS.append((fn.__name__, fn))
    return fn


def _tool(name: str, required: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "description": "",
        "schema": {"type": "object", "properties": required, "required": list(required)},
    }


def _facts() -> Any:
    from scripts.rehearsal.roles import _Facts

    return _Facts(ids=[], lines=[], urls=[], sample_path="/s/sample_1.exe", sha256="a" * 64)


LISTING = json.dumps(
    {"functions": [{"name": "entry0", "address": "0x00401000"}, {"name": "FUN_00401200"}]}
)
IMPORTED = json.dumps({"binary_name": "sample_1.exe-1a2b3c", "status": "imported"})


@check
def an_address_argument_is_given_up_without_answers() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool("any_decompiler", {"address": {"type": "string"}})
    assert _fillable(tool, _facts()) is None
    assert _fillable(tool, _facts(), []) is None


@check
def an_address_argument_takes_the_latest_answers_first_place() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool("any_decompiler", {"address": {"type": "string"}})
    args = _fillable(tool, _facts(), [LISTING])
    assert args == {"address": "0x00401000"}, args
    older = json.dumps({"seen": "sub_00409999"})
    assert _fillable(tool, _facts(), [LISTING, older]) == {"address": "0x00401000"}
    named = _tool("x", {"name_or_address": {"type": "string"}})
    assert _fillable(named, _facts(), [older, LISTING]) == {"name_or_address": "sub_00409999"}


@check
def a_required_string_takes_the_value_under_its_key() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool("x", {"binary_name": {"type": "string"}, "name_or_address": {"type": "string"}})
    args = _fillable(tool, _facts(), [LISTING, IMPORTED])
    assert args == {"binary_name": "sample_1.exe-1a2b3c", "name_or_address": "0x00401000"}, args
    by_last_word = _tool("x", {"program_status": {"type": "string"}})
    assert _fillable(by_last_word, _facts(), [IMPORTED]) == {"program_status": "imported"}
    prose = _tool("x", {"session": {"type": "string"}})
    assert _fillable(prose, _facts(), ["opened\nsession: s-42\n"]) == {"session": "s-42"}
    missing = _tool("x", {"unheard_of": {"type": "string"}})
    assert _fillable(missing, _facts(), [IMPORTED]) is None


@check
def a_described_place_is_filled_only_when_no_key_holds_it() -> None:
    from scripts.rehearsal.roles import _fillable

    described = _tool("x", {"target": {"type": "string", "description": "the function to read"}})
    assert _fillable(described, _facts(), [LISTING]) == {"target": "0x00401000"}
    held = _tool("x", {"target": {"type": "string", "description": "the function to read"}})
    assert _fillable(held, _facts(), [json.dumps({"target": "t1"})]) == {"target": "t1"}


@check
def every_rule_that_filled_before_fills_the_same() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool(
        "x",
        {
            "file_path": {"type": "string"},
            "section": {"type": "string"},
            "technique_id": {"type": "string"},
            "api": {"type": "string"},
            "sha256": {"type": "string"},
            "limit": {"type": "integer"},
        },
    )
    before = _fillable(tool, _facts())
    assert before == _fillable(tool, _facts(), [LISTING, IMPORTED]), before
    pcap = _tool("x", {"pcap_path": {"type": "string"}})
    assert _fillable(pcap, _facts(), [LISTING]) is None


@check
def a_tool_answer_is_read_without_the_products_frame() -> None:
    from scripts.rehearsal.roles import _answer_text

    framed = '[ev_0042]\n{"a": 1}\n\n=== RUN STATE (derived) ===\n[ev_0001] 0x1234'
    assert _answer_text(framed) == '{"a": 1}'


@check
def the_stub_fills_from_answers_only_when_asked() -> None:
    from scripts.rehearsal import wire
    from scripts.rehearsal.roles import _next_call

    tools = [_tool("any_decompiler", {"address": {"type": "string"}})]
    turns = [
        wire.Turn(role="user", text="go"),
        wire.Turn(role="assistant", tool_calls=[wire.ToolCall("lister", {}, "c1")]),
        wire.Turn(role="user", tool_results=[wire.ToolResult("c1", "[ev_0001]\n" + LISTING)]),
    ]
    request = wire.Request("openai", "m", "sys", turns, tools, None, False, {})
    assert _next_call(request, _facts(), 1) is None
    call = _next_call(request, _facts(), 1, fill_from_results=True)
    assert call is not None and call.args == {"address": "0x00401000"}, call


@check
def a_report_is_refused_by_a_provider_that_takes_none() -> None:
    from scripts.rehearsal.inprocess import attach_report

    handed: list[Any] = []

    def provider(accepts: bool) -> Any:
        return SimpleNamespace(
            id="p",
            capabilities=SimpleNamespace(accepts_uploaded_report=accepts),
            set_pending_blob=lambda blob, **kw: handed.append((blob, kw)),
        )

    path = _ROOT / "tests" / "fixtures" / "sandbox" / "cape2_report.json"
    refusing = SimpleNamespace(
        container=SimpleNamespace(get_sandbox_provider=lambda: provider(False))
    )
    try:
        attach_report(refusing, path, None)
    except ValueError:
        pass
    else:
        raise AssertionError("a provider that accepts no report took one")
    taking = SimpleNamespace(container=SimpleNamespace(get_sandbox_provider=lambda: provider(True)))
    attach_report(taking, path, "cape2")
    assert handed and handed[0][1] == {"filename": path.name, "report_format": "cape2"}
    assert handed[0][0] == path.read_bytes()


@check
def static_paths_are_passed_as_the_worker_passes_them() -> None:
    from scripts.rehearsal.inprocess import Rehearsal, _static_paths

    settings = SimpleNamespace(static=SimpleNamespace(provider="r2"))
    sample = Path("/s/sample_1.exe")
    assert _static_paths(Rehearsal(), settings, sample) == {}
    got = _static_paths(Rehearsal(static_sample_paths={"r2": ""}), settings, sample)
    assert got == {"static_sample_path": str(sample), "static_sample_paths": {"r2": str(sample)}}


def _record(**over: Any) -> Any:
    base = {
        "malware_report": {
            "evidence_index": [
                {"id": "ev_0001", "server": "pipeline", "tool": "t", "ok": True, "source": "pack"},
                {
                    "id": "ev_0002",
                    "server": "newcomer",
                    "tool": "look",
                    "ok": True,
                    "source": "mcp:newcomer",
                    "facts": {},
                },
            ],
            "sections": [{"key": "tool_look", "evidence_ids": ["ev_0002"]}],
            "flagged_statements": [],
            "degradation_reasons": [],
            "figures": [],
            "technical_evidence": {"a": [{"seq": 1, "output": "the newcomer answered this"}]},
        },
        "events": [
            {
                "type": "agent_message",
                "role": "analyst",
                "speaker": "a",
                "claims": [{"claim": "It looks.", "evidence_ref": "[ev_0002] look: ..."}],
            },
        ],
        "run_summary": {"corroboration": {}},
        "markdown": "Appendix A. Evidence index\n\n| ID |\n|---|\n| ev_0002 | a | newcomer |\n",
        "stix_bundle": {},
        "stix_extended": {},
    }
    base.update(over)
    return SimpleNamespace(**base)


@check
def reach_reads_the_six_rows_of_one_source() -> None:
    import tempfile

    from scripts.validation.reach import reach

    with tempfile.TemporaryDirectory() as tmp:
        dump = Path(tmp)
        body = {
            "model": "m",
            "messages": [
                {"role": "system", "content": "sys"},
                {
                    "role": "user",
                    "content": "Section: x. Evidence: [ev_0002] the newcomer answered this",
                },
            ],
        }
        (dump / "0001-composer.json").write_text(json.dumps(body), encoding="utf-8")
        row = reach(_record(), dump, "newcomer", absent=("Elsewhere",))
    for e in ("E1", "E2", "E3", "E4", "E5", "E6"):
        assert row[e]["ok"], (e, row[e])
    assert row["E3"]["undeclared"] == ["ev_0002"]
    named = reach(_record(markdown="Elsewhere said so"), None, "newcomer", absent=("Elsewhere",))
    assert not named["E6"]["ok"] and not named["E4"]["ok"]
    failed = _record()
    failed.malware_report["technical_evidence"]["a"][0]["output"] = "Error: binary not found"
    assert reach(failed, None, "newcomer")["E6"]["ok_but_reads_as_error"] == ["ev_0002"]


@check
def the_registered_backend_is_built_by_the_products_factory() -> None:
    from scripts.validation import memory_backend

    from maljan.core.settings_overrides import build_settings
    from maljan.memory.store_factory import build_memory_store, registered_backends

    store = memory_backend.register()
    try:
        built = build_memory_store(build_settings({"memory.backend": memory_backend.BACKEND_ID}))
        assert built is store and built.function_hash_store() is None
        case = SimpleNamespace(sample_id="s1", summary_text="beacon over http")
        built.store(case)
        assert built.retrieve("http beacon") == [case]
        assert built.retrieve("http beacon", exclude_sample_id="s1") == []
        built.clear()
        built.writes.clear()
    finally:
        memory_backend.unregister()
    assert memory_backend.BACKEND_ID not in registered_backends()


@check
def a_results_directory_under_a_dot_segment_is_refused() -> None:
    from scripts.validation.run import no_hidden_segment

    try:
        no_hidden_segment(Path("/tmp/x/.hidden/out"))
    except SystemExit:
        pass
    else:
        raise AssertionError("a dot segment was accepted")
    assert no_hidden_segment(Path("/tmp/x/out")) == Path("/tmp/x/out").resolve()


def run_self_checks() -> int:
    failed = 0
    for name, fn in CHECKS:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — every check is reported
            failed += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {name}")
    print(f"{len(CHECKS) - failed}/{len(CHECKS)} harness self-checks pass")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run_self_checks())
