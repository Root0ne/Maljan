"""The script and rehearsal defects of the B9 audit (T-307) stay fixed."""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import json
import os
import sys
import textwrap
from pathlib import Path
from typing import Any

import httpx
import pytest
from scripts.rehearsal import inprocess, models, validate, wire
from scripts.rehearsal.stub_model import StubServer, StubState

from maljan.core import plugins
from tests.unit.scripts.test_the_attck_fixture_script_never_retires_an_unfetched_domain import (
    _bundle,
    _deprecated,
    _Fetcher,
    _paths,
    _previous,
    _script,
)

ROOT = Path(__file__).resolve().parents[3]
USER = [{"role": "user", "content": "hi"}]


class _Fixed:
    def __init__(self, reply: wire.Reply) -> None:
        self.reply = reply

    def reset(self) -> None:
        return None

    def answer(self, request: wire.Request) -> tuple[str, wire.Reply, str]:
        return "analyst", self.reply, ""


def _server(reply: wire.Reply) -> StubServer:
    return StubServer(StubState(brain=_Fixed(reply))).start()  # type: ignore[arg-type]


def test_the_stub_log_answers_instead_of_deadlocking() -> None:
    server = _server(wire.Reply(text="x"))
    try:
        answer = httpx.get(f"{server.root}/_stub/log", timeout=10)
        after = httpx.get(f"{server.root}/_stub/log", timeout=10)
    finally:
        server.stop()
    assert answer.status_code == 200
    assert answer.json() == []
    assert after.status_code == 200


def test_a_model_id_cannot_leave_the_description_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret": true}', encoding="utf-8")
    relative = os.path.relpath(outside.with_suffix(""), models._DESCRIPTIONS)
    assert ".." in relative
    assert models._description(relative) is None
    assert models._description("a/b") is None
    assert models._description("..") is None
    assert models._description("claude-haiku-5-5") is not None


def test_a_non_ascii_signature_is_a_refusal_not_an_error() -> None:
    signer = validate.Signer()
    block = {"type": "thinking", "thinking": "x", "signature": "stubsig-é"}
    assert signer.valid({}, block) is False
    assert signer.valid({}, {"type": "redacted_thinking", "data": "é"}) is False
    lone = {"type": "thinking", "thinking": "x", "signature": "stubsig-\ud800"}
    assert signer.valid({}, lone) is False
    good = {"type": "thinking", "thinking": "x", "signature": signer.sign({}, "x")}
    assert signer.valid({}, good) is True


def test_a_streamed_error_fires_on_a_reply_with_no_content() -> None:
    import anthropic
    import openai

    server = _server(wire.Reply(stream_error=True))
    try:
        with pytest.raises(anthropic.APIStatusError, match="Overloaded"):
            with anthropic.Anthropic(
                base_url=server.root, api_key="k", max_retries=0
            ).messages.stream(model="claude-haiku-5-5", max_tokens=100, messages=USER) as stream:
                stream.get_final_message()
        with pytest.raises(Exception, match="overloaded"):
            client = openai.OpenAI(base_url=f"{server.root}/v1", api_key="k", max_retries=0)
            for _ in client.chat.completions.create(
                model="deepseek-v4-flash", messages=USER, stream=True
            ):
                pass
    finally:
        server.stop()


def test_a_tool_s_own_timeout_is_not_the_run_s_deadline() -> None:
    own = TimeoutError("tool timed out")
    assert inprocess.timeout_message(600.0, 3.0, own) == "TimeoutError: tool timed out"
    assert inprocess.timeout_message(None, 3.0, own) == "TimeoutError: tool timed out"
    cancelled = TimeoutError()
    cancelled.__cause__ = asyncio.CancelledError()
    assert inprocess.timeout_message(5.0, 1.0, cancelled) == "the run passed its 5.0s deadline"
    bare = TimeoutError()
    assert inprocess.timeout_message(5.0, 5.2, bare) == "the run passed its 5.0s deadline"
    assert inprocess.timeout_message(5.0, 1.0, own) == "TimeoutError: tool timed out"


def test_the_process_state_puts_back_the_plugin_allow_list() -> None:
    before = plugins.allow_list()
    try:
        plugins.install_allow_list(["llm:before"])
        kept = inprocess._ProcessState()
        plugins.install_allow_list(["llm:during"])
        assert plugins.allow_list() == frozenset({"llm:during"})
        kept.restore()
        assert plugins.allow_list() == frozenset({"llm:before"})
    finally:
        plugins.install_allow_list(sorted(before))


def _load(relative: str) -> Any:
    spec = importlib.util.spec_from_file_location(Path(relative).stem + "_t307", ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_frozen_composer_golden_is_not_overwritten_by_a_run_with_no_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load("scripts/goldens/capture_composer_requests.py")
    fixture = ROOT / "tests" / "fixtures" / "composer_requests_before_concurrency.json"
    before = fixture.read_bytes()
    monkeypatch.setattr(sys, "argv", ["capture_composer_requests"])
    with pytest.raises(SystemExit) as refused:
        module.main()
    assert refused.value.code == 2
    assert "--fixture" in capsys.readouterr().err
    assert fixture.read_bytes() == before


def test_a_replay_out_is_refused_anywhere_in_the_repository_unless_ignored(
    tmp_path: Path,
) -> None:
    module = _load("scripts/goldens/capture_composer_requests.py")
    for inside in ("data", "apps", "tests", "src", "scripts", "."):
        with pytest.raises(SystemExit):
            module.check_replay_paths([], ROOT / inside)
    assert module.check_replay_paths([], tmp_path / "out") == (tmp_path / "out").resolve()


@pytest.mark.parametrize(
    "relative",
    [
        "scripts/goldens/capture_graph_golden.py",
        "scripts/goldens/capture_provider_goldens.py",
        "scripts/goldens/render_team_graphs.py",
        "scripts/goldens/capture_run_summary_golden.py",
    ],
)
def test_the_golden_writers_read_no_process_environment(relative: str) -> None:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    built = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "Settings" not in built
    assert "build_settings" in built


def test_a_graph_golden_does_not_move_with_the_operator_s_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load("scripts/goldens/capture_graph_golden.py")
    plain = module.graph_shape(True)
    monkeypatch.setenv("LLM__PROVIDER", "anthropic")
    monkeypatch.setenv("LLM__PARALLEL_ANALYSTS", "false")
    assert module.graph_shape(True) == plain


def test_a_codes_name_extended_with_augmented_assignment_is_read(tmp_path: Path) -> None:
    from scripts.validation_codes.register import build

    files = {
        "src/demo/__init__.py": "",
        "src/demo/base.py": "from dataclasses import dataclass\n\n\n"
        "@dataclass(frozen=True)\nclass Violation:\n    code: str\n",
        "src/demo/checks.py": textwrap.dedent(
            """\
            FOO_CODES = ("a.one",)
            FOO_CODES += ("a.two",)
            """
        ),
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    found = {code.code for code in build(tmp_path).codes}
    assert {"a.one", "a.two"} <= found


def _versioned(bundle: dict[str, Any], version: str) -> dict[str, Any]:
    bundle["objects"][0]["x_mitre_version"] = version
    return bundle


def test_a_valid_but_empty_bundle_is_refused_before_any_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _script()
    paths = _paths(tmp_path)
    before = _previous(paths["valid_ids_out"])
    for empty in ({"objects": []}, {}, _bundle()):
        fetcher = _Fetcher(
            {"enterprise": _bundle("T1001"), "mobile": empty, "ics": _bundle("T0800")}
        )
        with pytest.raises(SystemExit) as stopped:
            mod.prepare(fetcher=fetcher, **paths)
        assert stopped.value.code == 1
        assert "mobile bundle holds no active technique id" in capsys.readouterr().err
        assert paths["valid_ids_out"].read_text(encoding="utf-8") == before
        assert not paths["retired_out"].exists()
        assert not paths["techniques_out"].exists()
    fetcher = _Fetcher(
        {"enterprise": _bundle(), "mobile": _bundle("T1400"), "ics": _bundle("T0800")}
    )
    with pytest.raises(SystemExit):
        mod.prepare(fetcher=fetcher, **paths)
    assert paths["valid_ids_out"].read_text(encoding="utf-8") == before


def _ten(paths: dict[str, Any]) -> list[str]:
    ids = [f"T{1000 + i}" for i in range(10)]
    paths["valid_ids_out"].write_text(json.dumps({"enterprise": ids}), encoding="utf-8")
    return ids


def test_a_big_legitimate_deprecation_passes(tmp_path: Path) -> None:
    mod = _script()
    paths = _paths(tmp_path)
    ids = _ten(paths)
    fetcher = _Fetcher(
        {
            "enterprise": _deprecated(_bundle(ids[0]), *ids[1:]),
            "mobile": _bundle("T1400"),
            "ics": _bundle("T0800"),
        }
    )
    mod.prepare(fetcher=fetcher, **paths)
    retired = json.loads(paths["retired_out"].read_text(encoding="utf-8"))
    assert set(retired) - {"_meta"} == set(ids[1:])


def test_a_previous_id_the_bundle_does_not_carry_is_refused_and_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _script()
    paths = _paths(tmp_path)
    ids = _ten(paths)
    before = paths["valid_ids_out"].read_text(encoding="utf-8")

    def fetcher() -> _Fetcher:
        return _Fetcher(
            {
                "enterprise": _bundle(*ids[:9]),
                "mobile": _bundle("T1400"),
                "ics": _bundle("T0800"),
            }
        )

    with pytest.raises(SystemExit) as stopped:
        mod.prepare(fetcher=fetcher(), **paths)
    assert stopped.value.code == 1
    assert ids[9] in capsys.readouterr().err
    assert paths["valid_ids_out"].read_text(encoding="utf-8") == before
    assert not paths["retired_out"].exists()
    # A deliberate shrink is accepted with the flag.
    mod.prepare(fetcher=fetcher(), accept_lost_ids=True, **paths)
    retired = json.loads(paths["retired_out"].read_text(encoding="utf-8"))
    assert set(retired) - {"_meta"} == {ids[9]}


def test_the_labeled_sentences_are_written_only_when_asked_for(tmp_path: Path) -> None:
    mod = _script()
    paths = _paths(tmp_path)
    paths.pop("labeled_out")
    fetcher = _Fetcher(
        {"enterprise": _bundle("T1001"), "mobile": _bundle("T1400"), "ics": _bundle("T0800")}
    )
    mod.prepare(fetcher=fetcher, **paths)
    assert not (tmp_path / "labeled.jsonl").exists()
    mod.prepare(fetcher=fetcher, labeled_out=tmp_path / "labeled.jsonl", **paths)
    assert (tmp_path / "labeled.jsonl").exists()


def test_url_of_one_release_with_domains_of_another_is_refused_before_any_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _script()
    paths = _paths(tmp_path)
    before = _previous(paths["valid_ids_out"])
    fetcher = _Fetcher(
        {
            "enterprise": _versioned(_bundle("T1001"), "2.0"),
            "mobile": _versioned(_bundle("T1400"), "1.0"),
            "ics": _versioned(_bundle("T0800"), "2.0"),
        }
    )
    with pytest.raises(SystemExit) as stopped:
        mod.prepare(fetcher=fetcher, url="https://example.com/enterprise.json", **paths)
    assert stopped.value.code == 1
    assert "mobile bundle is release 1.0, enterprise is 2.0" in capsys.readouterr().err
    assert paths["valid_ids_out"].read_text(encoding="utf-8") == before
    assert not paths["retired_out"].exists()
    fetcher.bundles["mobile"] = _versioned(_bundle("T1400"), "2.0")
    mod.prepare(fetcher=fetcher, **paths)
    assert (
        json.loads(paths["valid_ids_out"].read_text(encoding="utf-8"))["_meta"]["attck_version"]
        == "2.0"
    )


def test_a_replay_out_check_without_the_vcs_tool_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load("scripts/goldens/capture_composer_requests.py")

    def missing(*args: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError("missing")

    monkeypatch.setattr(module.subprocess, "run", missing)
    with pytest.raises(SystemExit, match="needs git"):
        module.check_replay_paths([], ROOT / "data")


@pytest.mark.parametrize("operator", ["-=", "*=", "|=", "+="])
def test_only_additive_augmented_assignments_read_as_codes(tmp_path: Path, operator: str) -> None:
    from scripts.validation_codes.register import build

    checks = f'FOO_CODES = frozenset({{"a.one"}})\nFOO_CODES {operator} {{"a.two"}}\n'
    files = {
        "src/demo/__init__.py": "",
        "src/demo/base.py": "from dataclasses import dataclass\n\n\n"
        "@dataclass(frozen=True)\nclass Violation:\n    code: str\n",
        "src/demo/checks.py": checks,
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    register = build(tmp_path)
    found = {code.code for code in register.codes}
    if operator in ("|=", "+="):
        assert "a.two" in found
    else:
        assert "a.two" not in found
        assert any("augmented assignment" in item.why for item in register.unresolved)
