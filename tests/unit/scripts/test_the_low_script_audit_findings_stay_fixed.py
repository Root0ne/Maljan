"""AUD-72 (SC-8..16): small script defects, one regression test each."""

from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load(relative: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_fetch_external_does_not_accept_a_tree_ahead_of_the_pin(tmp_path: Path) -> None:
    text = (ROOT / "scripts" / "dev" / "fetch_external.sh").read_text(encoding="utf-8")
    loop = text[text.index("for spec in") : text.index('\n\n\nif [[ -d "$SIGMA_DEST')]
    repo = tmp_path / "external" / "tree"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "pin")
    _git(repo, "tag", "pin-tag")
    harness = tmp_path / "loop.sh"
    harness.write_text(
        f'set -u\nEXTERNAL="{tmp_path}/external"\ntargets=("tree|file:///nowhere|pin-tag")\n{loop}\n',
        encoding="utf-8",
    )

    def run() -> str:
        done = subprocess.run(
            ["bash", str(harness)], capture_output=True, text=True, check=False, timeout=60
        )
        return done.stdout

    assert "ok       tree" in run()
    _git(repo, "commit", "-q", "--allow-empty", "-m", "ahead of the pin")
    assert "ok       tree" not in run()


def test_stub_host_agrees_with_what_the_settings_save_and_needs_an_opt_in_for_the_rest() -> None:
    stub = _load("scripts/rehearsal/stub_model.py", "stub_model_under_test")
    for good in ("127.0.0.1", "127.5.5.5", "localhost", "172.17.0.1", "172.31.255.254"):
        assert stub.check_bind_host(good) == good
    for other_private in ("10.88.0.1", "192.168.1.5", "172.16.0.1"):
        with pytest.raises(ValueError, match="stub-host-private"):
            stub.check_bind_host(other_private)
        assert stub.check_bind_host(other_private, allow_private=True) == other_private
    never = ("0.0.0.0", "8.8.8.8", "172.32.0.1", "example.com", "", "::1", "169.254.1.1")  # noqa: S104
    for host in never:
        for opt_in in (False, True):
            with pytest.raises(ValueError):
                stub.check_bind_host(host, allow_private=opt_in)
    with pytest.raises(ValueError):
        stub.StubServer(stub.StubState.__new__(stub.StubState), 0, host="10.88.0.1")


def test_validation_out_is_never_the_root_the_home_or_the_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _load("scripts/validation/run.py", "validation_run_under_test")
    monkeypatch.setenv("HOME", str(tmp_path))
    for refused in (Path("/"), tmp_path, ROOT, ROOT.parent):
        with pytest.raises(SystemExit):
            run.no_hidden_segment(refused)
    assert run.no_hidden_segment(tmp_path / "out") == (tmp_path / "out").resolve()


def test_validation_out_check_survives_a_uid_with_no_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _load("scripts/validation/run.py", "validation_run_nohome_under_test")

    def no_home(cls: type[Path]) -> Path:
        raise RuntimeError("no home")

    monkeypatch.setattr(Path, "home", classmethod(no_home))
    assert run.no_hidden_segment(tmp_path / "out") == (tmp_path / "out").resolve()
    with pytest.raises(SystemExit):
        run.no_hidden_segment(Path("/"))


def test_mabel_rows_without_a_family_are_capped_per_category(tmp_path: Path) -> None:
    module = _load("scripts/knowledge/build_attck_case_kb.py", "case_kb_under_test")
    path = tmp_path / "mabel.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "sha256_hash",
                "family_name",
                "mitre_attack_id",
                "capa_capability_name",
                "yara_ransomware",
                "yara_rat",
            ],
        )
        writer.writeheader()
        for kind in ("yara_ransomware", "yara_rat"):
            for index in range(5):
                writer.writerow(
                    {
                        "sha256_hash": f"{kind}{index}",
                        "family_name": "",
                        "mitre_attack_id": "T1059",
                        "capa_capability_name": "run a command",
                        "yara_ransomware": "1" if kind == "yara_ransomware" else "",
                        "yara_rat": "1" if kind == "yara_rat" else "",
                    }
                )
    rows = module._cases_from_mabel([str(path)], max_per_family=2)
    by_category = [r["malware_category"] for r in rows]
    assert by_category.count("RANSOMWARE") == 2
    assert by_category.count("RAT") == 2


def test_measure_dedupes_digestless_rows_and_refuses_an_unknown_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load("scripts/knowledge/measure_api_behaviour_block.py", "measure_under_test")
    row = {"name": "a.exe", "imports": ["CreateFileW", "WriteFile"]}
    twin = {"name": "a.exe", "imports": ["WriteFile", "CreateFileW"]}
    upper = {"name": "b", "sha256": "AB", "imports": ["x"]}
    lower = {"name": "c", "sha256": "ab ", "imports": ["y"]}
    monkeypatch.setattr(module, "walk_pe", lambda roots: iter([row, twin, upper, lower]))
    assert [r["name"] for r in module.corpus(["r"], "windows")] == ["a.exe", "b"]
    monkeypatch.setattr(sys, "argv", ["measure", "somewhere", "--platform", "macos"])
    with pytest.raises(SystemExit) as refused:
        module.main()
    assert refused.value.code == 2


def test_expanded_yara_rules_are_escaped_and_checked_before_they_replace_the_file(
    tmp_path: Path,
) -> None:
    import yaml

    module = _load("scripts/knowledge/expand_yara_rules.py", "expand_yara_under_test")
    rule = {
        "id": "x_t1000_0",
        "technique_id": "T1000",
        "confidence": 0.8,
        "description": 'MITRE: say "hi" \\ done',
        "patterns": ["one", "two"],
    }
    parsed = yaml.safe_load("rules:\n" + module._yaml_dump_rules([rule]))
    assert parsed["rules"][0]["description"] == rule["description"]
    with pytest.raises(SystemExit):
        module._check_output("rules: [unclosed", set(), 0)
    with pytest.raises(SystemExit):
        module._check_output('rules:\n  - technique_id: "T1"\n', {"T1", "T2"}, 0)
    module._check_output('rules:\n  - technique_id: "T1"\n', {"T1"}, 0)
    # A rule lost although its technique is still named by another rule is caught by count.
    two = 'rules:\n  - technique_id: "T1"\n  - technique_id: "T1"\n'
    with pytest.raises(SystemExit):
        module._check_output(two, {"T1"}, 1, existing=2)
    module._check_output(two, {"T1"}, 0, existing=2)
    # U+0085 and every other non-ASCII character survive the round trip, escaped.
    odd = {**rule, "description": "a\x85b", "patterns": ["a\x85b", "\u2028"]}
    dumped = module._yaml_dump_rules([odd])
    assert dumped.isascii()
    back = yaml.safe_load("rules:\n" + dumped)["rules"][0]
    assert back["description"] == "a\x85b"
    assert back["patterns"] == ["a\x85b", "\u2028"]
    # The covered set is read from the old file's YAML, not by a regex.
    old = tmp_path / "old.yaml"
    old.write_text(
        'version: "1"\nrules:\n  - id: a\n    technique_id: "T1"\n    patterns: ["x"]\n'
        '  # - id: b\n  #   technique_id: "T9"\n',
        encoding="utf-8",
    )
    assert module._parse_existing_rules(old)[1] == ["T1"]
    assert not any(ord(ch) > 127 for ch in str(module.__doc__).replace("—", "-"))


def test_ghidra_manager_says_why_a_command_failed_and_ignores_its_state_file(
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load("scripts/dev/ghidra_manager.py", "ghidra_manager_under_test")
    with pytest.raises(subprocess.CalledProcessError):
        module._run([sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"])
    assert "boom" in capsys.readouterr().err
    ignored = subprocess.run(
        ["git", "-C", str(ROOT), "check-ignore", "-q", ".ghidra_mcp_state.json"], check=False
    )
    assert ignored.returncode == 0


def test_fixture_writers_are_anchored_on_the_checkout_not_the_working_directory() -> None:
    for name in ("write_console_schema", "write_tool_declaration_cases"):
        module = _load(f"scripts/dev/{name}.py", f"{name}_under_test")
        assert module.FIXTURE.is_absolute()
        assert ROOT in module.FIXTURE.parents


def test_composer_replay_refuses_an_out_inside_the_repository_sources(tmp_path: Path) -> None:
    module = _load("scripts/goldens/capture_composer_requests.py", "composer_capture_under_test")
    run_dir = tmp_path / "run1"
    run_dir.mkdir()
    for refused in (ROOT / "tests" / "fixtures", ROOT / "src", ROOT / "scripts" / "x"):
        with pytest.raises(SystemExit):
            module.check_replay_paths([run_dir], refused)
    with pytest.raises(SystemExit):
        module.check_replay_paths([Path("/")], tmp_path / "out")
    assert module.check_replay_paths([run_dir], tmp_path / "out") == (tmp_path / "out").resolve()


def test_a_graph_golden_profile_cannot_name_another_directory() -> None:
    module = _load("scripts/goldens/capture_graph_golden.py", "graph_golden_under_test")
    for bad in ("../x", "a/b", "..", ""):
        with pytest.raises(SystemExit):
            module.golden_path(bad)
    assert module.golden_path("team_lead").name == "graph_team_lead.json"


def test_attck_corpus_files_are_written_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load("scripts/knowledge/prepare_attck_malware_fixtures.py", "attck_prepare_atomic")
    seen: list[Path] = []
    real = module._atomic_write_text

    def spy(path: Path, text: str) -> None:
        seen.append(path)
        real(path, text)

    monkeypatch.setattr(module, "_atomic_write_text", spy)
    module.write_retired_ids({"T1": {"x": 1}}, tmp_path / "retired.json")
    module.write_valid_ids({"enterprise": ["T1"]}, tmp_path / "valid.json")
    module.write_technique_table({"T1": {"name": "x"}}, {}, tmp_path / "table.json")
    module.write_labeled_sentences([{"layer": "l", "text": "t"}], tmp_path / "sentences.jsonl")
    assert [p.stem for p in seen] == ["retired", "valid", "table", "sentences"]
    assert json.loads((tmp_path / "valid.json").read_text())["enterprise"] == ["T1"]


def test_sigma_is_pinned_exactly_and_never_falls_back_to_the_default_branch(
    tmp_path: Path,
) -> None:
    text = (ROOT / "scripts" / "dev" / "fetch_external.sh").read_text(encoding="utf-8")
    block = text[text.index('if [[ -d "$SIGMA_DEST/.git" ]]') : text.index("# capa's rules")]
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    _git(upstream, "init", "-q")
    _git(upstream, "commit", "-q", "--allow-empty", "-m", "one")
    _git(upstream, "tag", "pin-tag")
    dest = tmp_path / "sigma"

    def run(ref: str, target: Path) -> subprocess.CompletedProcess[str]:
        harness = tmp_path / "sigma.sh"
        harness.write_text(
            f'set -u\nSIGMA_URL="file://{upstream}"\nSIGMA_REF="{ref}"\n'
            f'SIGMA_DEST="{target}"\n{block}\n',
            encoding="utf-8",
        )
        return subprocess.run(
            ["bash", str(harness)], capture_output=True, text=True, check=False, timeout=60
        )

    assert run("pin-tag", dest).returncode == 0
    assert "ok       sigma" in run("pin-tag", dest).stdout
    _git(dest, "commit", "-q", "--allow-empty", "-m", "ahead")
    assert "ok       sigma" not in run("pin-tag", dest).stdout
    assert _git(dest, "rev-parse", "HEAD") == _git(upstream, "rev-parse", "pin-tag")
    missing = run("no-such-tag", tmp_path / "other")
    assert missing.returncode != 0
    assert "FAIL" in missing.stderr
    assert not (tmp_path / "other").exists()


def test_the_register_refuses_a_checkout_whose_file_list_cannot_be_read(tmp_path: Path) -> None:
    register = _load("scripts/validation_codes/register.py", "register_under_test")
    assert register.tracked_files(tmp_path) is None  # no .git: not a checkout
    (tmp_path / ".git").mkdir()  # a .git that git cannot read
    with pytest.raises(SystemExit, match="ls-files failed"):
        register.tracked_files(tmp_path)


def test_a_golden_run_refuses_duplicates_and_empty_manifests_before_writing_any(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = _load("scripts/goldens/capture_provider_goldens.py", "provider_goldens_under_test")
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "same.json").write_text("{}")
    (tmp_path / "b" / "same.json").write_text("{}")
    monkeypatch.setattr(provider, "ROOT", tmp_path)
    monkeypatch.setattr(provider, "CAPE_GLOBS", ("a/*.json", "b/*.json"))
    monkeypatch.setattr(provider, "PROMPTS", tmp_path / "prompts")
    with pytest.raises(SystemExit, match="same"):
        provider.main()
    assert not (tmp_path / "prompts").exists()

    sets = _load("scripts/goldens/capture_builtin_tool_sets.py", "tool_sets_under_test")
    monkeypatch.setattr(sets, "GOLDEN", tmp_path / "mcp_tools")
    answers = iter([{"a": []}, {}, {"c": []}, {"d": []}])

    async def manifest(*_a: object, **_k: object) -> dict[str, list[str]]:
        return next(answers)

    monkeypatch.setattr(sets, "enumerate_stdio_manifest", manifest)
    with pytest.raises(SystemExit, match="no tools"):
        sets.main()
    assert not (tmp_path / "mcp_tools").exists()
