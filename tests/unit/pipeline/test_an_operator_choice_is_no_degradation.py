"""A reason that cost the run no evidence it would have had is not a degradation (T-338).

A threat-intel key the operator never set, a tool a shared server withholds by
its configured policy, a server the operator switched off: each is listed as
the operator's choice, apart from the losses. Of the losses, one decision says
which cost this sample anything, and both the degraded flag and the tools the
banner names read it. Every sentence here is written by its own producer, so a
producer that changes its words fails here first.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.config import MCPServerConfig
from maljan.pipeline.operator_choice import (
    SampleFacts,
    is_loss,
    is_operator_choice,
    lost_tools,
    split_operator_choices,
)
from maljan.pipeline.triage_pack import run_is_degraded
from maljan.providers.sample_open import (
    LISTED_SHARED_WITHHELD,
    NO_NOTE,
    UNCOVERED,
    UNREAD_SCHEMA,
    withheld_unpinned,
)
from maljan.providers.servers import AGENT_TOOL_UNAVAILABLE_REASON, SERVER_DISABLED, ServerHandle
from maljan.tools.capabilities import ServerCapabilities, ToolNeeds, env, manifest, module

_SHARED = "remote http://localhost:8089 (backend 1)"


def _capabilities(monkeypatch: pytest.MonkeyPatch, *requires: Any) -> ServerCapabilities:
    for req in requires:
        if req.kind == "env":
            monkeypatch.delenv(req.name, raising=False)
    payload = manifest("threatintel", [ToolNeeds("check_hash", tuple(requires))], version="t")
    parsed = ServerCapabilities.from_payload("threatintel", payload)
    assert parsed is not None
    return parsed


def _manifest_reason(monkeypatch: pytest.MonkeyPatch, *requires: Any) -> str:
    """The degradation reason the registry records for one tool its manifest marks unavailable."""
    (missing,) = _capabilities(monkeypatch, *requires).unavailable()
    return missing.degradation_reason


def _handle(capabilities: ServerCapabilities, **config: Any) -> ServerHandle:
    handle = ServerHandle("threatintel", MCPServerConfig(enabled=True, **config))
    handle.capabilities = capabilities
    return handle


class TestAnUnsetSetting:
    """Only the manifest's code says a setting is unset; the words never do."""

    def test_a_key_the_manifest_marks_not_configured_is_a_choice(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capabilities = _capabilities(monkeypatch, env("T338_UNSET_A"), env("T338_UNSET_B"))
        (missing,) = capabilities.unavailable()
        assert missing.code == "not_configured"
        handle = _handle(capabilities, env={"T338_UNSET_A": ""}, env_allow=["T338_UNSET_B"])
        unset = handle.not_configured_reasons()
        assert unset == [missing.degradation_reason]
        assert is_operator_choice(missing.degradation_reason, unset)

    def test_the_same_words_with_no_manifest_code_are_a_loss(self) -> None:
        for reason in (
            "server.threatintel.check_hash_unavailable(VIRUSTOTAL_API_KEY is not configured)",
            "server.myvendor.yara_unavailable(yara-python is not configured)",
            "server.myvendor.submit_unavailable(database is not configured)",
        ):
            assert not is_operator_choice(reason), reason
            assert is_loss(reason), reason

    def test_a_key_the_platform_holds_that_never_reached_the_server_is_a_loss(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capabilities = _capabilities(monkeypatch, env("T338_HELD_KEY"))
        assert _handle(capabilities, env={"T338_HELD_KEY": "set"}).not_configured_reasons() == []
        monkeypatch.setenv("T338_HELD_KEY", "set")
        allowed = _handle(capabilities, env_allow=["T338_HELD_KEY"])
        assert allowed.not_configured_reasons() == []

    def test_a_library_not_installed_is_a_loss(self, monkeypatch: pytest.MonkeyPatch) -> None:
        capabilities = _capabilities(monkeypatch, module("t338_no_such_module"))
        (missing,) = capabilities.unavailable()
        assert _handle(capabilities).not_configured_reasons() == []
        assert not is_operator_choice(missing.degradation_reason)

    def test_a_key_unset_beside_a_missing_library_is_a_loss(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capabilities = _capabilities(monkeypatch, env("T338_UNSET_KEY"), module("t338_nope"))
        assert _handle(capabilities, env_allow=["T338_UNSET_KEY"]).not_configured_reasons() == []


def _claimed(server: str, *cells: dict[str, Any]) -> ServerCapabilities:
    parsed = ServerCapabilities.from_payload(server, {"server": server, "tools": list(cells)})
    assert parsed is not None
    return parsed


class TestAManifestThatClaimsALossIsASetting:
    """A server's manifest is held to what the platform knows of that server."""

    def test_a_claim_naming_no_setting_is_a_loss(self) -> None:
        cell = {
            "name": "sandbox_submit",
            "available": False,
            "code": "not_configured",
            "reason": "libvirt is not installed",
        }
        handle = _handle(_claimed("threatintel", cell), env_allow=["ANY_KEY"])
        assert handle.not_configured_reasons() == []

    def test_a_claim_naming_a_setting_the_platform_never_supplies_is_a_loss(self) -> None:
        cell = {
            "name": "yara",
            "available": False,
            "code": "not_configured",
            "reason": "YARA_X_UNUSED is not configured",
            "optional_dependency": "YARA_X_UNUSED",
        }
        assert _handle(_claimed("threatintel", cell)).not_configured_reasons() == []
        allowed = _handle(_claimed("threatintel", cell), env_allow=["YARA_X_UNUSED"])
        assert len(allowed.not_configured_reasons()) == 1

    def test_a_claim_whose_reason_is_not_the_probe_s_words_is_a_loss(self) -> None:
        cell = {
            "name": "yara",
            "available": False,
            "code": "not_configured",
            "reason": "yara-python missing",
            "optional_dependency": "YARA_KEY",
        }
        assert (
            _handle(_claimed("threatintel", cell), env_allow=["YARA_KEY"]).not_configured_reasons()
            == []
        )

    def test_a_manifest_naming_another_server_speaks_only_for_its_own(self) -> None:
        """A server answering as "analysis" cannot make analysis's capa loss a choice."""
        payload = {
            "server": "analysis",
            "tools": [
                {
                    "name": "capa",
                    "available": False,
                    "code": "not_configured",
                    "reason": "CAPA_KEY is not configured",
                    "optional_dependency": "CAPA_KEY",
                }
            ],
        }
        spoof = ServerHandle("myvendor", MCPServerConfig(enabled=True, env_allow=["CAPA_KEY"]))
        spoof._keep_capabilities(payload)
        assert spoof.capabilities is not None and spoof.capabilities.server == "myvendor"
        claimed = spoof.not_configured_reasons()
        assert claimed and all(r.startswith("server.myvendor.capa_unavailable(") for r in claimed)
        real = "server.analysis.capa_unavailable(capa is not installed (No module named 'capa'))"
        assert not is_operator_choice(real, claimed)
        assert is_loss(real, not_configured=claimed)


class TestAToolASharedServerWithholds:
    @pytest.mark.parametrize("why", [UNCOVERED, LISTED_SHARED_WITHHELD])
    def test_its_configured_policy_is_a_choice(self, why: str) -> None:
        assert is_operator_choice(withheld_unpinned(_SHARED, "close_program", why))

    @pytest.mark.parametrize(
        "why",
        [UNREAD_SCHEMA, NO_NOTE, "it could not be wrapped to carry the job's program (TypeError)"],
    )
    def test_a_failure_to_hold_it_to_the_job_is_a_loss(self, why: str) -> None:
        assert not is_operator_choice(withheld_unpinned(_SHARED, "list_functions", why))


class TestAReferencedTool:
    def _unavailable(self, name: str = "check_hash") -> str:
        return AGENT_TOOL_UNAVAILABLE_REASON.format(server="threatintel", name=name)

    def test_a_server_switched_off_is_a_choice(self) -> None:
        assert is_operator_choice(f"{self._unavailable('*')}: {SERVER_DISABLED}")

    def test_one_withheld_by_policy_is_a_choice(self) -> None:
        withheld = withheld_unpinned(_SHARED, "open_project", UNCOVERED)
        assert is_operator_choice(f"{self._unavailable('open_project')}: {withheld}")

    def test_one_whose_key_the_manifest_marks_unset_is_a_choice(self) -> None:
        unset = "server.threatintel.check_hash_unavailable(VIRUSTOTAL_API_KEY is not configured)"
        assert is_operator_choice(f"{self._unavailable()}: {unset}", [unset])
        assert not is_operator_choice(f"{self._unavailable()}: {unset}")

    def test_one_not_offered_at_all_is_a_loss(self) -> None:
        assert not is_operator_choice(self._unavailable())


@pytest.mark.parametrize(
    "reason",
    [
        "triage.capa_failed",
        "mcp server 'analysis' unavailable",
        "no sandbox report (dynamic detonation unavailable) — static-only evidence",
        "judge failed (TimeoutError)",
        "",
    ],
)
def test_every_other_reason_stays_a_degradation(reason: str) -> None:
    assert not is_operator_choice(reason)


def test_the_split_keeps_each_list_in_the_run_s_order(monkeypatch: pytest.MonkeyPatch) -> None:
    unset = _manifest_reason(monkeypatch, env("T338_UNSET_KEY"))
    withheld = withheld_unpinned(_SHARED, "create_project", UNCOVERED)
    reasons = ["triage.capa_failed", unset, "judge failed (TimeoutError)", withheld]
    assert split_operator_choices(reasons, [unset]) == (
        ["triage.capa_failed", "judge failed (TimeoutError)"],
        [unset, withheld],
    )


# What the registry records for archive_list on a host without py7zr.
_ARCHIVE_PARTIAL = (
    "server.analysis.archive_list_unavailable(py7zr is not installed (No module named "
    "'py7zr')); still answers zip and tar members; 7z needs py7zr; install the optional tool "
    "libraries on the host that runs this server: uv sync --extra tools"
)
_MACHO = "server.analysis.macho_info_unavailable(macholib is not installed); install"


def _facts(file_type: str = "", **kwargs: Any) -> SampleFacts:
    return SampleFacts(file_type=file_type, **kwargs)


class TestAPartialAnswer:
    """A tool that still answers part loses a sample nothing only outside what it lacks."""

    def test_it_is_no_loss_where_the_missing_part_is_not_the_sample_s(self) -> None:
        for routed in ("pe", "zip", "elf"):
            assert run_is_degraded([_ARCHIVE_PARTIAL], facts=_facts(routed)) is False, routed
            assert lost_tools([_ARCHIVE_PARTIAL], _facts(routed)) == [], routed

    def test_it_is_a_loss_on_the_format_the_missing_part_reads(self) -> None:
        assert run_is_degraded([_ARCHIVE_PARTIAL], facts=_facts("7z")) is True
        assert lost_tools([_ARCHIVE_PARTIAL], _facts("7z")) == ["archive_list"]

    def test_it_is_a_loss_when_the_run_holds_no_format_fact(self) -> None:
        assert run_is_degraded([_ARCHIVE_PARTIAL]) is True
        assert run_is_degraded([_ARCHIVE_PARTIAL], facts=_facts("unknown")) is True
        assert lost_tools([_ARCHIVE_PARTIAL]) == ["archive_list"]

    def test_it_is_a_loss_when_the_tool_answered_the_run_short_of_its_library(self) -> None:
        """A 7z carved out of a PE: the top-level format says nothing of it."""
        failed = {
            "tool": "archive_list",
            "ok": False,
            "error": "py7zr is not installed (No module named 'py7zr')",
            "structured": {"error": {"code": "missing_dependency", "message": "py7zr"}},
        }
        from maljan.tools.errors import answered_short_of_a_library

        assert answered_short_of_a_library("archive_list", [failed])
        assert not answered_short_of_a_library("archive_list", [{**failed, "ok": True}])
        assert not answered_short_of_a_library("strings", [failed])
        facts = _facts("pe", failures=(failed,))
        assert run_is_degraded([_ARCHIVE_PARTIAL], facts=facts) is True
        assert lost_tools([_ARCHIVE_PARTIAL], facts) == ["archive_list"]

    def test_the_job_s_own_manifest_says_what_the_missing_part_reads(self) -> None:
        reads = {("analysis", "archive_list"): frozenset({"zip"})}
        assert run_is_degraded([_ARCHIVE_PARTIAL], facts=_facts("zip", without_reads=reads))
        assert not run_is_degraded([_ARCHIVE_PARTIAL], facts=_facts("7z", without_reads=reads))

    def test_a_tool_that_declares_nothing_of_its_missing_part_is_a_loss_where_it_applies(
        self,
    ) -> None:
        assert run_is_degraded(["triage.apk_info_degraded"], facts=_facts("apk")) is True
        assert lost_tools(["triage.apk_info_degraded"], _facts("apk")) == ["apk_info"]

    def test_the_manifest_carries_what_the_missing_part_reads(self) -> None:
        payload = manifest(
            "analysis",
            [ToolNeeds("x", (module("t338_no_such_module"),), without="y", without_reads=("7z",))],
            version="t",
        )
        assert payload["tools"][0]["without_reads"] == ["7z"]
        assert payload["tools"][0]["code"] == "missing_dependency"


class TestAToolForAnotherFormat:
    """A parser the sample's known format never calls on cost the sample nothing."""

    def test_it_neither_degrades_the_run_nor_is_named(self) -> None:
        for reason in (_MACHO, "triage.apk_info_degraded", "triage.macho_info_failed"):
            assert run_is_degraded([reason], facts=_facts("pe")) is False, reason
            assert lost_tools([reason], _facts("pe")) == [], reason

    def test_on_its_own_format_or_an_unknown_one_it_is_a_named_loss(self) -> None:
        for facts in (_facts("mach-o"), _facts(), _facts("unknown")):
            assert run_is_degraded([_MACHO], facts=facts) is True
            assert lost_tools([_MACHO], facts) == ["macho_info"]


# Every kind of reason a run carries, for the invariant below, with the tool
# each names (``None`` for a loss that is no tool's).
_EVERY_KIND: list[tuple[str, str | None]] = [
    ("triage.capa_failed", "capa"),
    ("triage.apk_info_degraded", "apk_info"),
    ("triage.macho_info_failed", "macho_info"),
    (_MACHO, "macho_info"),
    (_ARCHIVE_PARTIAL, "archive_list"),
    ("server.analysis.capa_unavailable(capa is not installed); install", "capa"),
    (
        "server.threatintel.check_hash_unavailable(VIRUSTOTAL_API_KEY is not configured)",
        "check_hash",
    ),
    (withheld_unpinned(_SHARED, "open_project", UNCOVERED), "open_project"),
    (withheld_unpinned(_SHARED, "list_functions", UNREAD_SCHEMA), "list_functions"),
    ("agent tool 'ghidra.*' unavailable: server disabled", "ghidra"),
    ("agent tool 'ghidra.decompile' unavailable", "decompile"),
    ("mcp server 'analysis' unavailable", None),
    ("analyst failures: static", None),
    ("packet capture not fetched (HTTP 502)", None),
]
_GENERIC = "this run had less evidence than a full analysis"


def _header(reasons: list[str], facts: SampleFacts) -> str:
    from maljan.pipeline.operator_choice import facts_record
    from maljan.reporting.models import MalwareReport
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    kept = facts_record(facts)
    report = MalwareReport.model_validate(
        {
            "verdict": "Malware",
            "overall_confidence": 0.5,
            "identity": {"hashes": {"sha256": "e" * 64}, "file_type": facts.file_type or "unknown"},
            "degraded_mode": run_is_degraded(reasons, facts=facts),
            "degradation_reasons": reasons,
            "run_summary": {"loss_facts": kept} if kept else {},
        }
    )
    rendered = MarkdownRenderer().render(report)
    return next((line for line in rendered.splitlines() if "[DEGRADED RUN]" in line), "")


@pytest.mark.parametrize("file_type", ["", "pe", "zip", "7z", "apk", "mach-o"])
def test_a_degraded_header_names_every_tool_the_run_lost(file_type: str) -> None:
    """Read off the rendered header: never the generic sentence while a tool was lost."""
    from itertools import combinations

    facts = _facts(file_type)
    for size in (1, 2):
        for pairs in combinations(_EVERY_KIND, size):
            reasons = [reason for reason, _tool in pairs]
            header = _header(reasons, facts)
            lost = [tool for reason, tool in pairs if tool and is_loss(reason, facts)]
            if not run_is_degraded(reasons, facts=facts):
                assert not header and not lost, reasons
                continue
            assert header, reasons
            for tool in lost:
                assert tool in header, (reasons, header)
            if lost:
                assert _GENERIC not in header.lower(), (reasons, header)


def test_the_header_reads_the_facts_the_judge_kept() -> None:
    """A 7z carved from a PE: the summary keeps the failed call, and the header names the tool."""
    from maljan.tools.errors import short_of_a_library_rows

    failed = {"tool": "archive_list", "ok": False, "error": "py7zr is not installed"}
    facts = _facts("pe", failures=(failed,))
    assert short_of_a_library_rows([failed]) == [
        {"tool": "archive_list", "code": "missing_dependency"}
    ]
    assert "archive_list" in _header([_ARCHIVE_PARTIAL], facts)
    assert _header([_ARCHIVE_PARTIAL], _facts("pe")) == ""


class TestTheJudgesParagraph:
    def test_a_run_with_only_choices_is_told_them_as_absences(self) -> None:
        from maljan.pipeline.nodes import RUN_QUALITY_CHOICES, run_quality_note

        note = run_quality_note([], degraded=False, choices=["a key never set"])
        assert note == f"RUN QUALITY — {RUN_QUALITY_CHOICES} a key never set."

    def test_no_choice_leaves_the_paragraph_as_it_was(self) -> None:
        from maljan.pipeline.nodes import run_quality_note

        assert run_quality_note([], degraded=False) == ""
        assert run_quality_note(["a reason"], degraded=True) == run_quality_note(
            ["a reason"], degraded=True, choices=()
        )


class TestTheToolsARunWentWithout:
    def test_a_failed_pack_tool_and_a_missing_library_are_named_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing = _manifest_reason(monkeypatch, module("t338_no_such_module"))
        assert lost_tools(["triage.capa_failed", missing, "triage.check_hash_failed"]) == [
            "capa",
            "check_hash",
        ]

    def test_a_choice_is_not_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        unset = _manifest_reason(monkeypatch, env("T338_UNSET_KEY"))
        assert lost_tools([unset], not_configured=[unset]) == []
        assert lost_tools([withheld_unpinned(_SHARED, "open_project", UNCOVERED)]) == []
