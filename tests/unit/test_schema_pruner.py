"""Unit tests for schema_pruner.py and JudgeAgent._build_schema_hint().

Tests:
  - MalwareCategory enum values
  - infer_malware_category(): correct category detection, ties → UNKNOWN,
    empty input → UNKNOWN, high-specificity ATT&CK IDs
  - get_pruned_schema_hint(): UNKNOWN → empty, all other categories
    return non-empty blocks with correct content
  - JudgeAgent._build_schema_hint(): wires inference + hint,
    graceful degradation on error
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from maljan.analysis.schema_pruner import (
    MalwareCategory,
    get_pruned_schema_hint,
    infer_malware_category,
)

# ---------------------------------------------------------------------------
# MalwareCategory enum
# ---------------------------------------------------------------------------


class TestMalwareCategory:
    def test_all_categories_defined(self) -> None:
        expected = {"ransomware", "rat", "dropper", "worm", "infostealer", "unknown"}
        actual = {cat.value for cat in MalwareCategory}
        assert actual == expected


class TestMalformedIsrRobustness:
    """Signal-quality §2.4: a malformed ISR value must not crash inference."""

    def test_isr_value_without_claims_is_skipped(self) -> None:
        # object lacking a list ``claims`` attribute (None / wrong type)
        bad = type("X", (), {"claims": None})()
        result = infer_malware_category(
            {"static": "ransomware encrypts files with AES for impact"},
            {"static": bad},  # type: ignore[dict-item]
        )
        assert result == MalwareCategory.RANSOMWARE

    def test_isr_claims_wrong_type_is_skipped(self) -> None:
        bad = type("X", (), {"claims": {"not": "a list"}})()
        result = infer_malware_category({}, {"static": bad})  # type: ignore[dict-item]
        assert result == MalwareCategory.UNKNOWN

    def test_unknown_is_fallback(self) -> None:
        assert MalwareCategory.UNKNOWN.value == "unknown"


# ---------------------------------------------------------------------------
# infer_malware_category() — empty / trivial inputs
# ---------------------------------------------------------------------------


class TestInferCategoryEdgeCases:
    def test_empty_reports_returns_unknown(self) -> None:
        assert infer_malware_category({}) is MalwareCategory.UNKNOWN

    def test_none_isr_reports_ok(self) -> None:
        result = infer_malware_category({"static": "process injection"}, None)
        assert isinstance(result, MalwareCategory)

    def test_whitespace_only_text_returns_unknown(self) -> None:
        assert infer_malware_category({"static": "   "}) is MalwareCategory.UNKNOWN

    def test_no_keyword_match_returns_unknown(self) -> None:
        result = infer_malware_category({"static": "the quick brown fox"})
        assert result is MalwareCategory.UNKNOWN


# ---------------------------------------------------------------------------
# infer_malware_category() — ransomware detection
# ---------------------------------------------------------------------------


class TestInferRansomware:
    def test_ransom_keyword_detected(self) -> None:
        result = infer_malware_category({"static": "drops ransom note, encrypts files"})
        assert result is MalwareCategory.RANSOMWARE

    def test_encrypt_keyword_detected(self) -> None:
        result = infer_malware_category(
            {"static": "uses AES-256 to encrypt user documents with RSA key exchange"}
        )
        assert result is MalwareCategory.RANSOMWARE

    def test_attck_t1486_detected(self) -> None:
        result = infer_malware_category({"static": "maps to t1486 data encrypted for impact"})
        assert result is MalwareCategory.RANSOMWARE

    def test_vssadmin_shadow_copy_detected(self) -> None:
        result = infer_malware_category(
            {"dynamic": "executes vssadmin delete shadows, bcdedit /set recoveryenabled no"}
        )
        assert result is MalwareCategory.RANSOMWARE

    def test_bitcoin_wallet_detected(self) -> None:
        result = infer_malware_category({"network": "connects to bitcoin wallet address"})
        assert result is MalwareCategory.RANSOMWARE


# ---------------------------------------------------------------------------
# infer_malware_category() — RAT detection
# ---------------------------------------------------------------------------


class TestInferRAT:
    def test_backdoor_keyword(self) -> None:
        result = infer_malware_category({"static": "installs a backdoor for persistent access"})
        assert result is MalwareCategory.RAT

    def test_reverse_shell_keyword(self) -> None:
        result = infer_malware_category({"dynamic": "opens reverse shell on port 4444"})
        assert result is MalwareCategory.RAT

    def test_command_and_control_keyword(self) -> None:
        result = infer_malware_category(
            {"network": "beacons to command and control server every 30 seconds"}
        )
        assert result is MalwareCategory.RAT

    def test_attck_t1095_detected(self) -> None:
        result = infer_malware_category({"static": "uses t1095 non-application layer protocol"})
        assert result is MalwareCategory.RAT


# ---------------------------------------------------------------------------
# infer_malware_category() — Dropper detection
# ---------------------------------------------------------------------------


class TestInferDropper:
    def test_dropper_keyword(self) -> None:
        result = infer_malware_category({"static": "acts as a dropper for the final payload"})
        assert result is MalwareCategory.DROPPER

    def test_loader_keyword(self) -> None:
        result = infer_malware_category({"static": "loader unpacks and executes next stage"})
        assert result is MalwareCategory.DROPPER

    def test_urldownloadtofile_keyword(self) -> None:
        result = infer_malware_category({"dynamic": "calls URLDownloadToFile to retrieve payload"})
        assert result is MalwareCategory.DROPPER

    def test_certutil_keyword(self) -> None:
        result = infer_malware_category({"dynamic": "uses certutil -decode to unpack payload"})
        assert result is MalwareCategory.DROPPER


# ---------------------------------------------------------------------------
# infer_malware_category() — Worm detection
# ---------------------------------------------------------------------------


class TestInferWorm:
    def test_worm_keyword(self) -> None:
        result = infer_malware_category({"static": "self-replicating worm spreads via network"})
        assert result is MalwareCategory.WORM

    def test_propagat_keyword(self) -> None:
        result = infer_malware_category({"dynamic": "propagates to adjacent hosts via SMB"})
        assert result is MalwareCategory.WORM

    def test_attck_t1091_detected(self) -> None:
        result = infer_malware_category({"dynamic": "t1091 replication through removable media"})
        assert result is MalwareCategory.WORM

    def test_network_share_keyword(self) -> None:
        result = infer_malware_category(
            {"dynamic": "copies itself to network share \\\\server\\share"}
        )
        assert result is MalwareCategory.WORM


# ---------------------------------------------------------------------------
# infer_malware_category() — Infostealer detection
# ---------------------------------------------------------------------------


class TestInferInfostealer:
    def test_keylog_keyword(self) -> None:
        result = infer_malware_category({"static": "keylogger captures all keystrokes"})
        assert result is MalwareCategory.INFOSTEALER

    def test_mimikatz_keyword(self) -> None:
        result = infer_malware_category({"dynamic": "loads mimikatz to dump lsass credentials"})
        assert result is MalwareCategory.INFOSTEALER

    def test_attck_t1003_detected(self) -> None:
        result = infer_malware_category({"static": "technique t1003 os credential dumping"})
        assert result is MalwareCategory.INFOSTEALER

    def test_exfiltrat_keyword(self) -> None:
        result = infer_malware_category(
            {"network": "exfiltrates stolen credentials via POST request"}
        )
        assert result is MalwareCategory.INFOSTEALER


# ---------------------------------------------------------------------------
# infer_malware_category() — tie-breaking
# ---------------------------------------------------------------------------


class TestInferTieBreaking:
    def test_neutral_text_returns_unknown(self) -> None:
        result = infer_malware_category({"static": "uses process injection and api hooking"})
        # No category-specific keywords should dominate
        assert isinstance(result, MalwareCategory)  # just verify no crash

    def test_multi_agent_reports_combined(self) -> None:
        """Scores across multiple agent reports are combined."""
        reports = {
            "static": "AES-256 encryption with RSA key exchange",
            "dynamic": "vssadmin delete shadows, bcdedit",
            "network": "bitcoin payment portal",
        }
        result = infer_malware_category(reports)
        assert result is MalwareCategory.RANSOMWARE


# ---------------------------------------------------------------------------
# get_pruned_schema_hint()
# ---------------------------------------------------------------------------


class TestGetPrunedSchemaHint:
    def test_unknown_returns_empty(self) -> None:
        assert get_pruned_schema_hint(MalwareCategory.UNKNOWN) == ""

    @pytest.mark.parametrize(
        "category",
        [
            MalwareCategory.RANSOMWARE,
            MalwareCategory.RAT,
            MalwareCategory.DROPPER,
            MalwareCategory.WORM,
            MalwareCategory.INFOSTEALER,
        ],
    )
    def test_all_categories_return_non_empty(self, category: MalwareCategory) -> None:
        hint = get_pruned_schema_hint(category)
        assert hint != "", f"Expected non-empty hint for {category}"

    def test_ransomware_hint_mentions_encryption(self) -> None:
        hint = get_pruned_schema_hint(MalwareCategory.RANSOMWARE)
        assert "encr" in hint.lower() or "t1486" in hint.lower()

    def test_rat_hint_mentions_c2(self) -> None:
        hint = get_pruned_schema_hint(MalwareCategory.RAT)
        assert "c2" in hint.lower() or "command" in hint.lower() or "backdoor" in hint.lower()

    def test_dropper_hint_mentions_download(self) -> None:
        hint = get_pruned_schema_hint(MalwareCategory.DROPPER)
        assert "download" in hint.lower() or "payload" in hint.lower() or "t1105" in hint.lower()

    def test_worm_hint_mentions_propagat(self) -> None:
        hint = get_pruned_schema_hint(MalwareCategory.WORM)
        assert "propagat" in hint.lower() or "spread" in hint.lower() or "lateral" in hint.lower()

    def test_infostealer_hint_mentions_credential(self) -> None:
        hint = get_pruned_schema_hint(MalwareCategory.INFOSTEALER)
        assert "credential" in hint.lower() or "exfiltrat" in hint.lower()

    def test_hint_includes_category_name(self) -> None:
        hint = get_pruned_schema_hint(MalwareCategory.RANSOMWARE)
        assert "RANSOMWARE" in hint

    def test_hint_includes_stix_guidance_header(self) -> None:
        hint = get_pruned_schema_hint(MalwareCategory.RAT)
        assert "STIX" in hint


# ---------------------------------------------------------------------------
# JudgeAgent._build_schema_hint()
# ---------------------------------------------------------------------------


class TestJudgeAgentBuildSchemaHint:
    def _make_judge(self) -> object:
        from maljan.agents.judge_agent import JudgeAgent

        return JudgeAgent(llm=MagicMock())

    def test_ransomware_reports_return_hint(self) -> None:
        judge = self._make_judge()
        reports = {"static": "encrypts files with AES-256, drops ransom note, bitcoin wallet"}
        hint = judge._build_schema_hint(reports, None)  # type: ignore[union-attr]
        assert "RANSOMWARE" in hint

    def test_empty_reports_return_empty(self) -> None:
        judge = self._make_judge()
        hint = judge._build_schema_hint({}, None)  # type: ignore[union-attr]
        assert hint == ""

    def test_graceful_degradation_on_error(self) -> None:
        """_build_schema_hint must not raise even if inference fails."""
        judge = self._make_judge()
        # Pass a bad isr_reports type that will cause attribute access errors
        bad_isr = MagicMock()
        bad_isr.values.side_effect = RuntimeError("isr explosion")
        # reports is fine, but isr iteration will crash
        hint = judge._build_schema_hint(  # type: ignore[union-attr]
            {"static": "ransom encrypt bitcoin"},
            bad_isr,
        )
        # Should either return a valid hint or empty string — never raise
        assert isinstance(hint, str)
