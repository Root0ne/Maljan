"""A claim's code locations are read by the prefixes the deployment's sources declare (T-426).

Which names in a claim are code locations (``reporting.claim_coverage``) was a
pattern of five prefixes written in the module, so a decompiler whose server
declares its own prefixes (``auto_name_prefixes``) had its names read as words,
and a datum's label (``DAT_``) was read only because it was written there. The
pattern is now built from what every enabled source declares, for a function
(``auto_name_prefixes``) and for a datum (``data_label_prefixes``, a new
declaration field the Ghidra block sets to ``DAT_``), with the prefixes the
platform has always read: a server nobody has seen, whose decompiler writes
its own prefixes, is read as a built-in one is.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from maljan.core import undeclared_tools
from maljan.core.config import Settings
from maljan.core.declared_reading import declarations
from maljan.reporting.claim_coverage import claims_not_discussed, code_names
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

_IDENTITY = SampleIdentity(hashes=FileHashes(sha256="a" * 64))


def _report(text: str) -> MalwareReport:
    return MalwareReport(identity=_IDENTITY, executive_summary=text)


def _isrs(agent: str, *claims: str) -> dict[str, Any]:
    rows = [
        SimpleNamespace(claim=text, evidence_ref="[ev_0001]", confidence=0.8) for text in claims
    ]
    return {agent: SimpleNamespace(agent_id=agent, claims=rows)}


def _settings(**server: Any) -> Settings:
    return Settings.model_validate(
        {"mcp": {"servers": {"acme": {"command": "x", "enabled": True, **server}}}}
    )


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Make the given settings the ones every reader without settings reads."""

    def install(settings: Settings) -> Settings:
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: settings)
        return settings

    return install


def _addresses(text: str) -> list[str]:
    return [said for (what, _), said in code_names(text).items() if what == "address"]


class TestTheShippedPrefixes:
    def test_every_prefix_dev_read_is_still_read(self) -> None:
        text = "FUN_00401000 fcn.0x00402000 sub_00403000 LAB_00404000 DAT_00405000"
        assert _addresses(text) == text.split()

    def test_the_data_label_prefix_is_declared_by_the_ghidra_block_and_shipped(self) -> None:
        held = declarations(Settings())
        assert held.source("provider:ghidra").data_label_prefixes == ("DAT_",)
        assert undeclared_tools.DEFAULT_DATA_LABEL_PREFIXES == ("DAT_",)

    def test_a_prefix_is_read_with_its_own_separator(self) -> None:
        # ``func.`` and ``loc.`` are prefixes; a model's ``func_`` is not one.
        assert _addresses("func.00401000 loc.00402000") == ["func.00401000", "loc.00402000"]
        assert _addresses("func_0x01360bc09040 loc_3ccf0") == []

    def test_a_datum_s_label_is_never_a_function_s_name(self) -> None:
        assert not undeclared_tools.declared_auto_name_pattern(Settings()).fullmatch("DAT_00405000")


class TestADeclaredPrefix:
    def test_a_function_prefix_a_server_declares_is_a_code_location(self, installed: Any) -> None:
        assert _addresses("proc_00401000") == []
        installed(_settings(auto_name_prefixes=["PROC_"]))
        assert _addresses("proc_00401000 PROC_00402000") == ["proc_00401000", "PROC_00402000"]

    def test_a_data_prefix_a_server_declares_is_a_code_location(self, installed: Any) -> None:
        assert _addresses("mem_00405000") == []
        installed(_settings(data_label_prefixes=["MEM_"]))
        assert _addresses("MEM_00405000") == ["MEM_00405000"]
        # Never a function's name.
        assert not undeclared_tools.declared_auto_name_pattern().fullmatch("MEM_00405000")

    def test_a_disabled_server_s_prefix_is_not_read(self, installed: Any) -> None:
        installed(_settings(enabled=False, data_label_prefixes=["MEM_"]))
        assert _addresses("MEM_00405000") == []

    def test_a_data_label_prefix_is_a_prefix(self) -> None:
        with pytest.raises(ValueError, match="data_label_prefixes"):
            _settings(data_label_prefixes=["DAT"])


class TestANeverSeenServerIsReadAsABuiltInIs:
    """A server nobody declared before, whose tools and prefixes are its own, gets the same list."""

    def test_its_claims_are_listed_as_a_ghidra_claim_is(self, installed: Any) -> None:
        body = _report("The routine at 0x401000 decodes the table at 0x405000.")
        built_in = _isrs("static", "FUN_00401000 decodes DAT_00405000; FUN_00409000 sends it.")
        installed(_settings(auto_name_prefixes=["proc_"], data_label_prefixes=["mem_"]))
        renamed = _isrs("acme", "proc_00401000 decodes mem_00405000; proc_00409000 sends it.")

        (one,) = claims_not_discussed(body, built_in)
        (other,) = claims_not_discussed(body, renamed)
        assert one.missing == ["FUN_00409000"]
        assert other.missing == ["proc_00409000"]

    def test_a_claim_that_names_every_place_the_body_names_is_not_listed(
        self, installed: Any
    ) -> None:
        installed(_settings(auto_name_prefixes=["proc_"], data_label_prefixes=["mem_"]))
        body = _report("0x401000 reads 0x405000.")
        assert claims_not_discussed(body, _isrs("acme", "proc_00401000 reads mem_00405000.")) == []
