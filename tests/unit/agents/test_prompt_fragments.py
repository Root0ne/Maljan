"""An analyst is told about the artefacts its sample actually has.

The built-in prompts named Windows artefacts in their constant text, so an
analyst handed an APK was asked to cite a registry key. It either invented one
or reported nothing, and neither is analysis. The platform-specific half now
comes from the sample's own format.
"""

from __future__ import annotations

import pytest

from maljan.agents.composition import builtin_prompt, sample_format
from maljan.agents.prompt_fragments import format_fragment


class TestTheFragmentPerPlatform:
    @pytest.mark.parametrize(
        ("file_type", "platform", "expected"),
        [
            ("pe", "windows", "registry"),
            ("elf", "linux", "systemd"),
            ("mach-o", "macos", "launchd"),
            ("apk", "android", "receivers"),
            ("dex", "android", "permissions"),
            ("ipa", "ios", "entitlements"),
            ("jar", "multi", "JVM"),
            ("ole2", "multi", "macro"),
            ("ooxml", "multi", "macro"),
            ("pdf", "multi", "OpenAction"),
            ("ps1", "windows", "obfuscation"),
            ("sh", "linux", "obfuscation"),
            ("7z", "unknown", "archive"),
            ("unknown", "unknown", "not identified"),
        ],
    )
    def test_each_format_names_its_own_artefacts(
        self, file_type: str, platform: str, expected: str
    ) -> None:
        assert expected in format_fragment(file_type, platform)

    def test_the_fragment_is_never_empty(self) -> None:
        assert format_fragment("", "").strip()
        assert format_fragment("nonsense", "nonsense").strip()

    def test_a_windows_fragment_does_not_reach_a_non_windows_sample(self) -> None:
        for file_type, platform in (("apk", "android"), ("elf", "linux"), ("mach-o", "macos")):
            assert "registry" not in format_fragment(file_type, platform).lower()

    def test_a_script_keeps_its_hosts_artefacts_too(self) -> None:
        fragment = format_fragment("ps1", "windows")
        assert "obfuscation" in fragment
        assert "registry" in fragment


class _Provider:
    def prompt_fragment(self) -> str:
        return "PROVIDER-FRAGMENT"


class _Container:
    def __init__(self, fmt: tuple[str, str] | None = None) -> None:
        if fmt is not None:
            self.sample_format = fmt

    def get_static_provider(self, provider_id: str | None = None) -> _Provider:
        return _Provider()


class TestTheAssembledPrompt:
    @pytest.mark.parametrize("role", ["static", "dynamic", "network"])
    def test_the_format_fragment_is_in_every_built_in_prompt(self, role: str) -> None:
        prompt = builtin_prompt(role, _Container(("apk", "android")), "ghidra")
        assert format_fragment("apk", "android") in prompt

    def test_the_static_assembly_keeps_head_fragment_provider_order(self) -> None:
        from maljan.agents.static_analyst import _ISR_HEAD

        prompt = builtin_prompt("static", _Container(("elf", "linux")), "ghidra")
        assert prompt.index(_ISR_HEAD) == 0
        assert prompt.index(format_fragment("elf", "linux")) < prompt.index("PROVIDER-FRAGMENT")

    def test_a_container_that_was_never_told_gets_the_neutral_fragment(self) -> None:
        prompt = builtin_prompt("network", _Container(), "ghidra")
        assert format_fragment("unknown", "unknown") in prompt

    def test_the_sample_format_reader_tolerates_a_container_without_one(self) -> None:
        assert sample_format(_Container()) == ("unknown", "unknown")
        assert sample_format(_Container(("apk", "android"))) == ("apk", "android")
