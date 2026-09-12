"""What each sandbox is asked for depends on what the sample is.

A CAPE task created without a package detonates an APK with the Windows
executable analyser and reports nothing, and a report of nothing is
indistinguishable from a benign sample. Every provider therefore resolves the
sample's format first and asks for the package, guest or profile that format
needs — and asks for nothing at all when the operator configured nothing, which
is the behaviour that existed before.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from maljan.core.config import Settings
from maljan.loaders.cape2_client import CAPEv2Client
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider
from maljan.providers.sandbox.formats import cape_platform, detect_sample_format, option_for_format
from maljan.providers.sandbox.rest import RestSandboxProvider
from maljan.providers.sandbox.triage import TriageSandboxProvider


def _pe(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ" + b"\x00" * 64)
    return path


def _apk(tmp_path: Path) -> Path:
    path = tmp_path / "sample.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "x")
    return path


def _elf(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return path


# ---------------------------------------------------------------------------
# The shared resolution helpers
# ---------------------------------------------------------------------------
class TestFormatResolution:
    def test_the_detected_format_travels_with_the_sample(self, tmp_path: Path) -> None:
        assert detect_sample_format(_apk(tmp_path)) == ("apk", "android")
        assert detect_sample_format(_elf(tmp_path)) == ("elf", "linux")

    def test_an_unreadable_sample_resolves_to_nothing(self, tmp_path: Path) -> None:
        assert detect_sample_format(tmp_path / "absent.bin") == ("unknown", "unknown")

    def test_an_exact_entry_beats_the_fallback(self) -> None:
        options = {"apk": "apk", "*": "generic"}
        assert option_for_format(options, "apk") == "apk"
        assert option_for_format(options, "elf") == "generic"

    def test_no_entry_and_no_fallback_asks_for_nothing(self) -> None:
        assert option_for_format({}, "apk") == ""
        assert option_for_format({"elf": "generic"}, "apk") == ""

    def test_the_caller_supplied_fallback_is_last(self) -> None:
        assert option_for_format({"elf": "generic"}, "apk", "default-profile") == "default-profile"

    @pytest.mark.parametrize(
        ("platform", "expected"),
        [
            ("windows", "windows"),
            ("linux", "linux"),
            ("android", "android"),
            ("macos", ""),
            ("ios", ""),
            ("multi", ""),
            ("unknown", ""),
        ],
    )
    def test_only_the_guests_cape_names_are_sent(self, platform: str, expected: str) -> None:
        assert cape_platform(platform) == expected


# ---------------------------------------------------------------------------
# CAPEv2
# ---------------------------------------------------------------------------
def _cape_client(tmp_path: Path, captured: list[httpx.Request]) -> CAPEv2Client:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"error": False, "data": {"task_ids": [7]}})

    client = CAPEv2Client(base_url="https://cape.example")
    client._http = httpx.Client(
        base_url="https://cape.example", transport=httpx.MockTransport(handler)
    )
    return client


def _form_fields(request: httpx.Request) -> dict[str, str]:
    """The non-file multipart fields of a captured submission."""
    body = request.content.decode("utf-8", "replace")
    fields: dict[str, str] = {}
    for part in body.split("--" + request.headers["content-type"].split("boundary=")[1]):
        if 'name="' not in part or "filename=" in part:
            continue
        name = part.split('name="', 1)[1].split('"', 1)[0]
        value = part.split("\r\n\r\n", 1)[1].rsplit("\r\n", 1)[0]
        fields[name] = value
    return fields


class TestCape2Submit:
    def test_an_unset_field_is_not_sent_at_all(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        client = _cape_client(tmp_path, captured)
        assert client.submit(_pe(tmp_path)) == "7"
        assert _form_fields(captured[0]) == {}

    def test_only_the_fields_that_were_set_are_sent(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        client = _cape_client(tmp_path, captured)
        client.submit(
            _pe(tmp_path),
            package="apk",
            platform="android",
            machine=None,
            tags="",
            options="procmemdump=1",
            timeout=120,
        )
        assert _form_fields(captured[0]) == {
            "package": "apk",
            "platform": "android",
            "options": "procmemdump=1",
            "timeout": "120",
        }

    def test_extra_fields_ride_along_verbatim(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        client = _cape_client(tmp_path, captured)
        client.submit(_pe(tmp_path), extra_fields={"route": "internet", "empty": ""})
        assert _form_fields(captured[0]) == {"route": "internet"}


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def submit(self, sample_path, **kwargs):
        self.calls.append({"sample_path": str(sample_path), **kwargs})
        return "7"


class TestCape2Provider:
    def _provider(self, **over) -> tuple[CAPE2SandboxProvider, _RecordingClient]:
        cfg = Settings(_env_file=None)
        for key, value in over.items():
            setattr(cfg.sandbox.cape2, key, value)
        provider = CAPE2SandboxProvider.from_settings(cfg)
        client = _RecordingClient()
        provider._client = client
        return provider, client

    def test_the_package_comes_from_the_samples_format(self, tmp_path: Path) -> None:
        provider, client = self._provider(package_by_format={"apk": "apk", "*": "generic"})
        provider.submit(_apk(tmp_path))
        assert client.calls[0]["package"] == "apk"
        assert client.calls[0]["platform"] == "android"

    def test_an_unnamed_format_takes_the_fallback_package(self, tmp_path: Path) -> None:
        provider, client = self._provider(package_by_format={"apk": "apk", "*": "generic"})
        provider.submit(_elf(tmp_path))
        assert client.calls[0]["package"] == "generic"
        assert client.calls[0]["platform"] == "linux"

    def test_nothing_configured_asks_cape_for_nothing(self, tmp_path: Path) -> None:
        provider, client = self._provider()
        provider.submit(_pe(tmp_path))
        assert client.calls[0]["package"] is None
        assert client.calls[0]["platform"] == "windows"

    def test_a_guest_cape_cannot_name_is_left_unset(self, tmp_path: Path) -> None:
        macho = tmp_path / "sample.bin"
        macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
        provider, client = self._provider()
        provider.submit(macho)
        assert client.calls[0]["platform"] is None

    def test_submit_options_are_passed_through(self, tmp_path: Path) -> None:
        provider, client = self._provider(submit_options={"route": "internet"})
        provider.submit(_pe(tmp_path))
        assert client.calls[0]["extra_fields"] == {"route": "internet"}


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------
class TestTriageProfileSelection:
    def _submitted_profiles(self, tmp_path: Path, sample: Path, **over) -> list[dict]:
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = request.content.decode("utf-8", "replace")
            seen.append(body)
            return httpx.Response(200, json={"id": "250101-abcde"})

        cfg = Settings(_env_file=None)
        cfg.sandbox.provider = "triage"
        cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
        for key, value in over.items():
            setattr(cfg.sandbox.triage, key, value)
        provider = TriageSandboxProvider.from_settings(cfg)
        provider._http = httpx.Client(
            base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
        )
        provider.submit(sample)
        return seen

    def test_the_profile_follows_the_format(self, tmp_path: Path) -> None:
        body = self._submitted_profiles(
            tmp_path,
            _apk(tmp_path),
            profile="win10",
            profile_by_format={"apk": "android13"},
        )[0]
        assert "android13" in body
        assert "win10" not in body

    def test_an_unnamed_format_keeps_the_configured_default(self, tmp_path: Path) -> None:
        body = self._submitted_profiles(
            tmp_path,
            _pe(tmp_path),
            profile="win10",
            profile_by_format={"apk": "android13"},
        )[0]
        assert "win10" in body

    def test_no_profile_anywhere_sends_no_profiles_block(self, tmp_path: Path) -> None:
        body = self._submitted_profiles(tmp_path, _pe(tmp_path))[0]
        assert "profiles" not in body


# ---------------------------------------------------------------------------
# The REST DSL
# ---------------------------------------------------------------------------
class TestRestSubmitFields:
    def _submit(self, tmp_path: Path, **submit_over) -> dict[str, str]:
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"id": "77"})

        cfg = Settings(_env_file=None)
        cfg.sandbox.provider = "rest"
        cfg.sandbox.rest.base_url = "https://xyz.example/api"
        for key, value in submit_over.items():
            setattr(cfg.sandbox.rest.submit, key, value)
        provider = RestSandboxProvider.from_settings(cfg)
        provider._http = httpx.Client(
            base_url="https://xyz.example/api", transport=httpx.MockTransport(handler)
        )
        provider.submit(_pe(tmp_path))
        return _form_fields(captured[0])

    def test_submit_fields_are_sent_verbatim(self, tmp_path: Path) -> None:
        assert self._submit(tmp_path, submit_fields={"package": "exe"}) == {"package": "exe"}

    def test_they_sit_beside_the_existing_extra_fields(self, tmp_path: Path) -> None:
        fields = self._submit(
            tmp_path,
            extra_fields={"tenant": "blue"},
            submit_fields={"package": "exe"},
        )
        assert fields == {"tenant": "blue", "package": "exe"}

    def test_nothing_configured_sends_no_extra_fields(self, tmp_path: Path) -> None:
        assert self._submit(tmp_path) == {}
