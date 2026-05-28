"""Unit tests for the tightened J-02 indicator filter (Wave 4)."""

from __future__ import annotations

import pytest

from maljan.agents.judge_postprocess import postprocess_judge_bundle


def _bundle_with(indicators: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000001",
        "objects": indicators,
    }


def _indicator(name: str, pattern: str) -> dict:
    return {
        "type": "indicator",
        "id": "indicator--00000000-0000-0000-0000-000000000002",
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-05-28T00:00:00Z",
    }


# ---------------------------------------------------------------------------
# file:name acceptance
# ---------------------------------------------------------------------------


class TestFileNameAcceptance:
    def test_accepts_path_with_real_extension(self) -> None:
        bundle = _bundle_with([_indicator("payload", "[file:name = '/data/local/tmp/payload.so']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={"payload.so"})
        kept = [o for o in result["objects"] if o.get("type") == "indicator"]
        assert len(kept) == 1

    def test_accepts_path_with_os_prefix(self) -> None:
        bundle = _bundle_with([_indicator("staging", "[file:name = '/sdcard/Download/dropper']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={"dropper"})
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1

    def test_rejects_compile_artefact_path(self) -> None:
        # NDK build path — zararli.apk's #1 noise source.
        ndk_path = (
            "/buildbot/src/android/ndk-r25-release/toolchain/llvm-project/libcxx/include/string"
        )
        bundle = _bundle_with([_indicator("ndk-leak", f"[file:name = '{ndk_path}']")])
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={ndk_path.lower()},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_rejects_android_class_ref(self) -> None:
        # `/lang/ClassCastException` etc. surfaced from .dex strings.
        bundle = _bundle_with(
            [_indicator("class-cast", "[file:name = '/lang/ClassCastException']")]
        )
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"/lang/classcastexception"},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_rejects_random_short_string_path(self) -> None:
        # /I FyD, /urLU4b — random extracted strings that aren't paths.
        bundle = _bundle_with(
            [
                _indicator("noise1", "[file:name = '/I FyD']"),
                _indicator("noise2", "[file:name = '/urLU4b']"),
            ]
        )
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"/i fyd", "/urlu4b"},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_file_name_cap_enforced(self) -> None:
        # Build 15 valid .exe indicators; only 10 should survive.
        inds = [_indicator(f"x{i}", f"[file:name = '/var/tmp/payload{i}.exe']") for i in range(15)]
        bundle = _bundle_with(inds)
        corpus = {f"payload{i}.exe" for i in range(15)}
        result = postprocess_judge_bundle(bundle, evidence_corpus=corpus)
        kept = [o for o in result["objects"] if o.get("type") == "indicator"]
        assert len(kept) == 10


# ---------------------------------------------------------------------------
# URL denylist
# ---------------------------------------------------------------------------


class TestUrlDenylist:
    def test_drops_developer_host(self) -> None:
        bundle = _bundle_with(
            [
                _indicator(
                    "ndk-url",
                    "[url:value = 'https://android.googlesource.com/toolchain/llvm-project']",
                )
            ]
        )
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"https://android.googlesource.com/toolchain/llvm-project"},
        )
        assert [o for o in result["objects"] if o.get("type") == "indicator"] == []

    def test_keeps_arbitrary_c2_url(self) -> None:
        bundle = _bundle_with([_indicator("c2", "[url:value = 'http://evil.example.com/beacon']")])
        result = postprocess_judge_bundle(
            bundle,
            evidence_corpus={"http://evil.example.com/beacon"},
        )
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1


# ---------------------------------------------------------------------------
# Backwards compatibility — non file:name / non url indicators
# ---------------------------------------------------------------------------


class TestLegacyKindsUnchanged:
    def test_hash_indicator_kept_when_in_corpus(self) -> None:
        h = "95236ef71738807ce60ef7d042699decb7156931931682cf46e6ad" + "0" * 10
        bundle = _bundle_with([_indicator("hash", f"[file:hashes.'SHA-256' = '{h}']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={h})
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1

    def test_domain_indicator_kept_when_in_corpus(self) -> None:
        bundle = _bundle_with([_indicator("c2", "[domain-name:value = 'evil.example.com']")])
        result = postprocess_judge_bundle(bundle, evidence_corpus={"evil.example.com"})
        assert len([o for o in result["objects"] if o.get("type") == "indicator"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
