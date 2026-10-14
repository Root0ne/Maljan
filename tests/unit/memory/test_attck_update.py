"""The console's ATT&CK check and update, against a cache of the test's own.

No network: the release index and the bundle downloads are stand-ins written
here, and the cache directory is a temporary one per test.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from maljan.memory import attck_loader, attck_update


def _bundle(version: str, *, techniques: int = 2, modified: str = "2026-08-05T21:33:58Z") -> dict:
    objects: list[dict[str, Any]] = [
        {"type": "x-mitre-collection", "x_mitre_version": version, "modified": modified}
    ]
    for n in range(techniques):
        objects.append(
            {
                "type": "attack-pattern",
                "name": f"Technique {n}",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": f"T{1000 + n}"}
                ],
            }
        )
    return {"type": "bundle", "objects": objects}


def _index(versions: dict[str, list[tuple[str, str]]]) -> dict:
    names = {"enterprise": "Enterprise ATT&CK", "mobile": "Mobile ATT&CK", "ics": "ICS ATT&CK"}
    return {
        "collections": [
            {
                "name": names[domain],
                "versions": [
                    {
                        "version": version,
                        "url": f"https://example.invalid/{domain}-attack/{domain}-attack-{version}.json",
                        "modified": modified,
                    }
                    for version, modified in rows
                ],
            }
            for domain, rows in versions.items()
        ]
    }


LATEST = _index(
    {
        "enterprise": [("19.2", "2026-08-05T21:33:58Z"), ("20.0", "2026-10-13T17:53:10Z")],
        "mobile": [("20.0", "2026-10-13T17:54:40Z"), ("19.2", "2026-08-05T21:34:50Z")],
        "ics": [("20.0", "2026-10-13T17:54:18Z")],
    }
)


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "attck"
    directory.mkdir()
    monkeypatch.setattr(attck_loader, "ATTCK_CACHE_DIR", directory)
    monkeypatch.setattr(
        attck_loader,
        "ATTCK_CACHE_FILES",
        {d: directory / f"{d}-attack.json" for d in attck_loader.DOMAINS},
    )
    return directory


def _seed(cache: Path, versions: dict[str, str]) -> None:
    for domain, version in versions.items():
        (cache / f"{domain}-attack.json").write_text(json.dumps(_bundle(version)), encoding="utf-8")


def _index_answers(monkeypatch: pytest.MonkeyPatch, index: Any) -> list[str]:
    asked: list[str] = []

    def fetch(url: str, timeout: float = 60) -> Any:
        asked.append(url)
        if isinstance(index, Exception):
            raise index
        return index

    monkeypatch.setattr(attck_loader, "_fetch_bundle", fetch)
    return asked


def _downloads_serve(
    monkeypatch: pytest.MonkeyPatch, bodies: dict[str, Any] | None = None
) -> list[str]:
    """Each download writes the release its URL names, unless ``bodies`` says otherwise."""
    fetched: list[str] = []

    def download(url: str, target: Path, timeout: float = 300) -> None:
        fetched.append(url)
        name = url.rsplit("/", 1)[-1]
        if bodies and name in bodies:
            body = bodies[name]
            if isinstance(body, Exception):
                raise body
            target.write_text(body if isinstance(body, str) else json.dumps(body), "utf-8")
            return
        version = name.rsplit("-", 1)[-1].removesuffix(".json")
        target.write_text(json.dumps(_bundle(version, modified="2026-10-13T17:53:10Z")), "utf-8")

    monkeypatch.setattr(attck_loader, "_download_bundle_file", download)
    return fetched


class TestTheReleaseIndex:
    def test_the_newest_release_per_domain_whatever_the_listing_order(self) -> None:
        latest = attck_update.latest_releases(LATEST)
        assert latest == {
            "enterprise": {"version": "20.0", "released": "2026-10-13T17:53:10Z"},
            "mobile": {"version": "20.0", "released": "2026-10-13T17:54:40Z"},
            "ics": {"version": "20.0", "released": "2026-10-13T17:54:18Z"},
        }

    def test_numbers_compare_as_numbers(self) -> None:
        index = _index({"enterprise": [("9.0", "a"), ("10.1", "b"), ("10.0", "c")]})
        assert attck_update.latest_releases(index)["enterprise"]["version"] == "10.1"

    def test_a_version_that_is_not_a_release_number_is_skipped(self) -> None:
        index = _index({"enterprise": [("20.0/../../x", "a"), ("19.2", "b")]})
        assert attck_update.latest_releases(index)["enterprise"]["version"] == "19.2"

    def test_an_index_with_no_collections_is_refused(self) -> None:
        with pytest.raises(attck_update.ReleaseIndexError):
            attck_update.latest_releases({"name": "MITRE ATT&CK"})
        with pytest.raises(attck_update.ReleaseIndexError):
            attck_update.latest_releases({"collections": [{"name": "Something else"}]})

    def test_a_download_address_is_built_from_the_platform_constant(self) -> None:
        url = attck_update.release_url("mobile", "20.0")
        assert url == f"{attck_loader._BUNDLE_BASE_URL}/mobile-attack/mobile-attack-20.0.json"
        with pytest.raises(ValueError):
            attck_update.release_url("enterprise", "20.0/../../evil")
        with pytest.raises(ValueError):
            attck_update.release_url("pre-attack", "1.0")

    def test_the_index_is_read_from_the_platform_constant(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = _index_answers(monkeypatch, LATEST)
        attck_update.check()
        assert asked == [attck_update.ATTCK_INDEX_URL]
        assert attck_update.ATTCK_INDEX_URL.startswith(attck_loader._BUNDLE_BASE_URL)


class TestCheck:
    def test_an_up_to_date_cache_says_so_with_its_versions(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0", "mobile": "20.0", "ics": "20.0"})
        _index_answers(monkeypatch, LATEST)
        before = {p.name: p.stat().st_mtime_ns for p in cache.glob("*-attack.json")}

        result = attck_update.check({"user_id": "u1"}, refresh_days=7)

        assert result["outcome"] == "up_to_date" and result["ok"]
        assert [row["state"] for row in result["domains"]] == ["current"] * 3
        assert result["domains"][0]["cached"]["version"] == "20.0"
        assert {p.name: p.stat().st_mtime_ns for p in cache.glob("*-attack.json")} == before

    def test_an_outdated_cache_names_cached_and_latest_with_the_date(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "20.0"})
        _index_answers(monkeypatch, LATEST)

        result = attck_update.check(refresh_days=7)

        assert result["outcome"] == "outdated"
        enterprise = result["domains"][0]
        assert enterprise["state"] == "outdated"
        assert enterprise["cached"]["version"] == "19.2"
        assert enterprise["latest"] == {"version": "20.0", "released": "2026-10-13T17:53:10Z"}
        assert result["next_check_at"] is not None

    def test_a_missing_domain_counts_as_outdated(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0", "mobile": "20.0"})
        _index_answers(monkeypatch, LATEST)
        result = attck_update.check()
        assert result["outcome"] == "outdated"
        assert result["domains"][2]["state"] == "missing"

    def test_a_network_failure_is_failed_never_up_to_date(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0", "mobile": "20.0", "ics": "20.0"})
        _index_answers(monkeypatch, RuntimeError("Failed to fetch: timed out"))

        result = attck_update.check()

        assert result["outcome"] == "failed" and not result["ok"]
        assert "timed out" in result["reason"]
        assert all(row["latest"] is None for row in result["domains"])

    def test_the_check_downloads_no_bundle_and_is_recorded(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        _index_answers(monkeypatch, LATEST)
        fetched = _downloads_serve(monkeypatch)

        result = attck_update.check({"user_id": "u1", "name": "Ada"})

        assert fetched == []
        assert attck_update.read_state()["last_check"] == result

    def test_with_the_interval_off_there_is_no_next_check(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        _index_answers(monkeypatch, LATEST)
        assert attck_update.check(refresh_days=0)["next_check_at"] is None


class TestUpdate:
    def test_outdated_domains_are_replaced_and_the_old_files_kept(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "19.2"})
        old_enterprise = (cache / "enterprise-attack.json").read_text()
        _index_answers(monkeypatch, LATEST)
        fetched = _downloads_serve(monkeypatch)

        result = attck_update.update({"user_id": "u1", "name": "Ada"})

        assert result["ok"] and result["outcome"] == "updated"
        assert [(c["domain"], c["from"], c["to"]) for c in result["changes"]] == [
            ("enterprise", "19.2", "20.0"),
            ("ics", "19.2", "20.0"),
        ]
        assert fetched == [
            attck_update.release_url("enterprise", "20.0"),
            attck_update.release_url("ics", "20.0"),
        ]
        assert attck_update.cached_facts("enterprise")["version"] == "20.0"
        assert (cache / "enterprise-attack.json.bak").read_text() == old_enterprise
        assert not (cache / "mobile-attack.json.bak").exists()
        assert not list(cache.glob(".*.part"))
        state = attck_update.read_state()
        assert state["last_update"] == result and "running" not in state

    def test_an_invalid_bundle_is_rejected_and_the_old_cache_kept(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "19.2", "ics": "19.2"})
        before = {p.name: p.read_bytes() for p in cache.glob("*-attack.json")}
        _index_answers(monkeypatch, LATEST)
        _downloads_serve(monkeypatch, {"mobile-attack-20.0.json": '{"objects": [ truncated'})

        result = attck_update.update({"user_id": "u1"})

        assert not result["ok"] and result["kept_previous"]
        assert result["reason"].startswith("Mobile: the download does not parse as JSON")
        assert {p.name: p.read_bytes() for p in cache.glob("*-attack.json")} == before
        assert not list(cache.glob(".*.part"))
        assert not list(cache.glob("*.bak"))

    @pytest.mark.parametrize(
        ("body", "reason"),
        [
            (_bundle("19.2"), "is release 19.2, not 20.0"),
            (_bundle("20.0", techniques=0), "carries no techniques"),
            ({"type": "bundle"}, "not a STIX bundle"),
        ],
    )
    def test_a_bundle_that_is_not_the_named_release_is_rejected(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch, body: dict, reason: str
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        before = (cache / "enterprise-attack.json").read_bytes()
        _index_answers(monkeypatch, LATEST)
        _downloads_serve(monkeypatch, {"enterprise-attack-20.0.json": body})

        result = attck_update.update()

        assert not result["ok"]
        assert reason in result["reason"]
        assert (cache / "enterprise-attack.json").read_bytes() == before

    def test_a_failed_download_keeps_the_old_cache(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        before = (cache / "enterprise-attack.json").read_bytes()
        _index_answers(monkeypatch, LATEST)
        _downloads_serve(
            monkeypatch, {"enterprise-attack-20.0.json": RuntimeError("connection reset")}
        )

        result = attck_update.update()

        assert not result["ok"] and "connection reset" in result["reason"]
        assert (cache / "enterprise-attack.json").read_bytes() == before

    def test_an_unreadable_index_changes_nothing(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        _index_answers(monkeypatch, RuntimeError("Name or service not known"))
        fetched = _downloads_serve(monkeypatch)
        result = attck_update.update()
        assert not result["ok"] and "could not be read" in result["reason"]
        assert fetched == []

    def test_a_current_cache_downloads_nothing_and_counts_its_age_from_now(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0", "mobile": "20.0", "ics": "20.0"})
        old = time.time() - 30 * 86400
        for path in cache.glob("*-attack.json"):
            os.utime(path, (old, old))
        _index_answers(monkeypatch, LATEST)
        fetched = _downloads_serve(monkeypatch)

        result = attck_update.update()

        assert result["ok"] and result["outcome"] == "up_to_date" and result["changes"] == []
        assert fetched == []
        assert attck_update.cached_facts("enterprise")["age_days"] < 1

    def test_two_updates_at_once_do_not_interleave(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "20.0"})
        _index_answers(monkeypatch, LATEST)
        inside = threading.Event()
        release = threading.Event()
        fetched: list[str] = []

        def slow_download(url: str, target: Path, timeout: float = 300) -> None:
            fetched.append(url)
            inside.set()
            release.wait(10)
            target.write_text(json.dumps(_bundle("20.0")), "utf-8")

        monkeypatch.setattr(attck_loader, "_download_bundle_file", slow_download)
        first: dict[str, Any] = {}
        runner = threading.Thread(
            target=lambda: first.update(attck_update.update({"user_id": "a"}))
        )
        runner.start()
        assert inside.wait(10)

        second = attck_update.update({"user_id": "b"})
        release.set()
        runner.join(10)

        assert second["outcome"] == "busy" and not second["ok"]
        assert "another ATT&CK update is running" in second["reason"]
        assert first["ok"] and len(fetched) == 1
        assert attck_update.read_state()["last_update"]["triggered_by"] == {"user_id": "a"}

    def test_a_reader_during_the_swap_reads_one_whole_file(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bundle is replaced by a rename: an open reader keeps the old one, whole."""
        _seed(cache, {"enterprise": "19.2"})
        _index_answers(monkeypatch, LATEST)
        _downloads_serve(monkeypatch)
        reader = (cache / "enterprise-attack.json").open(encoding="utf-8")
        try:
            assert attck_update.update()["ok"]
            old = json.loads(reader.read())
        finally:
            reader.close()
        assert attck_update.bundle_facts(old)["version"] == "19.2"
        fresh = json.loads((cache / "enterprise-attack.json").read_text(encoding="utf-8"))
        assert attck_update.bundle_facts(fresh)["version"] == "20.0"

    def test_leftovers_of_a_stopped_update_are_cleared(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0", "mobile": "20.0", "ics": "20.0"})
        (cache / ".enterprise-attack.json.dead.part").write_text("half")
        (cache / ".update-state.json.live.part").write_text("{}")
        _index_answers(monkeypatch, LATEST)
        _downloads_serve(monkeypatch)
        attck_update.update()
        assert not (cache / ".enterprise-attack.json.dead.part").exists()
        assert (cache / ".update-state.json.live.part").exists()


class TestStatus:
    def test_each_domain_says_its_release_date_age_and_next_check(self, cache: Path) -> None:
        _seed(cache, {"enterprise": "19.2"})
        two_days = time.time() - 2 * 86400
        os.utime(cache / "enterprise-attack.json", (two_days, two_days))

        status = attck_update.status(7)

        enterprise, mobile, ics = status["domains"]
        assert enterprise["version"] == "19.2" and enterprise["techniques"] == 2
        assert enterprise["released"] == "2026-08-05T21:33:58Z"
        assert 1.9 < enterprise["age_days"] < 2.1
        assert enterprise["next_check_at"] == attck_update._iso_ts(two_days + 7 * 86400)
        assert status["next_check_at"] == enterprise["next_check_at"]
        assert mobile == {
            "domain": "mobile",
            "label": "Mobile",
            "present": False,
            "next_check_at": None,
        }
        assert ics["present"] is False

    def test_an_interval_of_zero_has_no_next_check(self, cache: Path) -> None:
        _seed(cache, {"enterprise": "19.2"})
        status = attck_update.status(0)
        assert status["next_check_at"] is None
        assert status["domains"][0]["next_check_at"] is None

    def test_the_facts_are_read_once_and_kept_beside_the_bundle(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        attck_update.cached_facts("enterprise")
        assert (cache / "enterprise-attack.meta.json").is_file()

        def no_parse(path: Path) -> dict:
            raise AssertionError("the kept facts must answer")

        monkeypatch.setattr(attck_loader, "_read_cache", no_parse)
        assert attck_update.cached_facts("enterprise")["version"] == "19.2"

    def test_an_unreadable_cache_says_so(self, cache: Path) -> None:
        (cache / "enterprise-attack.json").write_text("{ half", encoding="utf-8")
        facts = attck_update.cached_facts("enterprise")
        assert facts["present"] and not facts["readable"]
        assert "does not parse" in facts["reason"]


class TestTheAutomaticCheck:
    def test_it_is_due_once_the_cache_is_older_than_the_interval(self, cache: Path) -> None:
        _seed(cache, {"enterprise": "20.0"})
        assert not attck_update.scheduled_update_due(7)
        eight_days = time.time() - 8 * 86400
        os.utime(cache / "enterprise-attack.json", (eight_days, eight_days))
        assert attck_update.scheduled_update_due(7)
        assert not attck_update.scheduled_update_due(30)

    def test_an_interval_of_zero_never_runs_it(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0"})
        ancient = time.time() - 9999 * 86400
        os.utime(cache / "enterprise-attack.json", (ancient, ancient))
        _index_answers(monkeypatch, AssertionError("the interval is off"))
        assert attck_update.scheduled_update(0) is None

    def test_a_missing_enterprise_bundle_is_due(self, cache: Path) -> None:
        assert attck_update.scheduled_update_due(7)

    def test_when_due_it_runs_the_checked_update(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "20.0"})
        ten_days = time.time() - 10 * 86400
        os.utime(cache / "enterprise-attack.json", (ten_days, ten_days))
        _index_answers(monkeypatch, LATEST)
        _downloads_serve(monkeypatch)
        result = attck_update.scheduled_update(7)
        assert result is not None and result["ok"] and result["trigger"] == "schedule"
        assert attck_update.cached_facts("enterprise")["version"] == "20.0"


class TestTheLoadersOwnRefresh:
    def test_it_writes_in_one_rename(self, cache: Path) -> None:
        target = cache / "enterprise-attack.json"
        assert attck_update.save_refreshed_bundle(_bundle("20.0"), target)
        assert json.loads(target.read_text())["objects"][0]["x_mitre_version"] == "20.0"
        assert not list(cache.glob(".*.part"))

    def test_it_is_not_written_while_an_update_holds_the_cache(self, cache: Path) -> None:
        target = cache / "enterprise-attack.json"
        _seed(cache, {"enterprise": "19.2"})
        with attck_update._locked(cache / attck_update.LOCK_NAME, blocking=False) as held:
            assert held
            assert not attck_update.save_refreshed_bundle(_bundle("20.0"), target)
        assert json.loads(target.read_text())["objects"][0]["x_mitre_version"] == "19.2"

    def test_the_loader_goes_through_it(self, cache: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = cache / "enterprise-attack.json"
        monkeypatch.setattr(attck_loader, "_fetch_bundle", lambda url: _bundle("20.0"))
        raw = attck_loader._load_raw_bundle("https://x", target, True, 7)
        assert raw["objects"][0]["x_mitre_version"] == "20.0"
        assert json.loads(target.read_text())["objects"][0]["x_mitre_version"] == "20.0"


class TestTheCacheSignature:
    def test_a_replaced_bundle_changes_it(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        before = attck_update.cache_signature()
        _index_answers(monkeypatch, LATEST)
        _downloads_serve(monkeypatch)
        attck_update.update()
        assert attck_update.cache_signature() != before
