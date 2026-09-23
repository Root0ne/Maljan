from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.settings import router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import require_admin  # noqa: E402
from app.services.settings_service import (  # noqa: E402
    SaveResult,
    SettingsValidationError,
    ValueInfo,
)


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_schema_lists_groups_in_order_and_entries(client):
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        r = client.get("/api/v1/settings/schema")
    assert r.status_code == 200
    groups = r.json()["groups"]
    assert groups[0]["key"] == "llm"
    keys = {e["key"] for g in groups for e in g["entries"]}
    assert {"core.llm.provider", "api.enrichment_enabled", "api.debug"} <= keys
    ro = next(e for g in groups for e in g["entries"] if e["key"] == "api.debug")
    assert ro["editable"] is False


def test_values_never_contain_secret_values(client):
    fake = {
        "core.llm.openai.api_key": ValueInfo(None, True, "1234", "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "env"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings")
    assert r.status_code == 200
    body = r.json()["values"]
    assert body["core.llm.openai.api_key"] == {
        "value": None,
        "is_set": True,
        "hint": "1234",
        "source": "ui",
        "updated_at": None,
        "updated_by": None,
    }
    assert body["core.llm.provider"]["value"] == "openai"


def test_patch_returns_applies_summary(client):
    with patch(
        "app.api.v1.settings.SettingsService.save",
        AsyncMock(return_value=SaveResult(["core.llm.provider"], {"next_job": 1})),
    ):
        r = client.patch("/api/v1/settings", json={"changes": {"core.llm.provider": "openai"}})
    assert r.status_code == 200
    assert r.json() == {
        "applied": ["core.llm.provider"],
        "applies": {"next_job": 1},
        "warnings": {},
    }


def test_patch_validation_error_is_422_with_field_map(client):
    with patch(
        "app.api.v1.settings.SettingsService.save",
        AsyncMock(
            side_effect=SettingsValidationError(
                {"core.negotiation.max_iterations": "Input should be a valid integer"}
            )
        ),
    ):
        r = client.patch(
            "/api/v1/settings", json={"changes": {"core.negotiation.max_iterations": "x"}}
        )
    assert r.status_code == 422
    assert r.json()["errors"] == {
        "core.negotiation.max_iterations": "Input should be a valid integer"
    }


def test_reset_one_and_group(client):
    with patch(
        "app.api.v1.settings.SettingsService.reset", AsyncMock(return_value=["core.llm.provider"])
    ) as reset:
        r = client.delete("/api/v1/settings/core.llm.provider")
        assert r.status_code == 200 and r.json() == {"reset": ["core.llm.provider"]}
        r = client.delete("/api/v1/settings?group=llm")
        assert r.status_code == 200
        keys_passed = reset.call_args_list[1].args[0]
        assert (
            all(k.startswith("core.llm.") for k in keys_passed)
            and "core.llm.provider" in keys_passed
        )


def test_reset_group_unknown_is_404(client):
    r = client.delete("/api/v1/settings?group=does-not-exist")
    assert r.status_code == 404


def test_probe_unknown_is_404(client):
    r = client.post("/api/v1/settings/test/bogus", json={"values": {}})
    assert r.status_code == 404


def test_non_admin_is_rejected():
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    r = TestClient(app).get("/api/v1/settings/schema")
    assert r.status_code in (401, 403)


def test_the_preview_route_caps_the_pasted_sample(client):
    from app.services.mapping_preview import PREVIEW_MAX_BYTES

    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        json={"sample": {"pad": "x" * (PREVIEW_MAX_BYTES + 1)}, "mapping": {}},
    )
    assert r.status_code == 413


def test_the_preview_route_caps_a_streamed_body_with_no_content_length(client):
    """A body sent without a declared length (chunked transfer, or a lying
    header) must still be capped — the streamed guard, not ``Content-Length``,
    is what catches it."""
    from app.services.mapping_preview import PREVIEW_MAX_BYTES

    body = json.dumps({"sample": {"pad": "x" * (PREVIEW_MAX_BYTES + 1)}, "mapping": {}}).encode()

    def chunks():
        for i in range(0, len(body), 65536):
            yield body[i : i + 65536]

    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413


def test_the_preview_route_counts_rows_per_channel(client):
    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        json={"sample": {"p": [{"pid": 1}, {"nope": 2}]}, "mapping": {"processes": "$.p[*]"}},
    )
    assert r.status_code == 200
    assert r.json()["channels"]["processes"] == {
        "matched": 2,
        "kept": 1,
        "dropped": 1,
        "truncated": False,
        "sample_rows": [{"pid": 1}],
        "error": None,
    }


def test_the_preview_route_is_admin_only():
    """Without the ``require_admin`` override the real dependency runs and refuses."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.v1.settings import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    r = TestClient(app).post(
        "/api/v1/settings/sandbox-rest/preview", json={"sample": {}, "mapping": {}}
    )
    assert r.status_code in (401, 403)


class TestValidatingOneStageCondition:
    """The editor asks the parser, per blur, rather than waiting for apply.

    The grammar has exactly one implementation and this endpoint is a thin
    door onto it, so what is worth pinning is that the door is open, that it
    answers with the parser's own words, and that it stores nothing.
    """

    def test_an_empty_condition_is_valid(self, client):
        r = client.post("/api/v1/settings/validate-condition", json={"expression": "  "})
        assert r.status_code == 200
        assert r.json() == {"valid": True, "problems": []}

    def test_a_condition_over_the_sample_is_valid(self, client):
        r = client.post(
            "/api/v1/settings/validate-condition",
            json={"expression": 'platform == "windows"'},
        )
        assert r.json() == {"valid": True, "problems": []}

    def test_an_unknown_name_comes_back_as_a_problem(self, client):
        r = client.post(
            "/api/v1/settings/validate-condition",
            json={"expression": 'verdict == "Malware"'},
        )
        body = r.json()
        assert body["valid"] is False
        assert body["problems"]
        assert "verdict" in body["problems"][0]

    def test_a_call_is_refused_rather_than_evaluated(self, client):
        r = client.post(
            "/api/v1/settings/validate-condition",
            json={"expression": '__import__("os").system("id")'},
        )
        assert r.json()["valid"] is False

    def test_an_oversized_expression_is_refused_by_the_schema(self, client):
        r = client.post(
            "/api/v1/settings/validate-condition",
            json={"expression": "a" * 2001},
        )
        assert r.status_code == 422


class TestLintingTheTeams:
    """The editor's preview asks this as a team is edited; it stores nothing."""

    def _lint(self, client, body: dict, stored: dict | None = None):
        with (
            patch(
                "app.api.v1.settings.SettingsService.load_overrides",
                AsyncMock(return_value=stored or {}),
            ),
            patch("app.api.v1.settings.SettingsService.save", AsyncMock()) as save,
        ):
            r = client.post("/api/v1/settings/lint-teams", json=body)
        assert save.await_count == 0
        return r

    def test_the_seeded_teams_come_back_clean_and_laid_out(self, client):
        r = self._lint(client, {})
        assert r.status_code == 200
        body = r.json()
        assert body["findings"] == []
        default = body["graphs"]["default"]
        assert default["nodes"][0]["key"] == "triage_pack"
        assert default["columns"] == 1

    def test_a_staged_team_is_linted_as_staged_with_errors_first(self, client):
        team = {
            "stages": [
                {"key": "a", "kind": "analysis", "agents": ["ghost"]},
                {"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["a"]},
                {"key": "late", "kind": "analysis", "agents": ["dynamic"], "depends_on": ["v"]},
            ]
        }
        r = self._lint(client, {"profiles": {"mine": team}})
        findings = r.json()["findings"]
        assert findings[0]["severity"] == "error"
        assert findings[0]["path"] == "core.agents.profiles.mine.stages.a.agents"
        assert "unknown agent 'ghost'" in findings[0]["message"]
        assert any(f["code"] == "after_verdict" for f in findings)
        assert {n["key"] for n in r.json()["graphs"]["mine"]["nodes"]} == {"a", "v", "late"}

    def test_staged_definitions_are_what_the_team_is_checked_against(self, client):
        team = {
            "stages": [
                {"key": "a", "kind": "analysis", "agents": ["network"]},
                {"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["a"]},
            ]
        }
        r = self._lint(
            client,
            {
                "profiles": {"mine": team},
                "definitions": {"network": {"role": "network", "enabled": False}},
            },
        )
        assert any(f["code"] == "disabled_agent" for f in r.json()["findings"])

    def test_the_static_provider_note_the_save_carries_is_in_the_preview(self, client):
        r = self._lint(client, {}, stored={"core.static.provider": "none"})
        notes = [f for f in r.json()["findings"] if f["code"] == "static_provider_none"]
        assert notes
        assert all(f["severity"] == "warning" for f in notes)
        assert notes[0]["path"].startswith("core.agents.profiles.")


def test_the_lint_route_is_admin_only():
    """Without the ``require_admin`` override the real dependency runs and refuses."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    r = TestClient(app).post("/api/v1/settings/lint-teams", json={})
    assert r.status_code in (401, 403)


def test_a_team_of_a_thousand_stages_depending_on_later_ones_is_a_422(client):
    """Each stage depends on the next: the model refuses it, and so does apply, by name."""
    n = 1200
    keys = [f"s{i}" for i in range(n)]
    team = {
        "stages": [
            {
                "key": key,
                "kind": "analysis",
                "agents": ["static"] if i == 0 else [],
                "depends_on": keys[i + 1 : i + 2],
            }
            for i, key in enumerate(keys)
        ]
        + [{"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["s0"]}]
    }
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        r = client.patch(
            "/api/v1/settings", json={"changes": {"core.agents.profiles": {"mine": team}}}
        )
    assert r.status_code == 422
    errors = r.json()["errors"]
    assert errors["core.agents.profiles.mine.stages.s0.depends_on"] == (
        "stage 's0' depends on 's1', which is declared after it; a stage may only "
        "depend on an earlier stage"
    )
