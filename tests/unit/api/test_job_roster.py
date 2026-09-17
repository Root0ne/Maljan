"""The roster on the job endpoint: names for a reader who is not an admin.

The labels live on the agent definitions, which only an admin may read through
the settings endpoint. A job's own roster is as sensitive as the job, so it
goes out with the job — and that is the whole of the access rule being pinned
here: ownership, and no role.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.api.v1.jobs import _roster_for_job, get_job


class _Job:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.id = uuid.uuid4()
        self.sample_id = uuid.uuid4()
        self.sample_sha256 = "ab" * 32
        self.sample_filename = "evil.exe"
        self.status = "running"
        self.config = config
        self.created_at = datetime.now(UTC)
        self.started_at = None
        self.completed_at = None
        self.duration_seconds = None
        self.error_message = None


class _Service:
    def __init__(self, job: Any) -> None:
        self._job = job

    async def get_job(self, job_id: uuid.UUID, user: Any) -> Any:
        return self._job


class _User:
    id = uuid.uuid4()
    # Not an admin. The jobs router has no role check and must not grow one
    # for this; the test says so out loud.
    role = "ANALYST"


class _Session:
    pass


def _overrides(monkeypatch: pytest.MonkeyPatch, stored: dict[str, Any]) -> None:
    async def load(self: Any) -> dict[str, Any]:
        return stored

    monkeypatch.setattr("app.services.settings_service.SettingsService.load_overrides", load)


@pytest.mark.asyncio
async def test_a_non_admin_owner_is_given_the_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    _overrides(monkeypatch, {})
    response = await get_job(
        job_id=uuid.uuid4(), user=_User(), svc=_Service(_Job()), db=_Session()
    )
    roster = response.roster
    assert roster is not None
    keys = {agent.key for agent in roster.agents}
    assert "static" in keys
    static = next(a for a in roster.agents if a.key == "static")
    assert static.label == "Static analyst"
    assert static.role == "static"
    assert "analysis" in static.stages
    assert [stage.key for stage in roster.stages][0] == "triage_pack"


@pytest.mark.asyncio
async def test_the_roster_follows_the_profile_the_job_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _overrides(
        monkeypatch,
        {
            "core.agents.profiles": {
                "small": {
                    "label": "Small",
                    "stages": [
                        {
                            "key": "analysis",
                            "label": "Analysis",
                            "kind": "analysis",
                            "agents": ["static"],
                        }
                    ],
                }
            }
        },
    )
    response = await get_job(
        job_id=uuid.uuid4(),
        user=_User(),
        svc=_Service(_Job(config={"profile": "small"})),
        db=_Session(),
    )
    assert [a.key for a in response.roster.agents] == ["static"]
    assert [s.key for s in response.roster.stages] == ["analysis"]


@pytest.mark.asyncio
async def test_an_operator_label_replaces_the_registry_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _overrides(
        monkeypatch,
        {
            "core.agents.definitions": {
                "ahmet": {"role": "generic", "label": "ahmet", "enabled": True}
            },
            "core.agents.profiles": {
                "team": {
                    "stages": [
                        {
                            "key": "analysis",
                            "label": "Analysis",
                            "kind": "analysis",
                            "agents": ["ahmet"],
                        }
                    ]
                }
            },
        },
    )
    response = await get_job(
        job_id=uuid.uuid4(),
        user=_User(),
        svc=_Service(_Job(config={"profile": "team"})),
        db=_Session(),
    )
    assert response.roster.agents[0].label == "ahmet"


@pytest.mark.asyncio
async def test_a_team_written_as_a_flat_analyst_list_still_names_its_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _overrides(
        monkeypatch,
        {"core.agents.profiles": {"old": {"label": "Old", "analysts": ["static", "dynamic"]}}},
    )
    response = await get_job(
        job_id=uuid.uuid4(),
        user=_User(),
        svc=_Service(_Job(config={"profile": "old"})),
        db=_Session(),
    )
    assert [s.key for s in response.roster.stages] == [
        "triage_pack",
        "analysis",
        "debate",
        "verdict",
        "report",
    ]
    assert {a.key for a in response.roster.agents} >= {"static", "dynamic"}


@pytest.mark.asyncio
async def test_a_team_still_being_edited_is_read_as_it_stands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No verdict stage, which the model refuses. The members are still the
    # ones who would speak, so the roster names them rather than going empty.
    _overrides(
        monkeypatch,
        {
            "core.agents.profiles": {
                "half": {
                    "stages": [
                        {
                            "key": "analysis",
                            "label": "Analysis",
                            "kind": "analysis",
                            "agents": ["static"],
                        }
                    ]
                }
            }
        },
    )
    response = await get_job(
        job_id=uuid.uuid4(),
        user=_User(),
        svc=_Service(_Job(config={"profile": "half"})),
        db=_Session(),
    )
    assert [a.key for a in response.roster.agents] == ["static"]


@pytest.mark.asyncio
async def test_a_missing_job_is_still_a_404(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import HTTPException

    _overrides(monkeypatch, {})
    with pytest.raises(HTTPException) as exc:
        await get_job(job_id=uuid.uuid4(), user=_User(), svc=_Service(None), db=_Session())
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_a_team_that_will_not_load_costs_the_labels_and_not_the_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def load(self: Any) -> dict[str, Any]:
        raise RuntimeError("stored profiles are corrupt")

    monkeypatch.setattr("app.services.settings_service.SettingsService.load_overrides", load)
    roster = await _roster_for_job(_Session(), _Job())
    assert roster == {"agents": [], "stages": []}


@pytest.mark.asyncio
async def test_no_exception_text_reaches_the_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def load(self: Any) -> dict[str, Any]:
        raise RuntimeError("password=hunter2 at /home/op/secrets.env")

    monkeypatch.setattr("app.services.settings_service.SettingsService.load_overrides", load)
    response = await get_job(
        job_id=uuid.uuid4(), user=_User(), svc=_Service(_Job()), db=_Session()
    )
    assert response.roster.agents == []
    assert "hunter2" not in response.model_dump_json()
