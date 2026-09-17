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
        # The relationship the endpoint reads the run's recorded profile from;
        # ``None`` until the run writes a report.
        self.report = None


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


@pytest.fixture(autouse=True)
def _forget_cached_rosters() -> None:
    """The roster cache is process-local; no test may inherit another's."""
    from app.api.v1 import jobs

    jobs._ROSTER_CACHE.clear()


def _overrides(monkeypatch: pytest.MonkeyPatch, stored: dict[str, Any]) -> None:
    async def load(self: Any) -> dict[str, Any]:
        return stored

    monkeypatch.setattr("app.services.settings_service.SettingsService.load_overrides", load)


@pytest.mark.asyncio
async def test_a_non_admin_owner_is_given_the_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    _overrides(monkeypatch, {})
    response = await get_job(job_id=uuid.uuid4(), user=_User(), svc=_Service(_Job()), db=_Session())
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
async def test_a_lead_s_specialists_are_named_before_they_speak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seeded ``team_lead`` team, as the endpoint serves it.

    A live run of this team rostered three participants and then produced
    messages from five more, because the specialists are the lead's tools
    rather than stages. They are on the roster now, with the agent that can
    task them.
    """
    _overrides(monkeypatch, {})
    response = await get_job(
        job_id=uuid.uuid4(),
        user=_User(),
        svc=_Service(_Job(config={"profile": "team_lead"})),
        db=_Session(),
    )
    by_key = {a.key: a for a in response.roster.agents}

    for key in ("static", "dynamic", "network", "reverser", "triage"):
        assert key in by_key, key
        assert by_key[key].via == ["lead"], key
        assert by_key[key].stages == [], key
        assert by_key[key].label, key

    for key in ("lead", "judge", "reporter"):
        assert by_key[key].via is None, key
        assert by_key[key].stages, key

    assert [s.key for s in response.roster.stages] == [
        "triage_pack",
        "lead",
        "verdict",
        "report",
    ]


@pytest.mark.asyncio
async def test_the_walk_follows_the_configured_delegation_depth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored = {
        "core.agents.delegation_depth": 1,
        "core.agents.definitions": {
            "boss": {
                "role": "lead",
                "label": "Boss",
                "tools": [{"kind": "agent", "agent": "hand"}],
            },
            "hand": {
                "role": "generic",
                "label": "Hand",
                "tools": [{"kind": "agent", "agent": "deep"}],
            },
            "deep": {"role": "generic", "label": "Deep"},
        },
        "core.agents.profiles": {
            "chain": {
                "stages": [{"key": "lead", "label": "Lead", "kind": "analysis", "agents": ["boss"]}]
            }
        },
    }
    _overrides(monkeypatch, stored)
    response = await get_job(
        job_id=uuid.uuid4(),
        user=_User(),
        svc=_Service(_Job(config={"profile": "chain"})),
        db=_Session(),
    )
    assert {a.key for a in response.roster.agents} == {"boss", "hand"}


@pytest.mark.asyncio
async def test_a_finished_run_keeps_the_team_it_actually_ran(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing the default afterwards must not rename a finished run's roster.

    The job pinned no profile, so the team it ran is the one the worker
    recorded in its settings snapshot — not whatever the default happens to be
    when somebody opens the run a week later.
    """
    _overrides(monkeypatch, {"core.agents.profile": "measurement"})
    job = _Job()
    job.report = type(
        "R", (), {"run_summary": {"settings_snapshot": {"agents.profile": "team_lead"}}}
    )()
    response = await get_job(job_id=uuid.uuid4(), user=_User(), svc=_Service(job), db=_Session())
    assert [s.key for s in response.roster.stages] == [
        "triage_pack",
        "lead",
        "verdict",
        "report",
    ]


@pytest.mark.asyncio
async def test_a_pinned_profile_still_wins_over_the_recorded_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _overrides(monkeypatch, {})
    job = _Job(config={"profile": "team_lead"})
    job.report = type(
        "R", (), {"run_summary": {"settings_snapshot": {"agents.profile": "default"}}}
    )()
    response = await get_job(job_id=uuid.uuid4(), user=_User(), svc=_Service(job), db=_Session())
    assert "lead" in {s.key for s in response.roster.stages}


@pytest.mark.asyncio
async def test_a_run_with_no_report_yet_falls_through_to_the_current_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Which is what the worker read when it composed the team moments ago.
    _overrides(monkeypatch, {})
    response = await get_job(job_id=uuid.uuid4(), user=_User(), svc=_Service(_Job()), db=_Session())
    assert {a.key for a in response.roster.agents} >= {"static", "judge"}


@pytest.mark.asyncio
async def test_the_roster_is_not_rebuilt_on_every_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The layout polls this endpoint every 3 s while the live view polls it
    every 5 s, and the roster cannot change mid-run."""
    reads = {"count": 0}

    async def load(self: Any) -> dict[str, Any]:
        reads["count"] += 1
        return {}

    monkeypatch.setattr("app.services.settings_service.SettingsService.load_overrides", load)
    job = _Job()
    for _ in range(4):
        await get_job(job_id=job.id, user=_User(), svc=_Service(job), db=_Session())
    assert reads["count"] == 1


@pytest.mark.asyncio
async def test_two_jobs_do_not_share_a_roster(monkeypatch: pytest.MonkeyPatch) -> None:
    _overrides(
        monkeypatch,
        {
            "core.agents.profiles": {
                "one": {
                    "stages": [{"key": "a", "label": "A", "kind": "analysis", "agents": ["static"]}]
                },
                "two": {
                    "stages": [
                        {"key": "b", "label": "B", "kind": "analysis", "agents": ["dynamic"]}
                    ]
                },
            }
        },
    )
    first = _Job(config={"profile": "one"})
    second = _Job(config={"profile": "two"})
    a = await get_job(job_id=first.id, user=_User(), svc=_Service(first), db=_Session())
    b = await get_job(job_id=second.id, user=_User(), svc=_Service(second), db=_Session())
    assert [x.key for x in a.roster.agents] == ["static"]
    assert [x.key for x in b.roster.agents] == ["dynamic"]


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
    response = await get_job(job_id=uuid.uuid4(), user=_User(), svc=_Service(_Job()), db=_Session())
    assert response.roster.agents == []
    assert "hunter2" not in response.model_dump_json()


def test_the_run_and_the_job_endpoint_describe_the_same_team() -> None:
    """The worker's roster event and the job endpoint's roster are one shape.

    Two readings of the same settings that drifted would show a live run one
    set of names and the finished one another, which is the whole failure this
    roster exists to prevent.
    """
    from app.services.agent_map import effective_definitions, effective_profiles
    from app.worker.analysis_worker import _roster_for
    from maljan.core.config import Settings
    from maljan.pipeline.events import roster_payload

    settings = Settings()

    class _Container:
        config = settings

        def active_profile(self) -> Any:
            return settings.agents.profiles[settings.agents.profile]

    from_the_run = _roster_for(_Container())
    from_the_store = roster_payload(
        effective_profiles({})[settings.agents.profile],
        effective_definitions({}),
        depth=int(settings.agents.delegation_depth),
    )
    assert from_the_run == from_the_store
    assert [a["key"] for a in from_the_run["agents"]]


def test_a_container_that_cannot_name_its_team_costs_no_run() -> None:
    from app.worker.analysis_worker import _roster_for

    class _Broken:
        config = None

        def active_profile(self) -> Any:
            raise RuntimeError("no profile")

    assert _roster_for(_Broken()) == {"agents": [], "stages": []}
