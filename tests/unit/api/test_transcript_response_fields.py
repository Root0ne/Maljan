"""What a stored line tells a client about itself.

``AgentMessageResponse`` is documented as mirroring the live ``agent_message``
payload field for field, so that a replayed conversation and a live one go
through the same code path in the console. Three payload fields were neither
columns nor response fields until ``20260926000000``, and their absence was
visible: a stored ``delegation_ask`` and its answer replayed as two plain
lines with no arrow between them, every replayed line fell into one unnamed
stage, and a replay named an agent by its registry key where the live view had
used the operator's label.

A row recorded before those columns existed sends ``None`` for all three, and
that is the point: the client has to be able to tell a kind that was recorded
from one it must derive, rather than reading a default as a fact.
"""

from __future__ import annotations

from app.models.report import AgentMessage
from app.schemas.job import AgentMessageResponse

# Bookkeeping on the row rather than part of the message: the primary key, the
# foreign key and the two timestamps the mixins write when the row is saved.
_NOT_THE_MESSAGE = {"id", "report_id", "created_at", "updated_at", "report_ref"}


def _row(**kwargs: object) -> AgentMessage:
    fields: dict[str, object] = {
        "seq": 4,
        "speaker": "static",
        "role": "analyst",
        "round": 0,
        "status": "complete",
        "text": "a line",
        # Written by the column default at flush time, so an instance that has
        # never been to the database has to say it here.
        "report_truncated": False,
    }
    fields.update(kwargs)
    return AgentMessage(**fields)


def test_the_response_carries_the_kind_the_stage_and_the_label() -> None:
    response = AgentMessageResponse.model_validate(
        _row(
            kind="delegation_ask",
            stage="analysis",
            display_name="Ahmet",
            addressed_to="reverser",
        )
    )

    assert response.kind == "delegation_ask"
    assert response.stage == "analysis"
    assert response.display_name == "Ahmet"
    assert response.addressed_to == "reverser"


def test_a_row_from_before_the_columns_sends_none_for_all_three() -> None:
    response = AgentMessageResponse.model_validate(_row())

    assert response.kind is None
    assert response.stage is None
    assert response.display_name is None


def test_every_column_of_a_stored_line_has_a_response_field() -> None:
    """The mirror the docstring promises, held by the code rather than by prose."""
    columns = {c.name for c in AgentMessage.__table__.columns} - _NOT_THE_MESSAGE
    missing = sorted(columns - set(AgentMessageResponse.model_fields))
    assert not missing, (
        f"agent_messages carries {missing} and the response drops it. A client "
        "that cannot read a stored field has to derive it, which is the defect "
        "this contract exists to prevent."
    )
