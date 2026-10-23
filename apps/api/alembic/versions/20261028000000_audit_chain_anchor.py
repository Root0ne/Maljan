"""The audit chain's head is anchored in a table its own role only appends to.

``audit_chain_anchor`` holds one row per anchored head (``chain_seq`` as the
key, the chain value, key id, rotation boundary and the head's MAC), written
after each chained append commits through ``AUDIT_ANCHOR_DATABASE_URL``
(``app.services.audit_anchor``). On PostgreSQL a trigger refuses UPDATE, DELETE
and TRUNCATE on it for every role, and UPDATE, DELETE and TRUNCATE are revoked
from PUBLIC. Which role may write it is the operator's grant: the anchor role
takes INSERT and SELECT, and the table is best owned by a role the application
does not hold; the operator's verification reads and states what the roles in
fact hold.

It follows revision ``20261027000000``, which lands before it. A new, empty table: nothing is read or rewritten. ``lock_timeout`` bounds the
statements on PostgreSQL.

The downgrade is refused while the table holds an anchored head: dropping it
would discard the one record outside the head row that finds a cut chain.

Revision ID: 20261028000000
Revises: 20261027000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261028000000"
down_revision = "20261027000000"
branch_labels = None
depends_on = None

# How long each statement waits for a lock before the migration fails instead,
# so a busy catalogue is retried by the operator rather than queueing requests.
_LOCK = sa.text("SET LOCAL lock_timeout = '5s'")
_FUNCTION = sa.text(
    "CREATE OR REPLACE FUNCTION audit_chain_anchor_append_only() RETURNS trigger "
    "LANGUAGE plpgsql AS $$ BEGIN "
    "RAISE EXCEPTION 'audit_chain_anchor is append-only: % refused', TG_OP; "
    "END $$"
)
_ROW_TRIGGER = sa.text(
    "CREATE TRIGGER audit_chain_anchor_append_only BEFORE UPDATE OR DELETE "
    "ON audit_chain_anchor FOR EACH ROW EXECUTE FUNCTION audit_chain_anchor_append_only()"
)
_TRUNCATE_TRIGGER = sa.text(
    "CREATE TRIGGER audit_chain_anchor_no_truncate BEFORE TRUNCATE "
    "ON audit_chain_anchor FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_anchor_append_only()"
)
_REVOKE = sa.text("REVOKE UPDATE, DELETE, TRUNCATE ON audit_chain_anchor FROM PUBLIC")
_DROP_FUNCTION = sa.text("DROP FUNCTION IF EXISTS audit_chain_anchor_append_only()")
_HELD = sa.text("SELECT EXISTS (SELECT 1 FROM audit_chain_anchor)")


def _postgres() -> bool:
    return bool(op.get_bind().dialect.name == "postgresql")


def upgrade() -> None:
    if _postgres():
        op.execute(_LOCK)
    op.create_table(
        "audit_chain_anchor",
        sa.Column("chain_seq", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("chain", sa.String(64), nullable=False),
        # ``ledger_chain.KEY_ID_LENGTH``: a key id is 16 hex characters.
        sa.Column("key_id", sa.String(16), nullable=True),
        sa.Column("rotated_at_seq", sa.Integer(), nullable=False),
        sa.Column("mac", sa.String(64), nullable=False),
        sa.Column(
            "anchored_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    if _postgres():
        op.execute(_FUNCTION)
        op.execute(_ROW_TRIGGER)
        op.execute(_TRUNCATE_TRIGGER)
        op.execute(_REVOKE)


def downgrade() -> None:
    if op.get_bind().execute(_HELD).scalar():
        raise RuntimeError(
            "Refusing to downgrade past 20261028000000: audit_chain_anchor holds anchored "
            "heads, the one record outside the head row that finds a chain cut back to an "
            "earlier head. Keep a copy of the table, drop its append-only triggers as its "
            "owner and empty it, then retry."
        )
    if _postgres():
        op.execute(_LOCK)
    op.drop_table("audit_chain_anchor")
    if _postgres():
        op.execute(_DROP_FUNCTION)
