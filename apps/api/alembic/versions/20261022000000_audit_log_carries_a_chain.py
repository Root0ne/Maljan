"""The audit log can hold a hash chain: chained rows carry their place, digest and chain value.

``audit_log`` gains ``chain_seq`` (unique), ``digest``, ``chain`` and
``chain_key_id`` (``app.services.audit_chain``). A chained row (a ledger seal,
an amendment to a sealed report, a report's deletion) takes the next
``chain_seq`` and its chain value links it to the chained row before it. Every
other row, and every row written before this revision, holds none of them.
An index on ``(resource_id, chain_seq)`` over the chained rows lets one job's
verification read only that job's rows.

On PostgreSQL the indexes are built ``CONCURRENTLY`` in an autocommit block,
so writers are not locked out while they are built. Such a block commits the
columns before the index is built, so the upgrade is safe to run again after a
failed build: a column already there is not added twice, and an index the
failed build left INVALID is dropped and built again. SQLite builds in place.

Revision ID: 20261022000000
Revises: 20261021000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261022000000"
down_revision = "20261021000000"
branch_labels = None
depends_on = None

_UNIQUE = "uq_audit_log_chain_seq"
_BY_RESOURCE = "ix_audit_log_chain_resource"
_COLUMNS = (
    ("chain_seq", sa.Integer()),
    ("digest", sa.String(64)),
    ("chain", sa.String(64)),
    # ``ledger_chain.KEY_ID_LENGTH``: a key id is 16 hex characters.
    ("chain_key_id", sa.String(16)),
)


def _invalid_index(bind: sa.engine.Connection, name: str) -> bool:
    """Whether a PostgreSQL index of that name exists and is marked INVALID."""
    pg_class = sa.table("pg_class", sa.column("oid"), sa.column("relname"))
    pg_index = sa.table("pg_index", sa.column("indexrelid"), sa.column("indisvalid"))
    found = bind.execute(
        sa.select(pg_index.c.indisvalid)
        .select_from(pg_index.join(pg_class, pg_class.c.oid == pg_index.c.indexrelid))
        .where(pg_class.c.relname == name)
    ).first()
    return found is not None and not found[0]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    present = {c["name"] for c in inspector.get_columns("audit_log")}
    for name, kind in _COLUMNS:
        if name not in present:
            op.add_column("audit_log", sa.Column(name, kind, nullable=True))
    indexes = {i["name"] for i in inspector.get_indexes("audit_log")}
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            for name in (_UNIQUE, _BY_RESOURCE):
                if name in indexes and _invalid_index(bind, name):
                    op.drop_index(name, table_name="audit_log", postgresql_concurrently=True)
                    indexes.discard(name)
            if _UNIQUE not in indexes:
                op.create_index(
                    _UNIQUE, "audit_log", ["chain_seq"], unique=True, postgresql_concurrently=True
                )
            if _BY_RESOURCE not in indexes:
                op.create_index(
                    _BY_RESOURCE,
                    "audit_log",
                    ["resource_id", "chain_seq"],
                    postgresql_concurrently=True,
                    postgresql_where=sa.text("chain_seq IS NOT NULL"),
                )
        return
    if _UNIQUE not in indexes:
        op.create_index(_UNIQUE, "audit_log", ["chain_seq"], unique=True)
    if _BY_RESOURCE not in indexes:
        op.create_index(
            _BY_RESOURCE,
            "audit_log",
            ["resource_id", "chain_seq"],
            sqlite_where=sa.text("chain_seq IS NOT NULL"),
        )


def downgrade() -> None:
    op.drop_index(_BY_RESOURCE, table_name="audit_log")
    op.drop_index(_UNIQUE, table_name="audit_log")
    for name, _kind in reversed(_COLUMNS):
        op.drop_column("audit_log", name)
