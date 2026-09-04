"""Add ``sandbox_reports`` — operator-uploaded sandbox reports.

The upload sandbox provider runs no detonation of its own: the operator brings
a report from whatever sandbox they already run, and the job reads it instead of
submitting. This table is the metadata; the bytes are in object storage.

``sample_sha256_match`` is recorded once, at upload time. A mismatch is a
warning rather than a refusal (re-hashing a sample the sandbox unpacked is a
legitimate reason for the two to differ), and it is stored rather than
recomputed so the listing endpoint reports what was actually observed instead
of re-fetching and re-parsing the blob to ask the same question twice.

The ``id`` column carries no server-side default, matching every other table
built on ``UUIDPrimaryKeyMixin`` (see ``20260726020000_add_agent_messages_
transcript.py``): the mixin generates the value in Python
(``default=uuid.uuid4``) before the row is ever sent to the database.

Revision ID: 20260904000000
Revises: 20260903000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260904000000"
down_revision = "20260903000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sandbox_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("sample_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("storage_path", sa.String(length=1024), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256_of_blob", sa.String(length=64), nullable=False),
        sa.Column("sample_sha256_match", sa.Boolean(), nullable=False),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["sample_id"], ["samples.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    # The only query this table serves besides the FK itself is "every report
    # for one sample", so a plain index on the FK column is enough.
    op.create_index("ix_sandbox_reports_sample_id", "sandbox_reports", ["sample_id"])


def downgrade() -> None:
    op.drop_index("ix_sandbox_reports_sample_id", table_name="sandbox_reports")
    op.drop_table("sandbox_reports")
