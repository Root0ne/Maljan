"""A sandbox report an operator uploaded for a sample.

The bytes live in MinIO under a sha-derived path, not in the database: a CAPE
report is routinely tens of megabytes and this row is metadata. Storage is keyed
by the *sample's* sha256 so a report can never be written outside its sample's
prefix, and by the report id so a sample can carry several (a second detonation,
a colleague's run).

``sample_sha256_match`` is decided once, at upload time, from the report's own
claimed target hash, and stored rather than recomputed later: the listing
endpoint must show what was actually observed, and answering that from the
stored bit means it never has to re-fetch and re-parse the blob just to repeat
a comparison it already made.
"""

import uuid

from sqlalchemy import BigInteger, Boolean, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class SandboxReportRow(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "sandbox_reports"

    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"), index=True, nullable=False
    )
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    task_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_of_blob: Mapped[str] = mapped_column(String(64), nullable=False)
    sample_sha256_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )

    sample = relationship("Sample", back_populates="sandbox_reports")
