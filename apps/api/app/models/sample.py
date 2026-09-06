"""Sample model — uploaded malware samples."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class Sample(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Uploaded malware sample metadata.

    Each ``(sha256, uploaded_by)`` pair gets its own row. A shared MinIO
    storage path (keyed by sha256 only) keeps disk usage flat while every
    user retains their own metadata row — original filename, upload time,
    and IDOR-checked ``sample.id``. The previous schema treated sha256 as
    globally unique, so any second uploader hit a 404 when trying to start
    an analysis on a hash someone else had already submitted.
    """

    __tablename__ = "samples"
    __table_args__ = (UniqueConstraint("sha256", "uploaded_by", name="uq_samples_sha256_uploader"),)

    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    md5: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Foreign keys
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )

    # Metadata (PE headers, magic bytes, etc.)
    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    uploaded_by_user = relationship("User", back_populates="samples")
    jobs = relationship("AnalysisJob", back_populates="sample", lazy="selectin")
    sandbox_reports = relationship(
        "SandboxReportRow",
        back_populates="sample",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    @property
    def uploaded_at(self) -> datetime:
        return self.created_at

    def __repr__(self) -> str:
        return f"<Sample {self.sha256[:12]}... ({self.original_filename})>"
