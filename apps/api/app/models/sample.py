"""Sample model — uploaded malware samples."""

import uuid

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class Sample(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Uploaded malware sample metadata."""

    __tablename__ = "samples"

    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
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

    def __repr__(self) -> str:
        return f"<Sample {self.sha256[:12]}... ({self.original_filename})>"
