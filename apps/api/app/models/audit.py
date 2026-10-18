"""Audit and API key models — security and traceability."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Immutable audit trail for all significant user actions."""

    __tablename__ = "audit_log"

    # user_id is nullable: unauthenticated audit events (failed login) write
    # the action even when no row in ``users`` matches the supplied email.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True
    )

    action: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default="now()",
        nullable=False,
    )

    # The audit chain (``app.services.audit_chain``): a chained row (a ledger
    # seal, an amendment to a sealed report) takes the next ``chain_seq``, the
    # SHA-256 of its columns in canonical form, and the keyed chain value that
    # links it to the chained row before it, with the id of the key it was
    # chained under. NULL on every other row and every row written before.
    chain_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain_key_id: Mapped[str | None] = mapped_column(String(16), nullable=True)

    __table_args__ = (Index("uq_audit_log_chain_seq", "chain_seq", unique=True),)

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} by user={self.user_id}>"


class AuditChainHead(Base):
    """The audit chain's head: its last ``chain_seq`` and chain value, under a keyed MAC.

    One row (``name`` ``"audit"``), rewritten by every chained append in the
    same transaction (``app.services.audit_chain``). Cutting chained rows off
    the end of the log leaves the head pointing past them, and moving the head
    back needs the key the MAC is computed under; a writer holding an earlier
    head record can still put it back, which only an anchor outside the
    database rules out.
    """

    __tablename__ = "audit_chain_head"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    chain_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    chain: Mapped[str] = mapped_column(String(64), nullable=False)
    key_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mac: Mapped[str] = mapped_column(String(64), nullable=False)


class APIKey(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """API key for programmatic access."""

    __tablename__ = "api_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )

    key_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self) -> str:
        return f"<APIKey {self.key_prefix}*** ({self.name})>"
