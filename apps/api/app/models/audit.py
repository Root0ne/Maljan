"""Audit and API key models — security and traceability."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, text
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
    # ``ledger_chain.KEY_ID_LENGTH`` wide.
    chain_key_id: Mapped[str | None] = mapped_column(String(16), nullable=True)

    __table_args__ = (
        Index("uq_audit_log_chain_seq", "chain_seq", unique=True),
        # One job's chained rows, read by its verification alone.
        Index(
            "ix_audit_log_chain_resource",
            "resource_id",
            "chain_seq",
            postgresql_where=text("chain_seq IS NOT NULL"),
            sqlite_where=text("chain_seq IS NOT NULL"),
        ),
    )

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
    database rules out (:class:`AuditChainAnchor`, ``app.services.audit_anchor``).
    """

    __tablename__ = "audit_chain_head"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    chain_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    chain: Mapped[str] = mapped_column(String(64), nullable=False)
    # ``ledger_chain.KEY_ID_LENGTH`` wide.
    key_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mac: Mapped[str] = mapped_column(String(64), nullable=False)
    # The ``chain_seq`` of the first row under ``key_id``: 1 for a chain that
    # never rotated, set by the first append under a new key, covered by the
    # MAC. Verification reads the rotation boundary from here only.
    rotated_at_seq: Mapped[int] = mapped_column(Integer, nullable=False)


class AuditChainAnchor(Base):
    """A head of the audit chain as it was committed, kept where the head record cannot reach it.

    One row per anchored head, never changed (``app.services.audit_anchor``):
    written after the commit through ``AUDIT_ANCHOR_DATABASE_URL``, a role
    meant to hold only INSERT and SELECT here, and refused UPDATE, DELETE and
    TRUNCATE by a trigger on PostgreSQL. Verification compares the chain with
    the latest row, so a chain rewritten under the key, or cut back to an
    earlier head record, no longer verifies. What the roles in fact hold is
    read and stated with every verification.
    """

    __tablename__ = "audit_chain_anchor"

    chain_seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    chain: Mapped[str] = mapped_column(String(64), nullable=False)
    # ``ledger_chain.KEY_ID_LENGTH`` wide.
    key_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rotated_at_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    mac: Mapped[str] = mapped_column(String(64), nullable=False)
    anchored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )


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
    # The owner's ``users.token_generation`` when the key was created. A key
    # is refused once the owner's generation has moved past it, so every
    # revocation of the account's sessions (a password change, a replayed
    # refresh token) retires its keys too (``deps._user_from_api_key``).
    token_generation: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self) -> str:
        return f"<APIKey {self.key_prefix}*** ({self.name})>"
