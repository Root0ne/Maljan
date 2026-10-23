"""User model — authentication and authorization."""

import enum

from sqlalchemy import Boolean, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class UserRole(enum.StrEnum):
    """Allowed roles for a platform user.

    Two of them decide anything. ``admin`` gates the whole configuration
    surface, the audit log and API-key management; ``analyst`` is what a
    registration gets and is what every other route accepts.

    ``READONLY`` is enforced nowhere: no route in ``app.api.v1`` distinguishes
    it from ``ANALYST``, so an account holding it can upload a sample, submit a
    job and cancel its own. It is a label on the row, not a permission — see
    the Roles section of ``apps/docs/content/docs/security.mdx``. Kept rather than removed because
    a stored row carrying the value would not load against an enum without it,
    and because dropping it silently would widen those accounts rather than
    narrow them.
    """

    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Platform user with role-based access."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", native_enum=False),
        default=UserRole.ANALYST,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Every token carries the generation it was minted under
    # (``app.auth.jwt.TOKEN_GENERATION_CLAIM``); moving this on revokes every
    # access and refresh token of the account at once. A password change and a
    # replayed refresh token move it (``app.auth.revocation``).
    token_generation: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    # Relationships. The account's history is never loaded with the account:
    # every authenticated request resolves its caller to this row
    # (``app.deps.get_current_user``, the WebSocket handshake), and an eager
    # loader here pulled every sample, job, report, transcript, audit row and
    # API key the account ever made into each of them. ``raise`` makes reading
    # one off a loaded user an error rather than an unbounded query (or an
    # async lazy load); a route that needs the history queries it with its
    # own ``where`` and page, or asks for it with ``selectinload``.
    samples = relationship("Sample", back_populates="uploaded_by_user", lazy="raise")
    jobs = relationship("AnalysisJob", back_populates="created_by_user", lazy="raise")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="raise")
    api_keys = relationship("APIKey", back_populates="user", lazy="raise")

    def __repr__(self) -> str:
        return f"<User {self.email} role={self.role}>"
