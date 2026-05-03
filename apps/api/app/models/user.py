"""User model — authentication and authorization."""

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Platform user with role-based access."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    samples = relationship("Sample", back_populates="uploaded_by_user", lazy="selectin")
    jobs = relationship("AnalysisJob", back_populates="created_by_user", lazy="selectin")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="selectin")
    api_keys = relationship("APIKey", back_populates="user", lazy="selectin")

    def __repr__(self) -> str:
        return f"<User {self.email} role={self.role}>"
