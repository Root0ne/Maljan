"""One-off markers for configuration bookkeeping that is not a setting itself.

The first row is ``legacy_env_import`` (see ``app.services.legacy_env_import``):
its presence says the one-shot import of the previous ``.env``-based
configuration into ``runtime_settings`` has already run, so the API never
walks the legacy environment a second time. Deliberately its own table rather
than a ``runtime_settings`` row: a marker is not a setting an operator edits
or resets, and giving it a catalog key would make it show up in the console.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SettingsMeta(Base):
    __tablename__ = "settings_meta"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
