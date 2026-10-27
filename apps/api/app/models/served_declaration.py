"""What each tool server last declared of its own tools, kept past the process that listed it.

A server may declare its tools itself when it lists them
(``maljan.core.served_declarations``); the platform's own sidecars do, and
ship no table of their tools anywhere else. One row per source (``mcp:<key>``,
``provider:<id>``): the declaration its last listing gave, under the launch
identity of the block that reached it (``tool_declarations.launch_identity``).
A listing under another launch identity replaces the row, so a block pointed
at another server never reads the last one's. Read into every process that
reads declarations before any server attaches (the worker at job start, the
API), written back by the process that listed (``app.services.served_declarations_store``).

Not settings: nothing here is an operator's choice. Whether a block reads its
server's declaration as its own is the block's ``trusts_served_declaration``;
an untrusted server's row is read for its cautious claims alone.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ServedDeclaration(Base):
    __tablename__ = "served_tool_declarations"

    # ``mcp:<key>``, ``provider:<id>``: the source the tools are declared under.
    source: Mapped[str] = mapped_column(String(255), primary_key=True)
    # The block's launch identity when the server listed (16 hex characters,
    # or empty for a block of none).
    launch: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # Whether ``launch`` was the one the source ships with on the host that
    # listed it: a reader on another host reads such a row under its own
    # shipped launch (``served_declarations.install_persisted``).
    shipped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Per tool, each field it declares (``served_declarations.stored_form``).
    tool_facts: Mapped[object] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<ServedDeclaration {self.source}>"
