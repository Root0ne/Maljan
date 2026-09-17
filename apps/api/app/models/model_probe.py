"""What a probe reached, kept so a job can be refused before it starts.

A model name is the one part of an agent definition nothing validates until
the run gets to that agent. The settings probe answers the question — is this
model there, at this endpoint — and the answer used to live for exactly as
long as the console page was open. Here it is written down, so submitting a
job can ask it.

One row per ``(endpoint, model)``, because that pair is what a probe actually
reached. Changing either is a different question and finds no row, which is
the invalidation: nothing has to expire a result, because a result is never
looked up for a pair it was not taken against.

The detail is the probe's own last sentence, kept so a refusal can say what
went wrong rather than only that something did.
"""

from sqlalchemy import Boolean, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class ModelProbe(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "model_probes"
    __table_args__ = (UniqueConstraint("endpoint", "model", name="uq_model_probes_endpoint_model"),)

    # Where the probe went: a URL for a provider that has one, the vendor's
    # own name for one that does not (``maljan.core.model_assignments``).
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # The probe's own last sentence, whichever way it went.
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")

    def __repr__(self) -> str:
        return f"<ModelProbe {self.model}@{self.endpoint} ok={self.ok}>"
