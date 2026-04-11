import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


def _generate_uuid() -> str:
    """Generate a standard UUID string for STIX objects."""
    return str(uuid.uuid4())


def get_utcnow() -> datetime:
    """Helper to return aware UTC datetime for STIX timestamp defaults."""
    return datetime.now(UTC)


class STIXObject(BaseModel):
    """Base generic properties for all STIX Domain Objects (SDOs)."""

    type: str
    id: str
    created: datetime = Field(default_factory=get_utcnow)
    modified: datetime = Field(default_factory=get_utcnow)


class Indicator(STIXObject):
    """STIX 2.1 Indicator representing a pattern that denotes malicious behavior."""

    type: Literal["indicator"] = "indicator"
    id: str = Field(default_factory=lambda: f"indicator--{_generate_uuid()}")
    name: str | None = None
    description: str | None = None
    indicator_types: list[str] = Field(default_factory=lambda: ["malicious-activity"])
    pattern: str
    pattern_type: str = "stix"
    valid_from: datetime = Field(default_factory=get_utcnow)


class Malware(STIXObject):
    """STIX 2.1 Malware representation."""

    type: Literal["malware"] = "malware"
    id: str = Field(default_factory=lambda: f"malware--{_generate_uuid()}")
    name: str
    description: str | None = None
    is_family: bool = False
    malware_types: list[str] = Field(default_factory=list)


class Relationship(STIXObject):
    """STIX 2.1 Relationship structure to connect SDOs."""

    type: Literal["relationship"] = "relationship"
    id: str = Field(default_factory=lambda: f"relationship--{_generate_uuid()}")
    relationship_type: str
    source_ref: str
    target_ref: str


class AttackPattern(STIXObject):
    """STIX 2.1 Attack Pattern, used to represent MITRE ATT&CK TTPs."""

    type: Literal["attack-pattern"] = "attack-pattern"
    id: str = Field(default_factory=lambda: f"attack-pattern--{_generate_uuid()}")
    name: str
    description: str | None = None
    external_references: list[dict] = Field(default_factory=list)


class Bundle(BaseModel):
    """STIX 2.1 Bundle container for transferring multiple objects."""

    type: Literal["bundle"] = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{_generate_uuid()}")
    objects: list[Indicator | Malware | Relationship | AttackPattern] = Field(default_factory=list)
