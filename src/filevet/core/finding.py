from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_EVIDENCE = 256


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Location(BaseModel):
    model_config = ConfigDict(frozen=True)

    page: int | None = None
    sheet: str | None = None
    cell: str | None = None
    xpath: str | None = None
    offset: int | None = None
    archive_path: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(pattern=r"^[a-z]+\.[a-z0-9_]+$")
    title: str
    description: str = ""
    severity: Severity
    confidence: float = Field(default=1.0, ge=0, le=1)
    artifact_id: UUID | None = None
    location: Location | None = None
    evidence: str = ""
    references: list[str] = []
    analyzer: str = ""

    @field_validator("evidence", mode="before")
    @classmethod
    def _escape(cls, value: object) -> object:
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if isinstance(value, str):
            return value.encode("unicode_escape").decode("ascii")[:MAX_EVIDENCE]
        return value
