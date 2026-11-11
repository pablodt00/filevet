from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Artifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    name: str
    size: int
    sha256: str
    md5: str
    declared_type: str | None
    detected_type: str
    depth: int = 0
    parent_id: UUID | None = None
    path: Path = Field(exclude=True)
