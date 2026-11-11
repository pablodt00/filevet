from pydantic import BaseModel, ConfigDict, Field


class Limits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_input_bytes: int = Field(default=50 << 20, gt=0)
    max_depth: int = Field(default=5, ge=0)
    max_children: int = Field(default=1000, ge=0)
    max_total_expanded_bytes: int = Field(default=500 << 20, ge=0)
    timeout_s: float = Field(default=30, gt=0)
    memory_bytes: int = Field(default=1 << 30, gt=0)


DEFAULT_LIMITS = Limits()
