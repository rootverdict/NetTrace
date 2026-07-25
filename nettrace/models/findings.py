from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    title: str
    description: str
    evidence: dict[str, Any]
    category: str
    timestamp: float | None = None
    attack_id: str | None = None
    attack_name: str | None = None
    severity: str = "info"
    score: int = 0
    confidence: str = "medium"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
