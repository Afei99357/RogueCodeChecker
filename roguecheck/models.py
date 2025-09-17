from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

Severity = Literal["low", "medium", "high", "critical"]


@dataclass
class Position:
    line: int = 1
    column: int = 1


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    path: str
    position: Position
    snippet: Optional[str] = None
    recommendation: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
