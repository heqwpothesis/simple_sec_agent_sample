from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class Finding:
    file: Path
    line: int
    language: str
    sources: List[str]
    sink_line: str
    flow: str
    evidence: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "file": str(self.file),
            "line": self.line,
            "language": self.language,
            "sources": self.sources,
            "sink": self.sink_line,
            "flow": self.flow,
            "evidence": self.evidence,
        }
