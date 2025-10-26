from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from ..models import Finding


class BaseAnalyzer:
    language: str = ""

    def analyze(self, path: Path) -> Iterable[Finding]:
        raise NotImplementedError

    @staticmethod
    def read_lines(path: Path) -> List[str]:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
