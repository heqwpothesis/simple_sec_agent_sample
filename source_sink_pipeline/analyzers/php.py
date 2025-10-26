from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List
import re

from .base import BaseAnalyzer
from ..models import Finding
from ..rules import PHP_RULES


class PHPAnalyzer(BaseAnalyzer):
    language = "php"

    @staticmethod
    def _clean(line: str) -> str:
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            return ""
        if stripped.startswith("/*") or stripped.endswith("*/"):
            return ""
        return stripped

    def analyze(self, path: Path) -> Iterable[Finding]:
        lines = [self._clean(line) for line in self.read_lines(path)]
        sources: Dict[str, int] = {}
        tainted: Dict[str, Dict[str, int]] = {}
        tainted_line: Dict[str, int] = {}

        for idx, line in enumerate(lines, 1):
            assign = PHP_RULES.source_assign.search(line)
            if assign:
                sources[assign.group("name")] = idx

        var_assign = PHP_RULES.taint_assign

        for idx, line in enumerate(lines, 1):
            if not line:
                continue
            if PHP_RULES.source_assign.search(line):
                continue
            if PHP_RULES.source_inline.search(line):
                continue
            if any(pattern.search(line) for pattern in PHP_RULES.sink_patterns):
                continue
            assign_match = var_assign.search(line)
            if not assign_match:
                continue
            target = assign_match.group("name")
            taint_sources: Dict[str, int] = {}
            for src_name, src_line in sources.items():
                if re.search(rf"\${src_name}\b", line):
                    taint_sources[src_name] = src_line
            for var_name, info in tainted.items():
                if re.search(rf"\${var_name}\b", line):
                    for src_name, src_line in info.items():
                        taint_sources[src_name] = src_line
            if taint_sources:
                tainted[target] = dict(sorted(taint_sources.items(), key=lambda item: item[1]))
                tainted_line[target] = idx

        for idx, line in enumerate(lines, 1):
            if not line:
                continue
            if not any(pattern.search(line) for pattern in PHP_RULES.sink_patterns):
                continue
            matched_sources: List[str] = []
            evidence: Dict[str, int] = {}

            for name, src_line in sources.items():
                if re.search(rf"\${name}\b", line):
                    matched_sources.append(f"${name}")
                    evidence[f"${name}"] = src_line

            for var_name, info in tainted.items():
                if re.search(rf"\${var_name}\b", line):
                    assign_line = tainted_line.get(var_name, idx)
                    for src_name, src_line in info.items():
                        label = f"${src_name}->{var_name}"
                        evidence[label] = assign_line
                        if f"${src_name}" not in matched_sources:
                            matched_sources.append(f"${src_name}")

            if PHP_RULES.source_inline.search(line):
                matched_sources.append("direct superglobal")
                evidence["superglobal"] = idx

            if matched_sources:
                flow = " -> ".join(matched_sources + [line.strip()])
                yield Finding(
                    file=path,
                    line=idx,
                    language=self.language,
                    sources=matched_sources,
                    sink_line=line.strip(),
                    flow=flow,
                    evidence=evidence,
                )
