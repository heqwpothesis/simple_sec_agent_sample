from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List
import re

from .base import BaseAnalyzer
from ..models import Finding
from ..rules import JS_RULES


SANITIZERS = [
    re.compile(r"escape|encodeURI|encodeURIComponent|sanitize|validator\.sanitize", re.IGNORECASE),
    re.compile(r"Number\(|parseInt\(|parseFloat\(", re.IGNORECASE),
]


class JavaScriptAnalyzer(BaseAnalyzer):
    language = "javascript"

    def analyze(self, path: Path) -> Iterable[Finding]:
        lines = self.read_lines(path)
        sources: Dict[str, int] = {}
        tainted: Dict[str, Dict[str, int]] = {}
        tainted_line: Dict[str, int] = {}

        for idx, line in enumerate(lines, 1):
            assign = JS_RULES.source_assign.search(line)
            if assign:
                sources[assign.group("name")] = idx

        general_assign = re.compile(
            r"(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z0-9_]+)\s*=\s*(?P<expr>.+)"
        )

        for idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if JS_RULES.source_inline.search(line):
                continue
            if any(pattern.search(line) for pattern in JS_RULES.sink_patterns):
                continue
            match = general_assign.match(line)
            if not match:
                continue

            target = match.group("name")
            expr = match.group("expr")
            if any(pattern.search(expr) for pattern in SANITIZERS):
                if target in tainted:
                    del tainted[target]
                continue

            taint_sources: Dict[str, int] = {}
            for src_name, src_line in sources.items():
                if re.search(rf"\b{src_name}\b", expr):
                    taint_sources[src_name] = src_line
            for var_name, info in tainted.items():
                if re.search(rf"\b{var_name}\b", expr):
                    for src_name, src_line in info.items():
                        taint_sources[src_name] = src_line

            if taint_sources:
                tainted[target] = dict(sorted(taint_sources.items(), key=lambda item: item[1]))
                tainted_line[target] = idx

        for idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not any(pattern.search(line) for pattern in JS_RULES.sink_patterns):
                continue

            matched_sources: List[str] = []
            evidence: Dict[str, int] = {}

            for name, src_line in sources.items():
                if re.search(rf"\b{name}\b", line):
                    matched_sources.append(name)
                    evidence[name] = src_line

            for var_name, info in tainted.items():
                if re.search(rf"\b{var_name}\b", line):
                    assign_line = tainted_line.get(var_name, idx)
                    for src_name, src_line in info.items():
                        label = f"{src_name}->{var_name}"
                        evidence[label] = assign_line
                        if src_name not in matched_sources:
                            matched_sources.append(src_name)

            if JS_RULES.source_inline.search(line):
                matched_sources.append("direct req.*")
                evidence["req.*"] = idx

            if matched_sources:
                flow = " -> ".join(matched_sources + [line])
                yield Finding(
                    file=path,
                    line=idx,
                    language=self.language,
                    sources=matched_sources,
                    sink_line=line,
                    flow=flow,
                    evidence=evidence,
                )
