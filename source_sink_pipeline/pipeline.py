from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .analyzers import get_analyzer
from .models import Finding
from .utils import iter_files, read_config


class Pipeline:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path.resolve()
        self.base_dir = self.config_path.parent
        self.config = read_config(self.config_path)

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for target in self.config.get("targets", []):
            path = Path(target["path"])
            if not path.is_absolute():
                path = (self.base_dir / path).resolve()
            language = target["language"]
            include = target.get("include")
            if include:
                include = [
                    ((path / inc) if Path(inc).is_absolute() else path / inc).resolve()
                    for inc in include
                ]
            analyzer_cls = get_analyzer(language)
            analyzer = analyzer_cls()
            for file in iter_files(path, include):
                if language == "php" and file.suffix != ".php":
                    continue
                if language in {"javascript", "js"} and file.suffix not in {".js", ".mjs", ".cjs"}:
                    continue
                findings.extend(list(analyzer.analyze(file)))
        return findings

    def write_output(self, findings: List[Finding]) -> Path:
        out_path = Path(self.config.get("default_output", "findings.json"))
        if not out_path.is_absolute():
            out_path = (self.base_dir / out_path).resolve()
        payload = [f.to_dict() for f in findings]
        out_path.write_text(json.dumps(payload, indent=2))
        return out_path
