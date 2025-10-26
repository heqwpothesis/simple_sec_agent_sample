from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def read_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    text = path.read_text()
    if path.suffix in {".yaml", ".yml"}:
        if not yaml:
            raise RuntimeError("pyyaml is required to read YAML config files")
        return yaml.safe_load(text)
    if path.suffix == ".json":
        return json.loads(text)
    raise ValueError("Unsupported config format (use .yaml or .json)")


def iter_files(root: Path, include: List[Path] | None = None) -> Iterable[Path]:
    root = root.resolve()
    include_paths = include or []
    candidates = include_paths or [root]
    for base in candidates:
        if base.is_file():
            yield base
            continue
        for path in base.rglob("*"):
            if path.is_file():
                yield path
