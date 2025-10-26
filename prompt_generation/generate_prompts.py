#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from jinja2 import Template  # type: ignore

from source_sink_pipeline.templates import (  # noqa: E402
    DETECTION_TEMPLATE,
    REMEDIATION_TEMPLATE,
)


def load_context(path: Path) -> list[dict]:
    return json.loads(path.read_text())


def render_prompts(context: list[dict]) -> list[dict]:
    detection_tpl = Template(DETECTION_TEMPLATE)
    remediation_tpl = Template(REMEDIATION_TEMPLATE)
    prompts = []
    for entry in context:
        rendered_detection = detection_tpl.render(
            file=entry["file"],
            language=entry["language"],
            flow=entry["flow"],
            source_lines=entry.get("source_lines", {}),
            sink_line=entry["sink_line"],
            start_line=entry["start_line"],
            end_line=entry["end_line"],
            code=entry["code"],
        )
        rendered_remediation = remediation_tpl.render(
            file=entry["file"],
            language=entry["language"],
            flow=entry["flow"],
            sink_line=entry["sink_line"],
            start_line=entry["start_line"],
            end_line=entry["end_line"],
            code=entry["code"],
        )
        prompts.append(
            {
                "file": entry["file"],
                "language": entry["language"],
                "flow": entry["flow"],
                "detection_prompt": rendered_detection,
                "remediation_prompt": rendered_remediation,
            }
        )
    return prompts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render LLM prompts from context payloads."
    )
    parser.add_argument(
        "--context",
        type=Path,
        default=Path("../context_payloads.json"),
        help="Path to context payload JSON.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("prompts.json"),
        help="File to write rendered prompts.",
    )
    args = parser.parse_args()

    context_data = load_context(args.context.resolve())
    prompts = render_prompts(context_data)
    args.output.resolve().write_text(json.dumps(prompts, indent=2))
    print(f"Wrote {len(prompts)} prompt entries to {args.output.resolve()}")


if __name__ == "__main__":
    main()
