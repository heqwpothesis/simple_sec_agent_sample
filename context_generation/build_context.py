#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from source_sink_pipeline.context_builder import build_context_file  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate LLM-ready context snippets from findings.")
    parser.add_argument(
        "--findings",
        type=Path,
        default=Path("../findings.json"),
        help="Path to findings.json produced by the pipeline.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("context_payloads.json"),
        help="Where to write the enriched context payload.",
    )
    args = parser.parse_args()

    findings_path = args.findings.resolve()
    output_path = args.output.resolve()
    build_context_file(findings_path, output_path)
    print(f"Wrote context payload to {output_path}")


if __name__ == "__main__":
    main()
