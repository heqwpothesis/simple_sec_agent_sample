#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from source_sink_pipeline.pipeline import Pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Source/Sink detection pipeline.")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"), help="Path to config file")
    parser.add_argument("--output", type=Path, help="Override output file path")
    parser.add_argument("--json", action="store_true", help="Print findings to stdout as JSON")
    args = parser.parse_args()

    pipeline = Pipeline(args.config)
    findings = pipeline.run()
    out_path = pipeline.write_output(findings) if not args.output else args.output
    if args.output:
        out_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(f"Found {len(findings)} potential flows. Results saved to {out_path}")


if __name__ == "__main__":
    main()
