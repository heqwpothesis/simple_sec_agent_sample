#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipelines.agent.runner import run_agent_pipeline  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run source/sink analysis through the LangGraph-based agent pipeline."
    )
    parser.add_argument("--config", type=Path, default=Path("config.yaml"), help="Path to config file.")
    parser.add_argument(
        "--findings-output",
        type=Path,
        default=Path("findings.json"),
        help="File for findings JSON output.",
    )
    parser.add_argument(
        "--context-output",
        type=Path,
        default=Path("context_payloads.json"),
        help="File for context JSON output.",
    )
    parser.add_argument(
        "--prompts-output",
        type=Path,
        default=Path("prompts.json"),
        help="File for prompts JSON output.",
    )
    parser.add_argument("--run-llm", action="store_true", help="Run LLM on selected prompt.")
    parser.add_argument("--index", type=int, default=0, help="Prompt index for LLM execution.")
    parser.add_argument(
        "--type",
        dest="prompt_type",
        choices=["detection", "remediation"],
        default="detection",
        help="Prompt type for LLM execution.",
    )
    parser.add_argument("--model", default="deepseek-v3-1-terminus", help="Model name for LLM execution.")
    parser.add_argument("--stream", action="store_true", help="Enable streaming for LLM execution.")
    parser.add_argument(
        "--llm-output",
        type=Path,
        default=Path("llm_response.json"),
        help="File for optional LLM response JSON output.",
    )
    parser.add_argument("--api-key", default=None, help="Optional API key override for LLM calls.")
    parser.add_argument("--base-url", default=None, help="Optional API base URL override for LLM calls.")
    parser.add_argument("--json", action="store_true", help="Print the final state as JSON.")

    args = parser.parse_args()
    state = run_agent_pipeline(
        config_path=args.config,
        findings_output=args.findings_output,
        context_output=args.context_output,
        prompts_output=args.prompts_output,
        run_llm=args.run_llm,
        prompt_index=args.index,
        prompt_type=args.prompt_type,
        model=args.model,
        stream=args.stream,
        llm_output=args.llm_output if args.run_llm else None,
        api_key=args.api_key,
        base_url=args.base_url,
    )

    if args.json:
        print(json.dumps(state, indent=2, ensure_ascii=False))
        return

    if state.get("errors"):
        print(f"Agent pipeline finished with {len(state['errors'])} error(s).")
        for item in state["errors"]:
            print(f"- [{item['node']}] {item['type']}: {item['message']}")
        return

    artifacts = state.get("artifacts", {})
    print("Agent pipeline finished successfully.")
    for name, path in artifacts.items():
        print(f"- {name}: {path}")


if __name__ == "__main__":
    main()

