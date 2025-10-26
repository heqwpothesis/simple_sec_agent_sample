#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from openai import OpenAI


def load_prompts(path: Path) -> list[dict]:
    return json.loads(path.read_text())


def select_prompt(prompts: list[dict], index: int, prompt_type: str) -> tuple[str, dict]:
    if not (0 <= index < len(prompts)):
        raise IndexError(f"Index {index} out of range (0..{len(prompts)-1})")
    entry = prompts[index]
    field = "detection_prompt" if prompt_type == "detection" else "remediation_prompt"
    return entry[field], entry


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send a generated prompt to the LLM endpoint."
    )
    parser.add_argument(
        "--prompts-file",
        type=Path,
        default=Path("../prompts.json"),
        help="Path to prompts.json produced by generate_prompts.py",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=0,
        help="Which prompt entry to send (0-based)",
    )
    parser.add_argument(
        "--type",
        choices=["detection", "remediation"],
        default="detection",
        help="Prompt flavor to send",
    )
    parser.add_argument(
        "--model",
        default="deepseek-v3-1-terminus",
        help="Model/endpoint ID",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Use streaming responses",
    )
    args = parser.parse_args()

    prompts = load_prompts(args.prompts_file.resolve())
    prompt_text, entry = select_prompt(prompts, args.index, args.type)

    client = OpenAI(
        base_url="https://ark.cn-beijing.volces.com/api/v3",
        api_key=os.environ.get("ARK_API_KEY"),
    )

    messages = [
        {"role": "system", "content": "You are a senior application security engineer."},
        {"role": "user", "content": prompt_text},
    ]

    if args.stream:
        stream = client.chat.completions.create(
            model=args.model,
            messages=messages,
            stream=True,
        )
        for chunk in stream:
            if not chunk.choices:
                continue
            print(chunk.choices[0].delta.content or "", end="")
        print()
    else:
        completion = client.chat.completions.create(
            model=args.model,
            messages=messages,
        )
        print(completion.choices[0].message.content)


if __name__ == "__main__":
    main()
