from __future__ import annotations

from pathlib import Path
from typing import Optional

from .graph import build_agent_graph
from .state import AgentState


def run_agent_pipeline(
    *,
    config_path: Path,
    findings_output: Path,
    context_output: Path,
    prompts_output: Path,
    run_llm: bool = False,
    prompt_index: int = 0,
    prompt_type: str = "detection",
    model: str = "deepseek-v3-1-terminus",
    stream: bool = False,
    llm_output: Optional[Path] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> AgentState:
    initial_state: AgentState = {
        "config_path": str(config_path.resolve()),
        "findings_output": str(findings_output.resolve()),
        "context_output": str(context_output.resolve()),
        "prompts_output": str(prompts_output.resolve()),
        "findings": [],
        "contexts": [],
        "prompts": [],
        "artifacts": {},
        "errors": [],
        "run_llm": run_llm,
        "prompt_index": prompt_index,
        "prompt_type": prompt_type,
        "model": model,
        "stream": stream,
        "api_key": api_key,
        "base_url": base_url,
    }
    if llm_output:
        initial_state["llm_output"] = str(llm_output.resolve())

    graph = build_agent_graph()
    result = graph.invoke(initial_state)
    return result

