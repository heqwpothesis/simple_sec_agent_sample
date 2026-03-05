from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class SelectedPrompt(TypedDict):
    entry: Dict[str, Any]
    prompt_text: str
    prompt_type: str


class AgentState(TypedDict, total=False):
    config_path: str
    findings_output: str
    context_output: str
    prompts_output: str
    llm_output: str
    findings: List[Dict[str, Any]]
    contexts: List[Dict[str, Any]]
    prompts: List[Dict[str, Any]]
    selected_prompt: Optional[SelectedPrompt]
    llm_response: Dict[str, Any]
    artifacts: Dict[str, str]
    errors: List[Dict[str, str]]
    run_llm: bool
    prompt_index: int
    prompt_type: str
    model: str
    stream: bool
    base_url: Optional[str]
    api_key: Optional[str]

