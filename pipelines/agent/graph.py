from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from source_sink_pipeline.context_builder import build_contexts
from source_sink_pipeline.pipeline import Pipeline
from source_sink_pipeline.templates import DETECTION_TEMPLATE, REMEDIATION_TEMPLATE

from .state import AgentState

try:
    from langgraph.graph import END, StateGraph  # type: ignore
except Exception:  # pragma: no cover - optional dependency for local tests
    END = "__end__"  # type: ignore
    StateGraph = None  # type: ignore


NodeFn = Callable[[AgentState], Dict[str, Any]]


def _error_payload(node: str, exc: Exception) -> Dict[str, str]:
    return {
        "node": node,
        "type": type(exc).__name__,
        "message": str(exc),
    }


def _guarded(node_name: str, fn: NodeFn) -> NodeFn:
    def wrapped(state: AgentState) -> Dict[str, Any]:
        if state.get("errors"):
            return {}
        try:
            return fn(state)
        except Exception as exc:  # pragma: no cover - behavior checked by tests
            current = list(state.get("errors", []))
            current.append(_error_payload(node_name, exc))
            return {"errors": current}

    return wrapped


def scan_node(state: AgentState) -> Dict[str, Any]:
    pipeline = Pipeline(Path(state["config_path"]))
    findings = [item.to_dict() for item in pipeline.run()]
    return {"findings": findings}


def context_node(state: AgentState) -> Dict[str, Any]:
    findings = state.get("findings", [])
    return {"contexts": build_contexts(findings)}


def prompt_node(state: AgentState) -> Dict[str, Any]:
    contexts = state.get("contexts", [])
    return {"prompts": _render_prompts_compat(contexts)}


def _render_template_fallback(template: str, values: Dict[str, Any]) -> str:
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace(f"{{{{ {key} }}}}", str(value))
    return rendered


def _render_prompts_compat(contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    try:
        from prompt_generation.generate_prompts import render_prompts as legacy_render_prompts

        return legacy_render_prompts(contexts)
    except ModuleNotFoundError:
        prompts: List[Dict[str, Any]] = []
        for entry in contexts:
            values = {
                "file": entry["file"],
                "language": entry["language"],
                "flow": entry["flow"],
                "source_lines": entry.get("source_lines", {}),
                "sink_line": entry["sink_line"],
                "start_line": entry["start_line"],
                "end_line": entry["end_line"],
                "code": entry["code"],
            }
            prompts.append(
                {
                    "file": entry["file"],
                    "language": entry["language"],
                    "flow": entry["flow"],
                    "detection_prompt": _render_template_fallback(DETECTION_TEMPLATE, values),
                    "remediation_prompt": _render_template_fallback(REMEDIATION_TEMPLATE, values),
                }
            )
        return prompts


def select_prompt_node(state: AgentState) -> Dict[str, Any]:
    if not state.get("run_llm", False):
        return {"selected_prompt": None}
    prompts = state.get("prompts", [])
    if not prompts:
        raise ValueError("No prompts available for LLM execution")
    prompt_index = int(state.get("prompt_index", 0))
    if not (0 <= prompt_index < len(prompts)):
        raise IndexError(f"Prompt index {prompt_index} out of range")
    prompt_type = state.get("prompt_type", "detection")
    field = "detection_prompt" if prompt_type == "detection" else "remediation_prompt"
    entry = prompts[prompt_index]
    return {
        "selected_prompt": {
            "entry": entry,
            "prompt_text": entry[field],
            "prompt_type": prompt_type,
        }
    }


def _invoke_llm(prompt_text: str, state: AgentState) -> Dict[str, Any]:
    system_message = "You are a senior application security engineer."
    model = state.get("model", "deepseek-v3-1-terminus")
    stream = bool(state.get("stream", False))
    api_key = state.get("api_key") or os.environ.get("ARK_API_KEY")
    base_url = state.get("base_url") or "https://ark.cn-beijing.volces.com/api/v3"
    if not api_key:
        raise RuntimeError("ARK_API_KEY is required when --run-llm is enabled")

    try:
        from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore
        from langchain_openai import ChatOpenAI  # type: ignore

        chat = ChatOpenAI(model=model, api_key=api_key, base_url=base_url)
        messages = [SystemMessage(content=system_message), HumanMessage(content=prompt_text)]
        if stream:
            chunks: List[str] = []
            for chunk in chat.stream(messages):
                if isinstance(chunk.content, str):
                    chunks.append(chunk.content)
            content = "".join(chunks)
        else:
            response = chat.invoke(messages)
            if isinstance(response.content, str):
                content = response.content
            elif isinstance(response.content, list):
                content = "".join(str(item) for item in response.content)
            else:
                content = str(response.content)
        return {"provider": "langchain_openai", "model": model, "content": content}
    except ImportError:
        from openai import OpenAI

        client = OpenAI(base_url=base_url, api_key=api_key)
        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt_text},
        ]
        if stream:
            stream_resp = client.chat.completions.create(model=model, messages=messages, stream=True)
            chunks = []
            for chunk in stream_resp:
                if chunk.choices:
                    chunks.append(chunk.choices[0].delta.content or "")
            content = "".join(chunks)
        else:
            completion = client.chat.completions.create(model=model, messages=messages)
            content = completion.choices[0].message.content or ""
        return {"provider": "openai", "model": model, "content": content}


def llm_node(state: AgentState) -> Dict[str, Any]:
    if not state.get("run_llm", False):
        return {}
    selected = state.get("selected_prompt")
    if not selected:
        raise ValueError("No selected prompt for LLM execution")
    response = _invoke_llm(selected["prompt_text"], state)
    return {"llm_response": response}


def _write_json(path_text: str, payload: Any) -> str:
    path = Path(path_text).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def persist_node(state: AgentState) -> Dict[str, Any]:
    artifacts = dict(state.get("artifacts", {}))
    artifacts["findings"] = _write_json(state["findings_output"], state.get("findings", []))
    artifacts["contexts"] = _write_json(state["context_output"], state.get("contexts", []))
    artifacts["prompts"] = _write_json(state["prompts_output"], state.get("prompts", []))
    llm_response = state.get("llm_response")
    llm_output = state.get("llm_output")
    if llm_response and llm_output:
        artifacts["llm_response"] = _write_json(llm_output, llm_response)
    return {"artifacts": artifacts}


def error_node(state: AgentState) -> Dict[str, Any]:
    return {"errors": state.get("errors", [])}


def _route_after_stage(state: AgentState, success_target: str) -> str:
    if state.get("errors"):
        return "error"
    return success_target


def _route_after_select(state: AgentState) -> str:
    if state.get("errors"):
        return "error"
    return "llm" if state.get("run_llm", False) else "persist"


def _build_langgraph() -> Any:
    graph = StateGraph(AgentState)
    graph.add_node("scan", _guarded("scan", scan_node))
    graph.add_node("context", _guarded("context", context_node))
    graph.add_node("prompt", _guarded("prompt", prompt_node))
    graph.add_node("select_prompt", _guarded("select_prompt", select_prompt_node))
    graph.add_node("llm", _guarded("llm", llm_node))
    graph.add_node("persist", _guarded("persist", persist_node))
    graph.add_node("error", error_node)
    graph.set_entry_point("scan")

    graph.add_conditional_edges("scan", lambda s: _route_after_stage(s, "context"))
    graph.add_conditional_edges("context", lambda s: _route_after_stage(s, "prompt"))
    graph.add_conditional_edges("prompt", lambda s: _route_after_stage(s, "select_prompt"))
    graph.add_conditional_edges("select_prompt", _route_after_select)
    graph.add_conditional_edges("llm", lambda s: _route_after_stage(s, "persist"))
    graph.add_conditional_edges("persist", lambda s: "error" if s.get("errors") else END)
    graph.add_conditional_edges("error", lambda s: END)
    return graph.compile()



def build_agent_graph() -> Any:
    if StateGraph is None:
        return _FallbackCompiledGraph()
    return _build_langgraph()
