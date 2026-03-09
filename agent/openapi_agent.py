"""OpenAPI-driven IDOR Detection Agent

An intelligent IDOR vulnerability detection agent that uses OpenAPI specifications to:
- Automatically discover API endpoints
- Identify object-level access patterns
- Perform targeted vulnerability testing
- Generate detailed security reports
"""

import os, json, argparse, re, requests
from typing import List, Dict, Any, Optional, Union
from typing_extensions import TypedDict
from rich import print

from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI

def llm():
    model = os.getenv("IDOR_MODEL") or os.getenv("DEEPSEEK_MODEL") or "gpt-4o-mini"
    api_key = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
    api_base = os.getenv("DEEPSEEK_API_BASE") or os.getenv("OPENAI_API_BASE")

    kwargs = {"model": model, "temperature": 0}
    if api_key:
        kwargs["openai_api_key"] = api_key
    if api_base:
        kwargs["openai_api_base"] = api_base
    return ChatOpenAI(**kwargs)

class AgentState(TypedDict, total=False):
    base_url: str
    username: str
    password: str
    token: str
    my_user_id: int
    openapi: Dict[str, Any]
    obj_get_path: str            # e.g., /orders/{order_id}
    obj_get_secure_path: str     # e.g., /orders/secure/{order_id}
    list_mine_path: str          # e.g., /orders/mine
    id_param_name: str           # e.g., order_id
    my_ids: List[int]
    probe_ids: List[int]
    observations: List[Dict[str, Any]]
    owner_field: str
    verdict: Dict[str, Any]
    report_md: str

OWNER_FIELD_CANDIDATES = [
    "owner_id",
    "user_id",
    "uid",
    "account_id",
    "customer_id",
    "member_id",
    "tenant_id",
    "created_by",
    "author_id",
]

DEFAULT_ID_CANDIDATES: tuple[int, ...] = tuple(list(range(1, 11)) + list(range(100, 111)) + list(range(1000, 1006)))
FAMILY_PRIORITY: tuple[str, ...] = ("orders", "documents", "users")

# ----------------- Helpers -----------------
def extract_resource_ids_from_payload(payload: Union[Dict[str, Any], List[Any]], id_param_name: Optional[str]) -> List[int]:
    found: set[int] = set()

    def walker(node: Union[Dict[str, Any], List[Any], Any]):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, int) and key in {id_param_name, "id"}:
                    found.add(value)
                elif isinstance(value, (dict, list)):
                    walker(value)
        elif isinstance(node, list):
            for item in node:
                walker(item)

    walker(payload)
    return sorted(found)


def _resource_family(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    return parts[0] if parts else ""


def _family_rank(family: str) -> tuple[int, str]:
    if family in FAMILY_PRIORITY:
        return (FAMILY_PRIORITY.index(family), family)
    return (len(FAMILY_PRIORITY), family)


def discover_ids_via_probe(state: AgentState, limit: int = 3) -> List[int]:
    path = state.get("obj_get_path")
    id_param = state.get("id_param_name")
    if not path or not id_param:
        return []
    base = state["base_url"]
    token = state["token"]
    secure_path = state.get("obj_get_secure_path")
    results: List[int] = []

    for candidate in DEFAULT_ID_CANDIDATES:
        target = path.replace(f"{{{id_param}}}", str(candidate))
        sc, body = _get(base, target, token)
        if sc != 200 or not isinstance(body, dict):
            continue

        owner_field = infer_owner_field(body)
        owner_value = body.get(owner_field)
        if owner_value is not None and state.get("my_user_id") is not None:
            if str(owner_value) != str(state["my_user_id"]):
                continue

        if secure_path:
            secure_target = secure_path.replace(f"{{{id_param}}}", str(candidate))
            sc_secure, _ = _get(base, secure_target, token)
            if sc_secure != 200:
                continue

        results.append(candidate)
        if len(results) >= limit:
            break

    return results

# ----------------- HTTP helpers -----------------
def _post(base, path, json_body):
    return requests.post(f"{base}{path}", json=json_body, timeout=10)

def _get(base, path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.get(f"{base}{path}", headers=headers, timeout=10)
    ctype = r.headers.get("content-type", "")
    body = r.json() if ctype.startswith("application/json") else r.text
    return r.status_code, body

# ----------------- Nodes -----------------
def node_login(state: AgentState) -> AgentState:
    r = _post(state["base_url"], "/login", {"username": state["username"], "password": state["password"]})
    r.raise_for_status()
    token = r.json()["token"]
    print("[bold cyan]Login[/] as", state["username"])
    return {"token": token}

def node_whoami(state: AgentState) -> AgentState:
    sc, body = _get(state["base_url"], "/me", state["token"])
    if sc != 200 or not isinstance(body, dict):
        raise RuntimeError("cannot get /me")
    print("[bold cyan]WhoAmI[/] user_id =", body.get("user_id"))
    return {"my_user_id": body.get("user_id")}

def node_fetch_openapi(state: AgentState) -> AgentState:
    for cand in ["/openapi.json", "/swagger.json"]:
        sc, body = _get(state["base_url"], cand, None)
        if sc == 200 and isinstance(body, dict) and "paths" in body:
            print("[bold cyan]OpenAPI[/] found at", cand)
            return {"openapi": body}
    raise RuntimeError("OpenAPI not found")

def pick_object_get_paths(spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    选择一个对象级 GET 接口，和其“安全版”对照接口（若存在），以及“我的资源列表”接口
    规则：路径含一个 {param}，且前缀相同的 secure 版本优先；mine/my 优先作为列表接口
    """
    paths = spec.get("paths", {})
    param_pat = re.compile(r"\{([^}/]+)\}")
    families: Dict[str, Dict[str, Any]] = {}

    for path, ops in paths.items():
        if "get" not in ops:
            continue

        family = _resource_family(path)
        if not family:
            continue

        info = families.setdefault(family, {"list_mine_path": None, "candidates": []})
        if re.fullmatch(rf"/{re.escape(family)}/(mine|my)", path):
            info["list_mine_path"] = path
            continue

        params = param_pat.findall(path)
        if len(params) != 1 or "/secure/" in path:
            continue

        secure_guess = path.replace("/{", "/secure/{", 1)
        info["candidates"].append(
            {
                "obj_get_path": path,
                "obj_get_secure_path": secure_guess if secure_guess in paths and "get" in paths[secure_guess] else None,
                "id_param_name": params[0],
            }
        )

    ranked_families = sorted(families, key=_family_rank)

    for require_list_mine in (True, False):
        for require_secure in (True, False):
            for family in ranked_families:
                info = families[family]
                if require_list_mine and not info["list_mine_path"]:
                    continue

                candidates = info["candidates"]
                if require_secure:
                    candidates = [candidate for candidate in candidates if candidate["obj_get_secure_path"]]
                if not candidates:
                    continue

                selected = candidates[0]
                return {
                    "obj_get_path": selected["obj_get_path"],
                    "obj_get_secure_path": selected["obj_get_secure_path"],
                    "list_mine_path": info["list_mine_path"],
                    "id_param_name": selected["id_param_name"],
                }

    return {
        "obj_get_path": None,
        "obj_get_secure_path": None,
        "list_mine_path": None,
        "id_param_name": None,
    }

def node_select_paths(state: AgentState) -> AgentState:
    spec = state["openapi"]
    sel = pick_object_get_paths(spec)
    print("[bold cyan]Select[/]", sel)
    if not sel["obj_get_path"]:
        raise RuntimeError("no object-level GET path found in OpenAPI")
    return sel

def node_list_my_resources(state: AgentState) -> AgentState:
    base = state["base_url"]
    token = state["token"]
    my_ids = []

    if state.get("list_mine_path"):
        sc, body = _get(base, state["list_mine_path"], token)
        if sc == 200 and isinstance(body, (dict, list)):
            my_ids = extract_resource_ids_from_payload(body, state.get("id_param_name"))

    if not my_ids:
        my_ids = discover_ids_via_probe(state)

    if not my_ids:
        raise RuntimeError("unable to discover owned resource identifiers")

    print("[bold cyan]Mine[/] ids =", my_ids)
    return {"my_ids": my_ids}

def infer_owner_field(obj: Dict[str, Any]) -> Optional[str]:
    # 优先完全匹配
    for k in OWNER_FIELD_CANDIDATES:
        if k in obj and isinstance(obj[k], (int, str)):
            return k
    # 其次包含 owner/user 的字段
    for k, v in obj.items():
        if isinstance(v, (int, str)) and (("owner" in k) or ("user" in k)):
            return k
    return None

def node_prepare_probes(state: AgentState) -> AgentState:
    # 基于“我的资源”挑出几个相邻 ID 作为探测对象
    my_ids = sorted(set(state["my_ids"]))
    if not my_ids:
        raise RuntimeError("no baseline ids available for probe generation")
    probes = []
    for i in my_ids:
        for delta in [-2, -1, 1, 2]:
            cand = i + delta
            if cand not in my_ids and cand > 0:
                probes.append(cand)
    probes = sorted(set(probes))[:6]  # 限制数量
    print("[bold cyan]ProbeIDs[/]:", probes)
    return {"probe_ids": probes}

def path_fill(path: str, id_param_name: str, value: int) -> str:
    return path.replace("{"+id_param_name+"}", str(value))

def node_probe(state: AgentState) -> AgentState:
    base = state["base_url"]
    token = state["token"]
    obs = []

    if not state["my_ids"]:
        raise RuntimeError("missing owned resource ids for probe baseline")

    # 基线：访问一个自己的对象，识别 owner 字段名
    base_obj_path = path_fill(state["obj_get_path"], state["id_param_name"], state["my_ids"][0])
    sc, body = _get(base, base_obj_path, token)
    if sc != 200 or not isinstance(body, dict):
        raise RuntimeError("baseline fetch failed")
    owner_field = infer_owner_field(body) or "owner_id"
    obs.append({"kind": "baseline", "resource_id": state["my_ids"][0], "status": sc, "body": body})

    # 探测：访问相邻 ID（潜在非本人对象）
    for oid in state["probe_ids"]:
        insecure_path = path_fill(state["obj_get_path"], state["id_param_name"], oid)
        sc1, b1 = _get(base, insecure_path, token)
        rec = {"kind": "probe_insecure", "resource_id": oid, "status": sc1, "body": b1}
        if state.get("obj_get_secure_path"):
            secure_path = path_fill(state["obj_get_secure_path"], state["id_param_name"], oid)
            sc2, b2 = _get(base, secure_path, token)
            rec.update({"status_secure": sc2, "body_secure": b2})
        obs.append(rec)

    print(f"[bold cyan]Probe[/] requests = {len(obs)} (owner_field: {owner_field})")
    return {"observations": obs, "owner_field": owner_field}

def node_verdict(state: AgentState) -> AgentState:
    my_id = state["my_user_id"]
    owner_field = state["owner_field"]
    obs = state["observations"]

    # 从基线再取一次 my_owner_value（有些接口返回 owner_id 与 /me 不同名）
    base_owner_value = None
    for o in obs:
        if o["kind"] == "baseline" and isinstance(o["body"], dict):
            base_owner_value = o["body"].get(owner_field)
            break
    if base_owner_value is None:
        base_owner_value = my_id  # 兜底

    cases = []
    for o in obs:
        if o["kind"] != "probe_insecure":
            continue
        if o["status"] == 200 and isinstance(o["body"], dict):
            owner_val = o["body"].get(owner_field)
            # 对照：如果存在 secure 且返回 403/401，更可信
            looks_forbidden_on_secure = (o.get("status_secure") in (401,403))
            if owner_val is not None and str(owner_val) != str(base_owner_value) and looks_forbidden_on_secure:
                cases.append({
                    "resource_id": o["resource_id"],
                    "owner_value": owner_val,
                    "status_insecure": o["status"],
                    "status_secure": o.get("status_secure")
                })

    verdict = {"is_idor": len(cases) > 0, "owner_field": owner_field, "my_owner_value": base_owner_value, "cases": cases}
    print("[bold cyan]Verdict[/]:", verdict)
    return {"verdict": verdict}

def node_report(state: AgentState) -> AgentState:
    v = state["verdict"]
    base = state["base_url"]

    if not v.get("is_idor"):
        md = "# IDOR Scan Report\n\n- Result: **No IDOR detected**\n- Evidence: secure endpoints align with insecure ones or ownership matches."
        with open("idor_report.md", "w", encoding="utf-8") as handle:
            handle.write(md)
        print("[bold green]Report[/] → idor_report.md (no issue)")
        return {"report_md": md}

    poc_blocks = []
    for c in v["cases"]:
        insecure_path = path_fill(state["obj_get_path"], state["id_param_name"], c["resource_id"])
        secure_path = None
        if state.get("obj_get_secure_path"):
            secure_path = path_fill(state["obj_get_secure_path"], state["id_param_name"], c["resource_id"])
        poc_blocks.append(f"""```bash
# 1) 登录获取 token（示例用户：bob）
curl -s -X POST {base}/login -H "Content-Type: application/json" -d '{{"username":"bob","password":"bob123"}}'
# 2) 使用 token 访问不属于当前用户的资源（不安全端点返回 200）
curl -H "Authorization: Bearer <BOB_TOKEN>" {base}{insecure_path}
# 3) 对照：安全端点返回 {c["status_secure"]}
curl -H "Authorization: Bearer <BOB_TOKEN>" {base}{secure_path or "<secure-endpoint-unavailable>"}
```""")

    fix = (
        "在对象读取/修改/删除路径统一做**对象级访问控制（BOLA/IDOR 防护）**：\n"
        "1）基于会话/JWT 获取当前用户身份；\n"
        "2）按 `WHERE owner_id = current_user_id` 查询或在取回对象后校验 `obj.owner == current_user`；\n"
        "3）不属于当前用户且非管理员时返回 `403 Forbidden`；\n"
        "4）避免信任客户端传入的 `user_id`/`role` 字段。\n"
        "示例修复见对应的安全对照接口实现。"
    )

    md = [
        "# IDOR Scan Report (OpenAPI-driven Demo)",
        "",
        "## Summary",
        "- Result: **IDOR detected**",
        f"- Owner field inferred: `{v['owner_field']}` ; my value: **{v['my_owner_value']}**",
        f"- Cases: {json.dumps(v['cases'], ensure_ascii=False)}",
        "",
        "## Minimal PoC (local only)",
        *poc_blocks,
        "",
        "## Fix Recommendation",
        fix,
        "",
        "> 本报告仅用于本地教学/自测；请勿用于未授权目标。"
    ]
    report_md = "\n".join(md)
    with open("idor_report.md", "w", encoding="utf-8") as handle:
        handle.write(report_md)
    print("[bold green]Report[/] → idor_report.md")
    return {"report_md": report_md}

def build_graph():
    g = StateGraph(AgentState)
    g.add_node("login", node_login)
    g.add_node("whoami", node_whoami)
    g.add_node("fetch_openapi", node_fetch_openapi)
    g.add_node("select_paths", node_select_paths)
    g.add_node("list_mine", node_list_my_resources)
    g.add_node("prepare_probes", node_prepare_probes)
    g.add_node("probe", node_probe)
    g.add_node("evaluate_verdict", node_verdict)
    g.add_node("report", node_report)

    g.set_entry_point("login")
    g.add_edge("login", "whoami")
    g.add_edge("whoami", "fetch_openapi")
    g.add_edge("fetch_openapi", "select_paths")
    g.add_edge("select_paths", "list_mine")
    g.add_edge("list_mine", "prepare_probes")
    g.add_edge("prepare_probes", "probe")
    g.add_edge("probe", "evaluate_verdict")
    g.add_edge("evaluate_verdict", "report")
    g.add_edge("report", END)
    return g.compile()

class OpenAPIIDORAgent:
    """OpenAPI-driven IDOR Detection Agent
    
    An intelligent IDOR vulnerability detection agent that leverages OpenAPI 
    specifications to automatically discover and test API endpoints for 
    insecure direct object reference vulnerabilities.
    
    Args:
        base_url (str): Target application base URL
        username (str): Username for authentication  
        password (str): Password for authentication
    
    Example:
        # Using as a class
        agent = OpenAPIIDORAgent(
            base_url="http://127.0.0.1:5005",
            username="bob", 
            password="bob123"
        )
        result = agent.run()
        
        # Or run directly
        python openapi_agent.py --base-url http://127.0.0.1:5005 --username bob
    """
    
    def __init__(self, base_url: str = "http://127.0.0.1:5005", username: str = "bob", password: str = "bob123"):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.graph = build_graph()
    
    def run(self) -> Dict[str, Any]:
        """Run the OpenAPI-driven IDOR detection scan
        
        Returns:
            Dict containing the final scan results including verdict and report
        """
        final_state = self.graph.invoke({
            "base_url": self.base_url,
            "username": self.username,
            "password": self.password
        })
        
        print("\n[bold]Done.[/]")
        print(json.dumps(final_state.get("verdict"), ensure_ascii=False, indent=2))
        
        return final_state

def main():
    """Command line interface for OpenAPIIDORAgent"""
    ap = argparse.ArgumentParser(description="OpenAPI-driven IDOR Detection Agent")
    ap.add_argument("--base-url", default="http://127.0.0.1:5005", help="Target application base URL")
    ap.add_argument("--username", default="bob", help="Username for authentication")
    ap.add_argument("--password", default="bob123", help="Password for authentication")
    args = ap.parse_args()
    
    # Create and run the agent
    agent = OpenAPIIDORAgent(
        base_url=args.base_url,
        username=args.username,
        password=args.password
    )
    
    try:
        agent.run()
    except Exception as e:
        print(f"[red]Error: {e}[/]")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
