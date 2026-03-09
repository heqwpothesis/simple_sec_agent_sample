"""Simple IDOR Detection Agent

A basic IDOR vulnerability detection agent that performs:
- Simple authentication
- Baseline resource enumeration
- Basic probe testing
- Simple vulnerability detection and reporting
"""

import os, json, argparse, requests
from typing import List, Dict, Any
from typing_extensions import TypedDict
from rich import print

from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI

BASE_URL_DEFAULT = "http://127.0.0.1:5005"
ORDER_ID_CANDIDATES: tuple[int, ...] = tuple(list(range(1, 11)) + list(range(100, 111)) + list(range(1000, 1006)))
PROBE_OFFSETS: tuple[int, ...] = (-3, -2, -1, 1, 2, 3)


class SimpleIDORAgent:
    def __init__(self, base_url: str = BASE_URL_DEFAULT, username: str = "bob", 
                 password: str = "bob123"):
        self.base_url = base_url
        self.username = username
        self.password = password
        
    def run(self) -> dict:
        app = self._build_graph()
        final = app.invoke({
            "base_url": self.base_url,
            "username": self.username,
            "password": self.password,
        })
        print("\n[bold]Done.[/] Verdict:", json.dumps(final.get("verdict"), ensure_ascii=False, indent=2))
        print("Report: idor_report.md")
        return final
        
    def _build_graph(self):
        return build_graph()

class AgentState(TypedDict, total=False):
    base_url: str
    username: str
    password: str
    token: str
    my_user_id: int
    my_order_ids: List[int]
    probe_ids: List[int]
    observations: List[Dict[str, Any]]
    verdict: Dict[str, Any]
    report_md: str

def llm():
    # 用 LLM 做总结（支持自定义 DeepSeek/OpenAI 配置）
    model = os.getenv("IDOR_MODEL") or os.getenv("DEEPSEEK_MODEL") or "gpt-4o-mini"
    api_key = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
    api_base = os.getenv("DEEPSEEK_API_BASE") or os.getenv("OPENAI_API_BASE")

    kwargs = {"model": model, "temperature": 0}
    if api_key:
        kwargs["openai_api_key"] = api_key
    if api_base:
        kwargs["openai_api_base"] = api_base
    return ChatOpenAI(**kwargs)

def _req(base, path, token):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.get(f"{base}{path}", headers=headers, timeout=10)
    if r.headers.get("content-type", "").startswith("application/json"):
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None
    return r.status_code, r.text

def discover_own_order_ids(base: str, token: str, limit: int = 3) -> List[int]:
    results: List[int] = []
    observed: List[Dict[str, Any]] = []

    for oid in ORDER_ID_CANDIDATES:
        sc, body = _req(base, f"/orders/{oid}", token)
        if sc != 200 or not isinstance(body, dict):
            continue

        owner_id = body.get("owner_id")
        sc_secure, _ = _req(base, f"/orders/secure/{oid}", token)
        observed.append({"order_id": oid, "owner_id": owner_id, "secure_status": sc_secure})

        if sc_secure == 200:
            results.append(oid)
            if len(results) >= limit:
                break

    if results:
        return sorted(set(results))

    owner_hits: Dict[Any, int] = {}
    for rec in observed:
        owner = rec.get("owner_id")
        if owner is None:
            continue
        score = owner_hits.get(owner, 0)
        if rec.get("secure_status") == 200:
            score += 2
        else:
            score += 1
        owner_hits[owner] = score

    if owner_hits:
        target_owner = max(owner_hits, key=owner_hits.get)
        return sorted({rec["order_id"] for rec in observed if rec.get("owner_id") == target_owner})

    return []

def node_login(state: AgentState) -> AgentState:
    url = f"{state['base_url']}/login"
    r = requests.post(url, json={"username": state["username"], "password": state["password"]}, timeout=10)
    r.raise_for_status()
    token = r.json()["token"]
    print("[bold cyan]Login[/] ok as", state["username"])
    return {"token": token}

def node_baseline(state: AgentState) -> AgentState:
    my_order_ids = discover_own_order_ids(state["base_url"], state["token"])
    if not my_order_ids:
        raise RuntimeError("unable to locate owned orders for baseline")
    print("[bold cyan]Baseline[/] my orders:", my_order_ids)
    return {"my_order_ids": my_order_ids}

def node_prepare_probe(state: AgentState) -> AgentState:
    my_ids = state["my_order_ids"]
    if not my_ids:
        raise RuntimeError("no owned orders available for probe preparation")
    probes = set()
    for oid in my_ids:
        for offset in PROBE_OFFSETS:
            candidate = oid + offset
            if candidate > 0 and candidate not in my_ids:
                probes.add(candidate)
    return {"probe_ids": sorted(probes)}

def node_probe(state: AgentState) -> AgentState:
    base = state["base_url"]
    token = state["token"]
    my_ids = state["my_order_ids"]
    probes = state["probe_ids"]

    obs = []
    # 访问自己的订单（基线）
    for oid in my_ids:
        sc, body = _req(base, f"/orders/{oid}", token)
        obs.append({"kind":"baseline", "order_id": oid, "status": sc, "body": body})

    # 访问他人订单（潜在越权）
    for oid in probes:
        sc, body = _req(base, f"/orders/{oid}", token)
        obs.append({"kind":"probe_insecure", "order_id": oid, "status": sc, "body": body})

        # 对照：安全接口（预期 403）
        sc2, body2 = _req(base, f"/orders/secure/{oid}", token)
        obs.append({"kind":"probe_secure", "order_id": oid, "status": sc2, "body": body2})

    print(f"[bold cyan]Probe[/] requests: {len(obs)}")
    return {"observations": obs}

def node_verdict(state: AgentState) -> AgentState:
    obs = state["observations"]
    # 简单规则：如果 probe_insecure 对他人订单返回 200，且 body.owner_id != owner_id，则判 IDOR
    # 先从 baseline 拿到 my_user_id
    my_user_id = None
    for o in obs:
        if o["kind"] == "baseline" and isinstance(o["body"], dict):
            my_user_id = o["body"].get("owner_id")
            break

    findings = []
    for o in obs:
        if o["kind"] == "probe_insecure" and o["status"] == 200 and isinstance(o["body"], dict):
            owner = o["body"].get("owner_id")
            # 对照安全接口
            sec = next((x for x in obs if x["kind"]=="probe_secure" and x["order_id"]==o["order_id"]), None)
            looks_idor = (my_user_id is not None and owner != my_user_id) and (sec and sec["status"] in (403,401))
            if looks_idor:
                findings.append({
                    "order_id": o["order_id"],
                    "owner_id": owner,
                    "status_insecure": o["status"],
                    "status_secure": (sec["status"] if sec else None),
                })

    verdict = {
        "is_idor": len(findings) > 0,
        "my_user_id": my_user_id,
        "cases": findings
    }
    print("[bold cyan]Verdict[/]:", verdict)
    return {"verdict": verdict, "my_user_id": my_user_id}

def node_report(state: AgentState) -> AgentState:
    v = state["verdict"]
    base = state["base_url"]
    token = state["token"]

    if not v.get("is_idor"):
        md = "# IDOR Scan Report\n\n- Result: **No IDOR detected in demo paths.**"
        with open("idor_report.md", "w", encoding="utf-8") as handle:
            handle.write(md)
        print("[bold green]Report[/] → idor_report.md (no issue)")
        return {"report_md": md}

    # 生成 PoC（curl）与修复建议（可用 LLM，也可纯文本）
    cases = v["cases"]
    poc_lines = []
    for c in cases:
        poc_lines.append(f"""```bash
# 登录获取 token
curl -s -X POST {base}/login -H "Content-Type: application/json" -d '{{"username":"bob","password":"bob123"}}'
# 使用 bob 的 token 访问 alice 的订单（/orders/{c["order_id"]} 返回 200）
curl -H "Authorization: Bearer <BOB_TOKEN>" {base}/orders/{c["order_id"]}
# 对照：安全接口返回 {c["status_secure"]}
curl -H "Authorization: Bearer <BOB_TOKEN>" {base}/orders/secure/{c["order_id"]}
```""")

    fix_text = (
        "服务端应进行**严格的对象级访问控制**：拿到 `order_id` 后，"
        "必须在服务端根据认证身份校验 `order.owner_id == current_user_id`（或具备 admin 权限），"
        "不可相信客户端传入的任何 user_id/role；"
        "对不属于当前用户的对象返回 403；同时在日志中记录尝试事件。\n\n"
        "**示例修复（Flask）**：\n"
        "```python\n"
        "@app.get('/orders/<int:order_id>')\n"
        "def get_order_fixed(order_id):\n"
        "    claims = _auth()\n"
        "    if not claims: return jsonify({'error':'unauthorized'}), 401\n"
        "    order = ORDERS.get(order_id)\n"
        "    if not order: return jsonify({'error':'not found'}), 404\n"
        "    if order['owner_id'] != claims['user_id'] and claims.get('role') != 'admin':\n"
        "        return jsonify({'error':'forbidden'}), 403\n"
        "    return jsonify({'order_id': order_id, 'owner_id': order['owner_id'], 'items': order['items']})\n"
        "```"
    )

    md = [
        "# IDOR Scan Report (Demo)",
        "",
        "## Summary",
        "- Result: **IDOR detected**",
        f"- Victim owner_id != tester user_id (**{v['my_user_id']}**)",
        f"- Cases: {json.dumps(cases, ensure_ascii=False)}",
        "",
        "## Minimal PoC (local only)",
        *poc_lines,
        "",
        "## Fix Recommendation",
        fix_text,
        ""
    ]
    report_md = "\n".join(md)
    with open("idor_report.md", "w", encoding="utf-8") as handle:
        handle.write(report_md)
    print("[bold green]Report[/] → idor_report.md")
    return {"report_md": report_md}

def build_graph():
    g = StateGraph(AgentState)
    g.add_node("login", node_login)
    g.add_node("baseline", node_baseline)
    g.add_node("prepare_probe", node_prepare_probe)
    g.add_node("probe", node_probe)
    g.add_node("evaluate_verdict", node_verdict)
    g.add_node("report", node_report)

    g.set_entry_point("login")
    g.add_edge("login", "baseline")
    g.add_edge("baseline", "prepare_probe")
    g.add_edge("prepare_probe", "probe")
    g.add_edge("probe", "evaluate_verdict")
    g.add_edge("evaluate_verdict", "report")
    g.add_edge("report", END)
    return g.compile()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=BASE_URL_DEFAULT)
    ap.add_argument("--username", default="bob")
    ap.add_argument("--password", default="bob123")
    args = ap.parse_args()

    agent = SimpleIDORAgent(args.base_url, args.username, args.password)
    agent.run()

if __name__ == "__main__":
    main()
