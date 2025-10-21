# enhanced_idor_agent.py
"""
Enhanced IDOR Detection Agent

This agent provides comprehensive IDOR vulnerability detection with:
- Multi-endpoint discovery via OpenAPI
- Smart probe generation
- Pattern-based vulnerability detection
- Detailed reporting with PoC generation
"""

import os, argparse, requests, re
from typing import List, Dict, Any, Optional, Tuple, Union
from typing_extensions import TypedDict
from rich import print
from datetime import datetime

from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI

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

DEFAULT_ID_CANDIDATES: Tuple[int, ...] = tuple(list(range(1, 11)) + list(range(100, 111)) + list(range(1000, 1006)))

class AgentState(TypedDict, total=False):
    base_url: str
    username: str
    password: str
    token: str
    my_user_id: int
    openapi: Dict[str, Any]
    target_endpoints: List[Dict[str, Any]]
    resource_types: List[Dict[str, Any]]
    observations: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    report_md: str

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

# ----------------- HTTP helpers -----------------
def _post(base: str, path: str, json_body: dict) -> requests.Response:
    return requests.post(f"{base}{path}", json=json_body, timeout=10)

def _get(base: str, path: str, token: Optional[str] = None) -> Tuple[int, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(f"{base}{path}", headers=headers, timeout=10)
        ctype = r.headers.get("content-type", "")
        body = r.json() if ctype.startswith("application/json") else r.text
        return r.status_code, body
    except Exception as e:
        return 500, {"error": str(e)}

# ----------------- Core Detection Logic -----------------
def discover_endpoints(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Discover potential IDOR endpoints from OpenAPI spec"""
    endpoints = []
    paths = spec.get("paths", {})
    
    # Pattern to find path parameters
    param_pattern = re.compile(r"\{([^}]+)\}")
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() != "get":
                continue
                
            # Look for endpoints with ID parameters
            params = param_pattern.findall(path)
            id_params = [p for p in params if "id" in p.lower()]
            
            if id_params:
                # Categorize endpoint type
                endpoint_type = "unknown"
                resource_name = "resource"
                
                if "/orders/" in path:
                    endpoint_type = "order"
                    resource_name = "order"
                elif "/documents/" in path:
                    endpoint_type = "document"
                    resource_name = "document"
                elif "/users/" in path:
                    endpoint_type = "user_profile"
                    resource_name = "user"
                elif any(word in path.lower() for word in ["file", "photo", "image"]):
                    endpoint_type = "file"
                    resource_name = "file"
                
                # Check if it's marked as secure
                is_secure = "secure" in path.lower() or "safe" in path.lower()
                
                endpoints.append({
                    "path": path,
                    "method": method,
                    "type": endpoint_type,
                    "resource_name": resource_name,
                    "id_params": id_params,
                    "is_secure": is_secure,
                    "summary": details.get("summary", ""),
                    "tags": details.get("tags", [])
                })
    
    return endpoints

def find_resource_discovery_endpoints(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Find endpoints that list user's own resources"""
    discovery_endpoints = []
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        if "get" not in methods:
            continue
            
        # Look for "mine", "my", or user-specific list endpoints
        if re.search(r"/(mine|my)\b", path.lower()):
            discovery_endpoints.append({
                "path": path,
                "type": "resource_list",
                "resource_type": extract_resource_type(path)
            })
    
    return discovery_endpoints

def extract_resource_type(path: str) -> str:
    """Extract resource type from path"""
    if "/orders/" in path:
        return "orders"
    elif "/documents/" in path:
        return "documents"
    elif "/users/" in path:
        return "users"
    elif "/files/" in path:
        return "files"
    else:
        return "unknown"

def generate_probe_ids(known_ids: List[int], probe_range: int = 5) -> List[int]:
    """Generate probe IDs around known valid IDs"""
    probe_ids = set()
    
    for base_id in known_ids:
        # Add nearby IDs
        for offset in range(-probe_range, probe_range + 1):
            if offset != 0:  # Don't probe our own IDs
                candidate = base_id + offset
                if candidate > 0:
                    probe_ids.add(candidate)
    
    # Add some common ID patterns
    common_ids = [1, 2, 3, 100, 101, 102, 200, 201, 202, 999, 1000]
    for cid in common_ids:
        if cid not in known_ids:
            probe_ids.add(cid)
    
    return sorted(list(probe_ids))[:20]  # Limit probe count

def infer_owner_field(obj: Dict[str, Any]) -> str:
    """Infer the ownership field from a resource object"""
    for field in OWNER_FIELD_CANDIDATES:
        if field in obj and isinstance(obj[field], (int, str)):
            return field
    
    for key, value in obj.items():
        if isinstance(value, (int, str)):
            lower = key.lower()
            if "owner" in lower or ("user" in lower and "id" in lower):
                return key
    
    return "owner_id"


def extract_resource_ids(payload: Union[Dict[str, Any], List[Any]], my_user_id: Optional[int]) -> List[int]:
    """Collect resource identifiers from varied payload structures"""
    results: set[int] = set()

    def walker(node: Union[Dict[str, Any], List[Any], Any], owner_hint: Optional[Union[int, str]] = None):
        if isinstance(node, dict):
            local_owner = owner_hint
            for key, value in node.items():
                if isinstance(value, (int, str)):
                    lower = key.lower()
                    if lower in OWNER_FIELD_CANDIDATES or "owner" in lower:
                        local_owner = value
                    if lower == "id" or lower.endswith("_id"):
                        if isinstance(value, int):
                            if local_owner is None or my_user_id is None or str(local_owner) == str(my_user_id):
                                results.add(value)
                elif isinstance(value, (dict, list)):
                    walker(value, local_owner)
        elif isinstance(node, list):
            for item in node:
                walker(item, owner_hint)

    walker(payload)
    return sorted(results)


def build_secure_endpoint_lookup(resource_types: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    lookup: Dict[str, List[Dict[str, Any]]] = {}
    for resource in resource_types:
        res_type = resource["type"]
        sec = [ep for ep in resource["endpoints"] if ep.get("is_secure")]
        if sec:
            lookup[res_type] = sec
    return lookup


def discover_ids_for_endpoint(state: AgentState, endpoint: Dict[str, Any], secure_lookup: Dict[str, List[Dict[str, Any]]], limit: int = 3) -> List[int]:
    """Probe common ID ranges to locate resources owned by the current user"""
    id_params = endpoint.get("id_params") or []
    if not id_params:
        return []
    id_param = id_params[0]
    base_url = state["base_url"]
    token = state["token"]
    results: List[int] = []

    secure_candidates = secure_lookup.get(endpoint["type"], [])
    secure_endpoint = secure_candidates[0] if secure_candidates else None

    for candidate in DEFAULT_ID_CANDIDATES:
        path = endpoint["path"].replace(f"{{{id_param}}}", str(candidate))
        sc, body = _get(base_url, path, token)
        if sc != 200 or not isinstance(body, dict):
            continue

        owner_field = infer_owner_field(body)
        owner_value = body.get(owner_field)
        if owner_value is not None and state.get("my_user_id") is not None:
            if str(owner_value) != str(state["my_user_id"]):
                continue

        if secure_endpoint:
            secure_path = secure_endpoint["path"].replace(f"{{{id_param}}}", str(candidate))
            sc_secure, _ = _get(base_url, secure_path, token)
            if sc_secure != 200:
                continue

        results.append(candidate)
        if len(results) >= limit:
            break

    return results

# ----------------- Graph Nodes -----------------
def node_login(state: AgentState) -> AgentState:
    """Authenticate with the target application"""
    try:
        r = _post(state["base_url"], "/login", {
            "username": state["username"], 
            "password": state["password"]
        })
        r.raise_for_status()
        token = r.json()["token"]
        print(f"[bold cyan]✓ Login[/] successful as {state['username']}")
        return {"token": token}
    except Exception as e:
        print(f"[red]✗ Login failed: {e}[/]")
        raise

def node_discover_user(state: AgentState) -> AgentState:
    """Get current user information"""
    sc, body = _get(state["base_url"], "/me", state["token"])
    if sc != 200 or not isinstance(body, dict):
        raise RuntimeError("Cannot get current user info")
    
    user_id = body.get("user_id")
    print(f"[bold cyan]✓ User Discovery[/] - ID: {user_id}")
    return {"my_user_id": user_id}

def node_fetch_openapi(state: AgentState) -> AgentState:
    """Fetch OpenAPI specification"""
    for endpoint in ["/openapi.json", "/swagger.json", "/api-docs"]:
        sc, body = _get(state["base_url"], endpoint)
        if sc == 200 and isinstance(body, dict) and "paths" in body:
            print(f"[bold cyan]✓ OpenAPI[/] found at {endpoint}")
            return {"openapi": body}
    
    raise RuntimeError("OpenAPI specification not found")

def node_analyze_endpoints(state: AgentState) -> AgentState:
    """Analyze OpenAPI spec to find potential IDOR endpoints"""
    spec = state["openapi"]
    endpoints = discover_endpoints(spec)
    discovery_endpoints = find_resource_discovery_endpoints(spec)
    
    # Group endpoints by resource type
    resource_types = {}
    for ep in endpoints:
        res_type = ep["type"]
        if res_type not in resource_types:
            resource_types[res_type] = {
                "type": res_type,
                "endpoints": [],
                "discovery_endpoint": None
            }
        resource_types[res_type]["endpoints"].append(ep)
    
    # Match discovery endpoints
    for disc_ep in discovery_endpoints:
        res_type_from_path = disc_ep["resource_type"]
        for rt_name, rt_data in resource_types.items():
            # Match orders with order, documents with document, etc.
            if (res_type_from_path == "orders" and rt_name == "order") or \
               (res_type_from_path == "documents" and rt_name == "document") or \
               (res_type_from_path == "users" and rt_name == "user_profile") or \
               (res_type_from_path in rt_name or rt_name in res_type_from_path):
                rt_data["discovery_endpoint"] = disc_ep
                break
    
    print(f"[bold cyan]✓ Endpoint Analysis[/] - Found {len(endpoints)} potential IDOR endpoints across {len(resource_types)} resource types")
    
    return {
        "target_endpoints": endpoints,
        "resource_types": list(resource_types.values())
    }

def node_discover_resources(state: AgentState) -> AgentState:
    """Discover user's own resources"""
    observations = []
    
    for resource_type in state["resource_types"]:
        if resource_type["discovery_endpoint"]:
            disc_path = resource_type["discovery_endpoint"]["path"]
            sc, body = _get(state["base_url"], disc_path, state["token"])
            
            if sc == 200 and isinstance(body, (dict, list)):
                resource_ids = extract_resource_ids(body, state.get("my_user_id"))
                
                observations.append({
                    "type": "resource_discovery",
                    "resource_type": resource_type["type"],
                    "endpoint": disc_path,
                    "status": sc,
                    "resource_ids": resource_ids,
                    "body": body
                })
                print(f"[bold cyan]✓ Resource Discovery[/] - Found {len(resource_ids)} {resource_type['type']} resources")
    
    return {"observations": observations}

def node_probe_vulnerabilities(state: AgentState) -> AgentState:
    """Probe for IDOR vulnerabilities"""
    observations = state.get("observations", [])
    
    # Get known resource IDs by type
    known_resources = {}
    for obs in observations:
        if obs["type"] == "resource_discovery":
            known_resources[obs["resource_type"]] = obs["resource_ids"]
    
    secure_lookup = build_secure_endpoint_lookup(state["resource_types"])

    for resource_type in state["resource_types"]:
        rt_name = resource_type["type"]
        known_ids = known_resources.get(rt_name, [])
        
        if not known_ids:
            probe_source = next((ep for ep in resource_type["endpoints"] if not ep.get("is_secure")), None)
            if probe_source:
                discovered = discover_ids_for_endpoint(state, probe_source, secure_lookup)
                if discovered:
                    known_ids = discovered
                    print(f"[bold cyan]✓ Active Discovery[/] - Located {len(known_ids)} {rt_name} resources via probing")
        
        if not known_ids:
            print(f"[yellow]Unable to discover owned resources for {rt_name}; skipping[/]")
            continue
            
        probe_ids = generate_probe_ids(known_ids)
        
        for endpoint in resource_type["endpoints"]:
            if endpoint["is_secure"]:
                continue  # Skip secure endpoints for now
                
            path_template = endpoint["path"]
            id_param = endpoint["id_params"][0] if endpoint["id_params"] else "id"
            
            # Test baseline (our own resource)
            baseline_id = known_ids[0]
            baseline_path = path_template.replace(f"{{{id_param}}}", str(baseline_id))
            sc_baseline, body_baseline = _get(state["base_url"], baseline_path, state["token"])
            
            if sc_baseline == 200 and isinstance(body_baseline, dict):
                owner_field = infer_owner_field(body_baseline)
                my_owner_value = body_baseline.get(owner_field, state["my_user_id"])
                
                observations.append({
                    "type": "baseline_test",
                    "endpoint": endpoint,
                    "resource_id": baseline_id,
                    "status": sc_baseline,
                    "body": body_baseline,
                    "owner_field": owner_field,
                    "owner_value": my_owner_value
                })
                
                print(f"[dim]Baseline test for {endpoint['path']} - owner_field: {owner_field}, value: {my_owner_value}[/]")
                
                # Probe other IDs
                for probe_id in probe_ids:
                    probe_path = path_template.replace(f"{{{id_param}}}", str(probe_id))
                    sc_probe, body_probe = _get(state["base_url"], probe_path, state["token"])
                    
                    # Also test secure version if available
                    sc_secure, body_secure = None, None
                    secure_endpoint = None
                    candidates = secure_lookup.get(endpoint["type"], [])
                    for sec_ep in candidates:
                        sec_params = sec_ep.get("id_params") or []
                        sec_param = sec_params[0] if sec_params else None
                        if sec_param and sec_param != id_param:
                            continue
                        secure_path = sec_ep["path"].replace(f"{{{id_param}}}", str(probe_id))
                        sc_secure, body_secure = _get(state["base_url"], secure_path, state["token"])
                        secure_endpoint = sec_ep
                        break
                    
                    observations.append({
                        "type": "probe_test",
                        "endpoint": endpoint,
                        "secure_endpoint": secure_endpoint,
                        "resource_id": probe_id,
                        "status": sc_probe,
                        "body": body_probe,
                        "status_secure": sc_secure,
                        "body_secure": body_secure,
                        "owner_field": owner_field,
                        "expected_owner": my_owner_value
                    })
                    
                    print(f"[dim]Probe {probe_id}: status={sc_probe}, secure_status={sc_secure}[/]")
    
    print(f"[bold cyan]✓ Vulnerability Probing[/] - Completed {len([o for o in observations if o['type'] == 'probe_test'])} probes")
    return {"observations": observations}

def node_analyze_vulnerabilities(state: AgentState) -> AgentState:
    """Analyze probe results for IDOR vulnerabilities"""
    observations = state["observations"]
    vulnerabilities = []
    
    print(f"[cyan]Analyzing {len(observations)} observations for vulnerabilities...[/]")
    
    for obs in observations:
        if obs["type"] != "probe_test":
            continue
            
        # Check for IDOR indicators
        if obs["status"] == 200 and isinstance(obs["body"], dict):
            owner_field = obs["owner_field"]
            expected_owner = obs["expected_owner"]
            
            # Check if we accessed someone else's resource
            if owner_field and owner_field in obs["body"]:
                actual_owner = obs["body"][owner_field]
                
                # Compare with secure endpoint result (if exists)
                secure_blocks_access = obs.get("status_secure") in [401, 403, 404]
                
                # IDOR detected if:
                # 1. We got 200 status on insecure endpoint
                # 2. The resource belongs to a different user 
                # 3. The secure endpoint blocks access (or no secure endpoint exists)
                if str(actual_owner) != str(expected_owner):
                    # If no secure endpoint, still flag as potential IDOR
                    if obs.get("secure_endpoint") is None or secure_blocks_access:
                        vulnerabilities.append({
                            "type": "idor",
                            "severity": "high",
                            "endpoint": obs["endpoint"],
                            "secure_endpoint": obs.get("secure_endpoint"),
                            "resource_id": obs["resource_id"],
                            "actual_owner": actual_owner,
                            "expected_owner": expected_owner,
                            "owner_field": owner_field,
                            "evidence": {
                                "vulnerable_response": obs["body"],
                                "secure_response_status": obs.get("status_secure"),
                                "vulnerable_status": obs["status"]
                            }
                        })
                        print(f"[red]🚨 IDOR found: {obs['endpoint']['path']} - resource {obs['resource_id']} owned by {actual_owner}, accessed by user {expected_owner}[/]")
    
    print(f"[bold red]⚠ Vulnerability Analysis[/] - Found {len(vulnerabilities)} IDOR vulnerabilities")
    return {"vulnerabilities": vulnerabilities}

def node_generate_report(state: AgentState) -> AgentState:
    """Generate detailed vulnerability report"""
    vulnerabilities = state["vulnerabilities"]
    base_url = state["base_url"]
    
    if not vulnerabilities:
        report = generate_clean_report()
    else:
        report = generate_vulnerability_report(vulnerabilities, base_url, state)
    
    # Save report
    with open("enhanced_idor_report.md", "w", encoding="utf-8") as f:
        f.write(report)
    
    print(f"[bold green]✓ Report Generated[/] - enhanced_idor_report.md")
    return {"report_md": report}

def generate_clean_report() -> str:
    return """# Enhanced IDOR Vulnerability Report

## Executive Summary
**Status**: ✅ No IDOR vulnerabilities detected

## Findings
The automated scan did not identify any Insecure Direct Object Reference vulnerabilities in the tested endpoints.

## Recommendations
- Continue implementing proper access controls
- Regularly audit object-level permissions
- Consider implementing additional security testing

---
*Report generated by Enhanced IDOR Detection Agent*
"""

def generate_vulnerability_report(vulnerabilities: List[Dict], base_url: str, state: AgentState) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report_lines = [
        "# Enhanced IDOR Vulnerability Report",
        "",
        f"**Generated**: {timestamp}",
        f"**Target**: {base_url}",
        f"**Test User**: {state['username']} (ID: {state['my_user_id']})",
        "",
        "## Executive Summary",
        f"**Status**: 🚨 {len(vulnerabilities)} IDOR vulnerabilities detected",
        "",
        "**Risk Level**: HIGH - Unauthorized access to sensitive resources",
        "",
        "## Vulnerability Details",
        ""
    ]
    
    for i, vuln in enumerate(vulnerabilities, 1):
        endpoint = vuln["endpoint"]
        secure_endpoint = vuln.get("secure_endpoint")
        
        report_lines.extend([
            f"### {i}. IDOR in {endpoint['path']}",
            "",
            f"**Resource Type**: {endpoint['type']}",
            f"**Affected Resource ID**: {vuln['resource_id']}",
            f"**Owner Field**: `{vuln['owner_field']}`",
            f"**Actual Owner**: {vuln['actual_owner']}",
            f"**Current User**: {vuln['expected_owner']}",
            "",
            "**Proof of Concept**:",
            "```bash",
            "# 1. Login and get token",
            f"curl -X POST {base_url}/login \\",
            '  -H "Content-Type: application/json" \\',
            f'  -d \'{{"username": "{state["username"]}", "password": "***"}}\'',
            "",
            "# 2. Access unauthorized resource (returns 200)",
            "curl -H 'Authorization: Bearer <TOKEN>' \\",
            f"  {base_url}{endpoint['path'].replace('{' + endpoint['id_params'][0] + '}', str(vuln['resource_id']))}",
            ""
        ])
        
        if secure_endpoint:
            report_lines.extend([
                f"# 3. Compare with secure endpoint (returns {vuln['evidence']['secure_response_status']})",
                f"curl -H 'Authorization: Bearer <TOKEN>' \\",
                f"  {base_url}{secure_endpoint['path'].replace('{' + secure_endpoint['id_params'][0] + '}', str(vuln['resource_id']))}",
                ""
            ])
        
        report_lines.extend([
            "```",
            "",
            "**Impact**: Unauthorized access to sensitive user data",
            "",
            "---",
            ""
        ])
    
    report_lines.extend([
        "## Remediation Recommendations",
        "",
        "### Immediate Actions",
        "1. **Implement Object-Level Access Control**: Verify resource ownership before returning data",
        "2. **Add Authorization Checks**: Ensure `resource.owner_id == current_user.id` or user has admin privileges",
        "3. **Return 403 Forbidden**: When users attempt to access unauthorized resources",
        "",
        "### Code Example (Python/Flask)",
        "```python",
        "@app.get('/orders/<int:order_id>')",
        "def get_order_secure(order_id):",
        "    # Authenticate user",
        "    claims = authenticate_token(request.headers.get('Authorization'))",
        "    if not claims:",
        "        return jsonify({'error': 'unauthorized'}), 401",
        "    ",
        "    # Fetch resource",
        "    order = get_order_by_id(order_id)",
        "    if not order:",
        "        return jsonify({'error': 'not found'}), 404",
        "    ",
        "    # Verify ownership (CRITICAL STEP)",
        "    if order.owner_id != claims['user_id'] and claims.get('role') != 'admin':",
        "        logger.warning(f'User {claims[\"user_id\"]} attempted to access order {order_id} owned by {order.owner_id}')",
        "        return jsonify({'error': 'forbidden'}), 403",
        "    ",
        "    return jsonify(order.to_dict())",
        "```",
        "",
        "### Long-term Security Measures",
        "- Implement comprehensive security testing in CI/CD",
        "- Regular security audits and penetration testing",
        "- Security awareness training for development teams",
        "- Implement centralized authorization mechanisms",
        "",
        "---",
        "*This report is for educational and defensive security purposes only.*"
    ])
    
    return "\n".join(report_lines)

# ----------------- Graph Construction -----------------
def build_graph():
    g = StateGraph(AgentState)
    
    # Add nodes
    g.add_node("login", node_login)
    g.add_node("discover_user", node_discover_user)
    g.add_node("fetch_openapi", node_fetch_openapi)
    g.add_node("analyze_endpoints", node_analyze_endpoints)
    g.add_node("discover_resources", node_discover_resources)
    g.add_node("probe_vulnerabilities", node_probe_vulnerabilities)
    g.add_node("analyze_vulnerabilities", node_analyze_vulnerabilities)
    g.add_node("generate_report", node_generate_report)
    
    # Define flow
    g.set_entry_point("login")
    g.add_edge("login", "discover_user")
    g.add_edge("discover_user", "fetch_openapi")
    g.add_edge("fetch_openapi", "analyze_endpoints")
    g.add_edge("analyze_endpoints", "discover_resources")
    g.add_edge("discover_resources", "probe_vulnerabilities")
    g.add_edge("probe_vulnerabilities", "analyze_vulnerabilities")
    g.add_edge("analyze_vulnerabilities", "generate_report")
    g.add_edge("generate_report", END)
    
    return g.compile()

class EnhancedIDORAgent:
    """Enhanced IDOR Detection Agent
    
    A comprehensive IDOR vulnerability detection agent that provides advanced features:
    - Multi-endpoint discovery via OpenAPI
    - Smart probe generation with advanced patterns
    - Pattern-based vulnerability detection
    - Detailed reporting with PoC generation
    - Enhanced error handling and logging
    
    Args:
        base_url (str): Target application base URL
        username (str): Username for authentication  
        password (str): Password for authentication
        verbose (bool): Enable verbose output for debugging
    
    Example:
        # Using as a class
        agent = EnhancedIDORAgent(
            base_url="http://127.0.0.1:5005",
            username="bob", 
            password="bob123",
            verbose=True
        )
        result = agent.run()
        
        # Or run directly
        python enhanced_agent.py --base-url http://127.0.0.1:5005 --username bob --verbose
    """
    
    def __init__(self, base_url: str = "http://127.0.0.1:5005", username: str = "bob", password: str = "bob123", verbose: bool = False):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.verbose = verbose
        self.graph = build_graph()
    
    def run(self) -> Dict[str, Any]:
        """Run the enhanced IDOR detection scan
        
        Returns:
            Dict containing the final scan results including vulnerabilities and report
        """
        print("[bold blue]🤖 Enhanced IDOR Detection Agent Starting...[/]")
        print(f"[dim]Target: {self.base_url}[/]")
        print(f"[dim]User: {self.username}[/]")
        
        try:
            final_state = self.graph.invoke({
                "base_url": self.base_url,
                "username": self.username,
                "password": self.password
            })
            
            vuln_count = len(final_state.get("vulnerabilities", []))
            if vuln_count > 0:
                print(f"[bold red]🚨 Detected {vuln_count} IDOR vulnerabilities![/]")
            else:
                print("[bold green]✅ No IDOR vulnerabilities detected[/]")
                
            print("[bold]📋 Report: enhanced_idor_report.md[/]")
            
            return final_state
            
        except Exception as e:
            print(f"[bold red]❌ Agent failed: {e}[/]")
            if self.verbose:
                import traceback
                traceback.print_exc()
            raise

def main():
    """Command line interface for EnhancedIDORAgent"""
    parser = argparse.ArgumentParser(description="Enhanced IDOR Detection Agent")
    parser.add_argument("--base-url", default="http://127.0.0.1:5005", help="Target application base URL")
    parser.add_argument("--username", default="bob", help="Username for authentication")
    parser.add_argument("--password", default="bob123", help="Password for authentication")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Create and run the agent
    agent = EnhancedIDORAgent(
        base_url=args.base_url,
        username=args.username,
        password=args.password,
        verbose=args.verbose
    )
    
    try:
        agent.run()
    except Exception as e:
        print(f"[red]Error: {e}[/]")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
