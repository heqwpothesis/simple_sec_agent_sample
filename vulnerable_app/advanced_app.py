from flask import Flask, request, jsonify
import time, jwt


def create_advanced_app():
    """Create an advanced vulnerable Flask app with multiple IDOR scenarios."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "demo-secret"

    # ---- 伪数据库 ----
    USERS = {
        "alice": {"password": "alice123", "user_id": 1, "role": "user"},
        "bob":   {"password": "bob123",   "user_id": 2, "role": "user"},
        "admin": {"password": "admin123", "user_id": 999, "role": "admin"},
    }
    ORDERS = {
        101: {"owner_id": 1, "items": ["book", "pen"]},    # alice 的
        102: {"owner_id": 2, "items": ["phone"]},          # bob 的
        103: {"owner_id": 1, "items": ["laptop"]},         # alice 的
    }

    def make_token(user_id, role):
        payload = {"user_id": user_id, "role": role, "iat": int(time.time())}
        return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

    def decode_token(token):
        return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])

    def _auth():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth.split(" ", 1)[1]
        try:
            return decode_token(token)
        except Exception:
            return None

    @app.post("/login")
    def login():
        data = request.get_json(force=True)
        u = USERS.get(data.get("username"))
        if not u or u["password"] != data.get("password"):
            return jsonify({"error": "invalid credentials"}), 401
        return jsonify({"token": make_token(u["user_id"], u["role"])})

    # 身份查询（便于 Agent 获取 my_user_id）
    @app.get("/me")
    def me():
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        return jsonify({"user_id": claims["user_id"], "role": claims["role"]})

    # "我的订单"列表（让 Agent 能自动发现我的资源）
    @app.get("/orders/mine")
    def list_mine():
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        my_id = claims["user_id"]
        data = [{"order_id": oid, **info} for oid, info in ORDERS.items() if info["owner_id"] == my_id]
        return jsonify({"orders": data})

    # 漏洞接口：缺少所有权校验
    @app.get("/orders/<int:order_id>")
    def get_order_insecure(order_id):
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        order = ORDERS.get(order_id)
        if not order:
            return jsonify({"error": "not found"}), 404
        # 漏洞：未校验 owner
        return jsonify({"order_id": order_id, "owner_id": order["owner_id"], "items": order["items"]})

    # 正确接口：对象级访问控制
    @app.get("/orders/secure/<int:order_id>")
    def get_order_secure(order_id):
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        order = ORDERS.get(order_id)
        if not order:
            return jsonify({"error": "not found"}), 404
        if order["owner_id"] != claims["user_id"] and claims.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"order_id": order_id, "owner_id": order["owner_id"], "items": order["items"]})

    # 文档查看（更多 IDOR 场景）
    DOCUMENTS = {
        201: {"owner_id": 1, "title": "Alice's Private Contract", "content": "Confidential business terms..."},
        202: {"owner_id": 2, "title": "Bob's Invoice", "content": "Payment details for services..."},
        203: {"owner_id": 1, "title": "Alice's Medical Record", "content": "Sensitive health information..."},
    }

    @app.get("/documents/<int:doc_id>")
    def get_document_insecure(doc_id):
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        doc = DOCUMENTS.get(doc_id)
        if not doc:
            return jsonify({"error": "not found"}), 404
        # 漏洞：未校验文档所有权
        return jsonify({"doc_id": doc_id, **doc})

    @app.get("/documents/secure/<int:doc_id>")
    def get_document_secure(doc_id):
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        doc = DOCUMENTS.get(doc_id)
        if not doc:
            return jsonify({"error": "not found"}), 404
        if doc["owner_id"] != claims["user_id"] and claims.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"doc_id": doc_id, **doc})

    @app.get("/documents/mine")
    def list_my_documents():
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        my_id = claims["user_id"]
        data = [{"doc_id": did, **info} for did, info in DOCUMENTS.items() if info["owner_id"] == my_id]
        return jsonify({"documents": data})

    # 用户资料（另一种 IDOR 场景）
    @app.get("/users/<int:user_id>/profile")
    def get_user_profile_insecure(user_id):
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        # 查找用户
        user_info = None
        for username, info in USERS.items():
            if info["user_id"] == user_id:
                user_info = {"username": username, "user_id": user_id, "role": info["role"]}
                break
        if not user_info:
            return jsonify({"error": "user not found"}), 404
        # 漏洞：任何已认证用户都能查看他人资料
        return jsonify(user_info)

    @app.get("/users/secure/<int:user_id>/profile")
    def get_user_profile_secure(user_id):
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        # 只能查看自己的资料（除非是管理员）
        if user_id != claims["user_id"] and claims.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
        # 查找用户
        user_info = None
        for username, info in USERS.items():
            if info["user_id"] == user_id:
                user_info = {"username": username, "user_id": user_id, "role": info["role"]}
                break
        if not user_info:
            return jsonify({"error": "user not found"}), 404
        return jsonify(user_info)

    # OpenAPI（完整 v3，供 Agent 自动枚举）
    @app.get("/openapi.json")
    def openapi():
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "IDOR Demo API", "version": "1.0.0", "description": "Educational IDOR vulnerability demonstration"},
            "servers": [{"url": "http://127.0.0.1:5005", "description": "Local development server"}],
            "paths": {
                "/login": {
                    "post": {
                        "summary": "User authentication",
                        "tags": ["Authentication"],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"}
                                        },
                                        "required": ["username", "password"]
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "Login successful"}, "401": {"description": "Invalid credentials"}}
                    }
                },
                "/me": {
                    "get": {
                        "summary": "Get current user info",
                        "tags": ["User"],
                        "security": [{"BearerAuth": []}],
                        "responses": {"200": {"description": "User info"}, "401": {"description": "Unauthorized"}}
                    }
                },
                "/orders/mine": {
                    "get": {
                        "summary": "List current user's orders",
                        "tags": ["Orders"],
                        "security": [{"BearerAuth": []}],
                        "responses": {"200": {"description": "List of orders"}}
                    }
                },
                "/orders/{order_id}": {
                    "get": {
                        "summary": "Get order by ID (vulnerable to IDOR)",
                        "tags": ["Orders"],
                        "security": [{"BearerAuth": []}],
                        "parameters": [{"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "Order details"}, "404": {"description": "Order not found"}}
                    }
                },
                "/orders/secure/{order_id}": {
                    "get": {
                        "summary": "Get order by ID (secure with access control)",
                        "tags": ["Orders"],
                        "security": [{"BearerAuth": []}],
                        "parameters": [{"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "Order details"}, "403": {"description": "Access denied"}, "404": {"description": "Order not found"}}
                    }
                },
                "/documents/{doc_id}": {
                    "get": {
                        "summary": "Get document by ID (vulnerable to IDOR)",
                        "tags": ["Documents"],
                        "security": [{"BearerAuth": []}],
                        "parameters": [{"name": "doc_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "Document details"}, "404": {"description": "Document not found"}}
                    }
                },
                "/documents/secure/{doc_id}": {
                    "get": {
                        "summary": "Get document by ID (secure with access control)",
                        "tags": ["Documents"],
                        "security": [{"BearerAuth": []}],
                        "parameters": [{"name": "doc_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "Document details"}, "403": {"description": "Access denied"}, "404": {"description": "Document not found"}}
                    }
                },
                "/documents/mine": {
                    "get": {
                        "summary": "List current user's documents",
                        "tags": ["Documents"],
                        "security": [{"BearerAuth": []}],
                        "responses": {"200": {"description": "List of documents"}}
                    }
                },
                "/users/{user_id}/profile": {
                    "get": {
                        "summary": "Get user profile (vulnerable to IDOR)",
                        "tags": ["Users"],
                        "security": [{"BearerAuth": []}],
                        "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "User profile"}, "404": {"description": "User not found"}}
                    }
                },
                "/users/secure/{user_id}/profile": {
                    "get": {
                        "summary": "Get user profile (secure with access control)",
                        "tags": ["Users"],
                        "security": [{"BearerAuth": []}],
                        "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "User profile"}, "403": {"description": "Access denied"}, "404": {"description": "User not found"}}
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            }
        }
        return jsonify(spec)

    return app


if __name__ == "__main__":
    app = create_advanced_app()
    app.run(host="127.0.0.1", port=5005, debug=False)
