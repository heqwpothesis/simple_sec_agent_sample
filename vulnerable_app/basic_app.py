from flask import Flask, request, jsonify
import time, jwt


def create_basic_app():
    """Create a basic vulnerable Flask app with IDOR vulnerabilities."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "demo-secret"

    # 伪数据库
    USERS = {
        "alice": {"password": "alice123", "user_id": 1, "role": "user"},
        "bob":   {"password": "bob123",   "user_id": 2, "role": "user"},
        "admin": {"password": "admin123", "user_id": 999, "role": "admin"},
    }
    # 订单：order_id -> {owner_id, items}
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

    @app.post("/login")
    def login():
        data = request.get_json(force=True)
        u = USERS.get(data.get("username"))
        if not u or u["password"] != data.get("password"):
            return jsonify({"error": "invalid credentials"}), 401
        return jsonify({"token": make_token(u["user_id"], u["role"])})

    def _auth():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth.split(" ", 1)[1]
        try:
            return decode_token(token)
        except Exception:
            return None

    # 漏洞接口：缺少所有权校验 —— 只要登录了就能看任意 order_id
    @app.get("/orders/<int:order_id>")
    def get_order_insecure(order_id):
        claims = _auth()
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        order = ORDERS.get(order_id)
        if not order:
            return jsonify({"error": "not found"}), 404
        # 漏洞点：没有检查 order["owner_id"] == claims["user_id"]
        return jsonify({"order_id": order_id, "owner_id": order["owner_id"], "items": order["items"]})

    # 正确示例：做所有权校验
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

    return app


if __name__ == "__main__":
    app = create_basic_app()
    app.run(host="127.0.0.1", port=5005, debug=False)
