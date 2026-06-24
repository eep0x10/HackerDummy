#!/usr/bin/env python3
"""
ShopAPI - Deliberately vulnerable JSON REST API for pentest training (OWASP API Top 10).

  *** INTENTIONALLY VULNERABLE - LOCALHOST ONLY ***

Single-file, stdlib-only (http.server + sqlite3 + hmac/hashlib/base64 + json).
NO external deps, NO PyJWT - JWT is built and verified by hand. Run on
127.0.0.1:18804 with `python app.py`.

This is a fake e-commerce API ("ShopAPI"). It plants nine OWASP-API-class bugs
(B1..B9). Each one really works. See README.md / gabarito.json for the full map.

Planted vulns (see README for OWASP categories + exploitation):
  B1 BOLA           GET  /api/v1/orders/<id>     any valid token reads any order
  B2 BOLA (PII)     GET  /api/v1/users/<id>      any valid token reads any user
  B3 BFLA           POST /api/v1/admin/promote   no role check -> self-promote
  B4 Mass Assign    PATCH/api/v1/me              blindly applies role/is_admin
  B5 Excess Data    GET  /api/v1/users           leaks password(md5)/ssn/notes
  B6 No rate limit  POST /api/v1/login           unlimited attempts, no lockout
  B7 SSRF           POST /api/v1/avatar          server fetches any url
  B8 Broken Auth    (all)                        alg:none + weak HS256 accepted
  B9 Misconfig      POST /api/v1/orders          full traceback on bad JSON
"""
import base64
import hashlib
import hmac
import http.server
import json
import socketserver
import sqlite3
import threading
import traceback
import urllib.parse
import urllib.request
import urllib.error

HOST, PORT = "127.0.0.1", 18804

# Weak, hardcoded HMAC secret -> trivially brute-forceable / guessable (B8).
JWT_SECRET = b"apisecret"

# "Internal" config that should only ever be reachable from the server itself.
# It is the SSRF target (B7) reachable via POST /api/v1/avatar.
INTERNAL_CONFIG = {
    "db_dsn": "postgres://shopapi:Pr0d-Shop-DB!2026@10.0.0.5:5432/shop",
    "stripe_secret_key": "sk_live_LAB_FAKE_EXAMPLE_4242deadbeef",
    "aws_access_key_id": "AKIA_LAB_FAKE_EXAMPLE_KEY",
    "aws_secret_access_key": "lab/FAKE/secret/EXAMPLE/aws/key",
    "internal_admin_token": "shopapi_root_8f1c9b7a6d5e4f3c2b1a",
    "flag": "flag{ssrf_reached_internal_config}",
}

# --------------------------------------------------------------------------- DB
# A thread-local connection per worker thread (sqlite objects are not safe to
# share across threads). The schema is recreated+seeded once into a shared
# on-disk-less DB via a serialized in-memory copy is awkward, so we use a single
# file-less shared cache DB.
_DB_URI = "file:shopapi_mem?mode=memory&cache=shared"
# Keep one connection alive for the whole process so the shared in-memory DB is
# not dropped when all other connections close.
_keepalive = sqlite3.connect(_DB_URI, uri=True, check_same_thread=False)
_tls = threading.local()


def db():
    conn = getattr(_tls, "conn", None)
    if conn is None:
        conn = sqlite3.connect(_DB_URI, uri=True, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _tls.conn = conn
    return conn


def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def seed_db():
    c = _keepalive
    c.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS orders;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,          -- md5 hash (weak by design)
            email TEXT,
            address TEXT,
            role TEXT,
            ssn TEXT,
            internal_notes TEXT
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            total REAL
        );
        """
    )
    users = [
        # id, username, password(plain->md5), email, address, role, ssn, notes
        (1, "admin",  "admin123",   "admin@shopapi.test",
         "1 Server Rd, DC1", "admin",
         "111-22-3333", "root operator; do not expose"),
        (2, "alice",  "alicepass",  "alice@example.com",
         "12 Maple St, Springfield", "user",
         "222-33-4444", "vip customer, net-30 terms"),
        (3, "bob",    "bobsecret",  "bob@example.com",
         "9 Oak Ave, Shelbyville", "user",
         "333-44-5555", "chargeback risk - watch"),
        (4, "carol",  "carol2024",  "carol@example.com",
         "55 Pine Blvd, Ogdenville", "user",
         "444-55-6666", "employee discount eligible"),
    ]
    for u in users:
        c.execute(
            "INSERT INTO users (id,username,password,email,address,role,ssn,internal_notes)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (u[0], u[1], md5(u[2]), u[3], u[4], u[5], u[6], u[7]),
        )
    orders = [
        (1001, 1, "Datacenter rack unit",  4999.00),
        (1002, 2, "Wireless headphones",    129.99),
        (1003, 2, "USB-C charger",           24.50),
        (1004, 3, "Mechanical keyboard",    109.00),
        (1005, 4, "4K monitor",             349.99),
    ]
    for o in orders:
        c.execute(
            "INSERT INTO orders (id,user_id,item,total) VALUES (?,?,?,?)", o
        )
    c.commit()


# -------------------------------------------------------------------- JWT (hand)
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def jwt_make(payload: dict, alg: str = "HS256") -> str:
    """Build a JWT by hand. Supports HS256 (signed with the weak secret) and
    'none' (unsigned). No 'exp' is added -> tokens never expire (part of B8)."""
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    sig = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def jwt_verify(token: str):
    """VULNERABLE verifier (B8). Returns the decoded payload dict or None.

      (a) accepts alg:'none' with NO signature at all,
      (b) for HS256 verifies against the WEAK hardcoded secret,
      (c) NEVER validates 'exp' (expiry ignored entirely).
    """
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        return None

    alg = header.get("alg", "")

    # (a) alg:none accepted -> any forged payload is trusted, no signature.
    if alg == "none":
        return payload

    # (b) HS256 verified with the weak secret (no alg allow-list enforced).
    if alg == "HS256":
        signing_input = f"{h_b64}.{p_b64}".encode()
        expected = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
        try:
            given = _b64url_decode(sig_b64)
        except Exception:
            return None
        if hmac.compare_digest(expected, given):
            # (c) exp intentionally never checked.
            return payload
        return None

    # Unknown algs rejected (only 'none' and HS256 are honored).
    return None


# ------------------------------------------------------------------ SSRF helper
def server_side_fetch(url, timeout=5):
    # B7: no scheme/destination validation beyond http(s) -> SSRF to internal.
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http/https supported")
    req = urllib.request.Request(url, headers={"User-Agent": "ShopAPI-avatar/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        body = r.read(65536)
        return r.status, body


# ----------------------------------------------------------------- HTTP handler
def row_to_dict(row):
    return {k: row[k] for k in row.keys()}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ShopAPI/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---- io helpers ----
    def _send(self, code, obj):
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _raw_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def _json_body(self):
        """Parse the request body as JSON. Raises on malformed input - callers
        that want verbose errors (B9) let it propagate."""
        raw = self._raw_body()
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _bearer_payload(self):
        """Return the verified JWT payload from Authorization: Bearer <jwt>,
        or None. Uses the VULNERABLE jwt_verify (B8)."""
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return None
        token = auth.split(None, 1)[1].strip()
        return jwt_verify(token)

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"

        # Discoverable index.
        if path in ("/", "/api/v1"):
            return self._send(200, {
                "service": "ShopAPI",
                "version": "v1",
                "endpoints": {
                    "POST /api/v1/login": "{username,password} -> {token}",
                    "GET /api/v1/me": "caller profile (Bearer token)",
                    "PATCH /api/v1/me": "update caller profile (JSON body)",
                    "GET /api/v1/orders/<id>": "fetch an order",
                    "POST /api/v1/orders": "{item} create an order",
                    "GET /api/v1/users": "list users",
                    "GET /api/v1/users/<id>": "fetch a user",
                    "POST /api/v1/admin/promote": "{username,role} promote user",
                    "POST /api/v1/avatar": "{url} import avatar from url",
                    "GET /api/v1/internal/config": "server-only internal config",
                },
            })

        # Server-only internal config: the SSRF target (B7). Refuses non-loopback.
        if path == "/api/v1/internal/config":
            ra = self.client_address[0]
            if ra not in ("127.0.0.1", "::1"):
                return self._send(403, {"error": "internal only"})
            return self._send(200, INTERNAL_CONFIG)

        # GET /api/v1/me -> caller profile from JWT (B8 token verify).
        if path == "/api/v1/me":
            payload = self._bearer_payload()
            if not payload:
                return self._send(401, {"error": "invalid or missing token"})
            row = db().execute(
                "SELECT * FROM users WHERE username=?", (payload.get("sub"),)
            ).fetchone()
            if not row:
                # alg:none forgeries can name a non-existent user; still
                # 'authenticated'. Reflect what the token claims.
                return self._send(200, {
                    "username": payload.get("sub"),
                    "role": payload.get("role"),
                    "note": "no DB record; profile from token claims",
                })
            return self._send(200, row_to_dict(row))

        # GET /api/v1/users -> B5 excessive data exposure (full records).
        if path == "/api/v1/users":
            if not self._bearer_payload():
                return self._send(401, {"error": "invalid or missing token"})
            rows = db().execute("SELECT * FROM users ORDER BY id").fetchall()
            # Intentionally returns EVERYTHING incl. password (md5), ssn, notes.
            out = []
            for r in rows:
                d = row_to_dict(r)
                d["password_hash"] = d.pop("password")  # expose under a clear name
                out.append(d)
            return self._send(200, {"users": out})

        # GET /api/v1/users/<id> -> B2 BOLA on PII (no ownership check).
        if path.startswith("/api/v1/users/"):
            if not self._bearer_payload():
                return self._send(401, {"error": "invalid or missing token"})
            uid = path.rsplit("/", 1)[-1]
            row = db().execute(
                "SELECT * FROM users WHERE id=?", (uid,)
            ).fetchone()
            if not row:
                return self._send(404, {"error": "no such user"})
            d = row_to_dict(row)
            d["password_hash"] = d.pop("password")
            return self._send(200, d)  # any id works -> BOLA

        # GET /api/v1/orders/<id> -> B1 BOLA (no ownership check).
        if path.startswith("/api/v1/orders/"):
            if not self._bearer_payload():
                return self._send(401, {"error": "invalid or missing token"})
            oid = path.rsplit("/", 1)[-1]
            row = db().execute(
                "SELECT * FROM orders WHERE id=?", (oid,)
            ).fetchone()
            if not row:
                return self._send(404, {"error": "no such order"})
            # Token valid -> returns the order regardless of who owns it (BOLA).
            return self._send(200, row_to_dict(row))

        return self._send(404, {"error": "no such endpoint"})

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"

        # POST /api/v1/login -> issues JWT. B6: no rate limiting / lockout.
        if path == "/api/v1/login":
            try:
                body = self._json_body()
            except Exception:
                return self._send(400, {"error": "invalid JSON"})
            username = body.get("username", "")
            password = body.get("password", "")
            row = db().execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
            # B6: every attempt is processed immediately - no counter, no delay,
            # no lockout regardless of how many failures occur.
            if not row or row["password"] != md5(password):
                return self._send(401, {"error": "invalid credentials"})
            token = jwt_make({"sub": row["username"], "role": row["role"]})
            return self._send(200, {"token": token})

        # POST /api/v1/admin/promote -> B3 BFLA (no caller-role check).
        if path == "/api/v1/admin/promote":
            payload = self._bearer_payload()
            if not payload:
                return self._send(401, {"error": "invalid or missing token"})
            # MISSING: any check that payload['role'] == 'admin'. A normal user
            # can call this admin function and promote anyone (incl. self).
            try:
                body = self._json_body()
            except Exception:
                return self._send(400, {"error": "invalid JSON"})
            target = body.get("username", "")
            new_role = body.get("role", "admin")
            cur = db().execute(
                "UPDATE users SET role=? WHERE username=?", (new_role, target)
            )
            db().commit()
            if cur.rowcount == 0:
                return self._send(404, {"error": "no such user"})
            return self._send(200, {
                "promoted": target, "role": new_role,
                "by": payload.get("sub"),
            })

        # POST /api/v1/avatar -> B7 SSRF (server fetches any http(s) url).
        if path == "/api/v1/avatar":
            payload = self._bearer_payload()
            if not payload:
                return self._send(401, {"error": "invalid or missing token"})
            try:
                body = self._json_body()
            except Exception:
                return self._send(400, {"error": "invalid JSON"})
            url = body.get("url", "")
            if not url:
                return self._send(400, {"error": "url required"})
            try:
                status, data = server_side_fetch(url)
                return self._send(200, {
                    "imported": True,
                    "url": url,
                    "status": status,
                    "size": len(data),
                    # Reflect the fetched body so SSRF is demonstrable.
                    "body": data.decode("utf-8", "replace")[:8000],
                })
            except (urllib.error.URLError, ValueError) as e:
                return self._send(502, {"imported": False, "error": str(e)})

        # POST /api/v1/orders -> create order. B9: verbose error / full traceback
        # on malformed JSON or unexpected type (instead of a generic 400/500).
        if path == "/api/v1/orders":
            payload = self._bearer_payload()
            if not payload:
                return self._send(401, {"error": "invalid or missing token"})
            try:
                # Any of these can raise on bad input: json.loads (malformed
                # JSON), body['item'] (KeyError), .strip() (AttributeError if
                # item is not a string). All are deliberately surfaced raw.
                body = self._json_body()
                item = body["item"]
                item = item.strip()
                row = db().execute(
                    "SELECT id FROM users WHERE username=?", (payload.get("sub"),)
                ).fetchone()
                user_id = row["id"] if row else 0
                nid = (db().execute("SELECT COALESCE(MAX(id),1000)+1 AS n FROM orders")
                       .fetchone()["n"])
                db().execute(
                    "INSERT INTO orders (id,user_id,item,total) VALUES (?,?,?,?)",
                    (nid, user_id, item, 0.0),
                )
                db().commit()
                return self._send(201, {"id": nid, "user_id": user_id, "item": item})
            except Exception:
                # Security misconfiguration: leak the FULL Python traceback.
                tb = traceback.format_exc()
                return self._send(500, {
                    "error": "unhandled exception while creating order",
                    "traceback": tb,
                })

        return self._send(404, {"error": "no such endpoint"})

    # ----------------------------------------------------------------- PATCH
    def do_PATCH(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"

        # PATCH /api/v1/me -> B4 mass assignment (blindly applies any field).
        if path == "/api/v1/me":
            payload = self._bearer_payload()
            if not payload:
                return self._send(401, {"error": "invalid or missing token"})
            try:
                body = self._json_body()
            except Exception:
                return self._send(400, {"error": "invalid JSON"})
            row = db().execute(
                "SELECT * FROM users WHERE username=?", (payload.get("sub"),)
            ).fetchone()
            if not row:
                return self._send(404, {"error": "no such user"})

            # B4: NO allow-list. Any column the client supplies is written,
            # including 'role' and 'is_admin' -> privilege escalation.
            allowed_columns = {"username", "password", "email", "address",
                               "role", "ssn", "internal_notes"}
            applied = {}
            for k, v in body.items():
                if k == "password":
                    v = md5(str(v))
                if k in allowed_columns:
                    db().execute(
                        f"UPDATE users SET {k}=? WHERE id=?", (v, row["id"])
                    )
                    applied[k] = v
                else:
                    # Unknown keys (e.g. is_admin) are still "accepted" and
                    # echoed back so a client believes they took effect.
                    applied[k] = v
            db().commit()
            updated = db().execute(
                "SELECT * FROM users WHERE id=?", (row["id"],)
            ).fetchone()
            d = row_to_dict(updated)
            d["password_hash"] = d.pop("password")
            d["applied"] = applied
            return self._send(200, d)

        return self._send(404, {"error": "no such endpoint"})

    # Surface verbose tracebacks (B9) instead of the framework's blank 500.
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except Exception:
            tb = traceback.format_exc()
            try:
                self._send(500, {"error": "internal server error",
                                 "traceback": tb})
            except Exception:
                pass


class TServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    seed_db()
    srv = TServer((HOST, PORT), Handler)
    print(f"ShopAPI (vulnerable API lab) on http://{HOST}:{PORT}  --  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
