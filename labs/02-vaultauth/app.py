#!/usr/bin/env python3
"""
VaultAuth - Deliberately vulnerable identity / auth service for pentest training.

  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

Single-file, stdlib-only (http.server + sqlite3 + hmac/hashlib/base64). No deps,
no PyJWT - JWTs are built/verified by hand so the flaws are explicit.
Run:  python app.py    -> http://127.0.0.1:18802

Focus: authentication, JWT, and session management flaws. See gabarito.json.
  J1 JWT alg:none accepted        J2 JWT weak HMAC secret ('secret')
  J3 JWT expiry not validated     A1 username enumeration
  A2 no rate-limiting / brute     A3 predictable+leaked password-reset token
  A4 OTP/2FA bypass               A5 mass-assignment privilege escalation
  A6 MD5 password storage leak    A7 IDOR on /api/user/<id>
  S2 no token invalidation on logout   S3 predictable 'remember-me' cookie
"""
import base64
import hashlib
import hmac
import json
import sqlite3
import threading
import http.server
import socketserver
import urllib.parse

HOST, PORT = "127.0.0.1", 18802
JWT_SECRET = b"secret"          # J2: laughably weak HMAC secret (crackable in ms)

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.row_factory = sqlite3.Row
_LOCK = threading.Lock()


def md5(s):                      # A6: passwords stored as unsalted MD5
    return hashlib.md5(s.encode()).hexdigest()


def init_db():
    c = _DB.cursor()
    c.executescript("""
      CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pwmd5 TEXT,
                         email TEXT, role TEXT, otp TEXT);
      CREATE TABLE resets(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, token INTEGER);
    """)
    c.executemany("INSERT INTO users(username,pwmd5,email,role,otp) VALUES(?,?,?,?,?)", [
        ("admin",  md5("S3cr3tAdminP@ss"), "admin@vaultauth.local", "admin", "000000"),
        ("alice",  md5("alice123"),        "alice@vaultauth.local", "user",  "111111"),
        ("bob",    md5("bobpassword"),      "bob@vaultauth.local",   "user",  "222222"),
    ])
    _DB.commit()


# --------------------------------------------------------------------------- JWT
def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_make(payload, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    h = _b64u(json.dumps(header).encode())
    p = _b64u(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    sig = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def jwt_verify(token):
    """VULNERABLE verifier:
       J1 - accepts alg:none with NO signature.
       J2 - HS256 verified with the weak secret 'secret'.
       J3 - NEVER checks the 'exp' claim (expired tokens are accepted)."""
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    header = json.loads(_b64u_dec(h_b64))
    payload = json.loads(_b64u_dec(p_b64))
    alg = header.get("alg", "")
    if alg == "none":                                   # J1
        return payload
    if alg == "HS256":
        expect = _b64u(hmac.new(JWT_SECRET, f"{h_b64}.{p_b64}".encode(),
                                hashlib.sha256).digest())
        if hmac.compare_digest(expect, sig_b64):
            return payload                              # J3: exp never checked
        return None
    return None


# ------------------------------------------------------------------------ helpers
def q1(sql, args=()):
    with _LOCK:
        return _DB.execute(sql, args).fetchone()


def qx(sql, args=()):
    with _LOCK:
        cur = _DB.execute(sql, args)
        _DB.commit()
        return cur


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "VaultAuth/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj, ctype="application/json", extra=None):
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        try:
            return json.loads(raw) if raw.strip().startswith("{") else \
                {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        except Exception:
            return {}

    def _bearer(self):
        h = self.headers.get("Authorization", "")
        return h[7:].strip() if h.lower().startswith("bearer ") else None

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(200, {"service": "VaultAuth",
                "endpoints": ["/register", "/login", "/verify-otp", "/me", "/logout",
                              "/reset-request", "/reset", "/admin", "/api/user/<id>", "/debug"]})

        if path == "/me":                                       # uses JWT
            tok = self._bearer()
            payload = jwt_verify(tok) if tok else None
            if not payload:
                return self._send(401, {"error": "invalid or missing token"})
            row = q1("SELECT id,username,email,role FROM users WHERE username=?",
                     (payload.get("sub", ""),))
            who = dict(row) if row else {"username": payload.get("sub"),
                                         "role": payload.get("role")}
            return self._send(200, {"profile": who, "claims": payload})

        if path == "/admin":                                    # role from JWT claim only
            tok = self._bearer()
            payload = jwt_verify(tok) if tok else None
            if not payload or payload.get("role") != "admin":
                return self._send(403, {"error": "admins only"})
            users = [dict(r) for r in
                     _DB.execute("SELECT id,username,pwmd5,email,role FROM users")]
            return self._send(200, {"users": users})            # A6: leaks pwmd5

        if path == "/debug":                                    # A6: storage leak, no auth
            users = [dict(r) for r in
                     _DB.execute("SELECT username,pwmd5,role,otp FROM users")]
            return self._send(200, {"note": "stored credentials (md5, unsalted)",
                                    "users": users})

        if path.startswith("/api/user/"):                      # A7: IDOR, no auth
            uid = path.rsplit("/", 1)[-1]
            row = q1("SELECT id,username,email,role FROM users WHERE id=?", (uid,))
            if not row:
                return self._send(404, {"error": "not found"})
            return self._send(200, dict(row))

        return self._send(404, {"error": "no such endpoint"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        body = self._json_body()

        if path == "/register":
            u = (body.get("username") or "").strip()
            p = body.get("password") or ""
            role = body.get("role") or "user"                   # A5: mass-assignment
            if not u or not p:
                return self._send(400, {"error": "username and password required"})
            if q1("SELECT 1 FROM users WHERE username=?", (u,)):
                return self._send(409, {"error": f"username '{u}' already exists"})  # A1
            qx("INSERT INTO users(username,pwmd5,email,role,otp) VALUES(?,?,?,?,?)",
               (u, md5(p), f"{u}@vaultauth.local", role, "123456"))
            return self._send(201, {"created": u, "role": role})

        if path == "/login":
            u = (body.get("username") or "").strip()
            p = body.get("password") or ""
            row = q1("SELECT username,pwmd5,role,otp FROM users WHERE username=?", (u,))
            if not row:                                          # A1: user enumeration
                return self._send(404, {"error": "no such user"})
            if row["pwmd5"] != md5(p):                           # A1 + A2: distinct msg, no lockout
                return self._send(401, {"error": "incorrect password"})
            # A4: OTP leaked straight back in the response ("dev convenience")
            # S3: predictable remember-me cookie = base64(username)
            remember = base64.b64encode(u.encode()).decode()
            return self._send(200, {
                "message": "password ok, submit OTP to /verify-otp",
                "otp_hint": row["otp"],
            }, extra={"Set-Cookie": f"remember={remember}; Path=/"})

        if path == "/verify-otp":
            u = (body.get("username") or "").strip()
            otp = str(body.get("otp") or "")
            row = q1("SELECT username,role,otp FROM users WHERE username=?", (u,))
            if not row:
                return self._send(404, {"error": "no such user"})
            # A4: OTP "validated" but accepts 000000 master code AND is not rate-limited
            if otp != row["otp"] and otp != "000000":
                return self._send(401, {"error": "bad otp"})
            token = jwt_make({"sub": u, "role": row["role"]}, alg="HS256")  # J3: no exp
            return self._send(200, {"token": token, "token_type": "Bearer"})

        if path == "/logout":
            # S2: stateless JWT + no deny-list => token stays valid forever after logout
            return self._send(200, {"message": "logged out (token remains valid)"})

        if path == "/reset-request":
            u = (body.get("username") or "").strip()
            if not q1("SELECT 1 FROM users WHERE username=?", (u,)):
                return self._send(404, {"error": "no such user"})   # A1
            cur = qx("INSERT INTO resets(username,token) VALUES(?, 0)", (u,))
            tok = cur.lastrowid                                    # A3: sequential int token
            qx("UPDATE resets SET token=? WHERE id=?", (tok, tok))
            # A3: reset token leaked directly in the response body
            return self._send(200, {"message": "reset token generated", "reset_token": tok})

        if path == "/reset":
            tok = body.get("token")
            newp = body.get("password") or ""
            row = q1("SELECT username FROM resets WHERE token=?", (tok,))
            if not row or not newp:
                return self._send(400, {"error": "invalid token"})
            qx("UPDATE users SET pwmd5=? WHERE username=?", (md5(newp), row["username"]))
            return self._send(200, {"message": f"password reset for {row['username']}"})

        return self._send(404, {"error": "no such endpoint"})


class TServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    init_db()
    srv = TServer((HOST, PORT), Handler)
    print(f"VaultAuth (vulnerable auth lab) on http://{HOST}:{PORT}  --  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
