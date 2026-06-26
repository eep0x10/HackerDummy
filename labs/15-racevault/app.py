#!/usr/bin/env python3
"""
RaceVault - Deliberately vulnerable wallet/voucher app for pentest training.

  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

Single-file, stdlib-only. Focuses on BUSINESS-LOGIC flaws — the class of bug you
only find by *interacting* with the app's logic, not by pattern-matching responses.
The crown jewel is a genuine **race condition**: the redeem endpoint has a real
check-then-act (TOCTOU) window, so firing concurrent requests redeems a single-use
voucher many times and over-credits the wallet. (Threaded server + a small sleep
makes the window reliably exploitable — and reliably MISSED by any tester that only
sends requests one at a time.)

Planted (each a distinct class so scoring doesn't collapse them):
  F1 race-condition  - concurrent /redeem double-spends a single-use voucher (TOCTOU)
  F2 idor            - /wallet?user= reads ANY user's balance, no auth/ownership
  F3 mass-assignment - /profile update accepts privileged fields (balance, is_admin)
  F4 no-rate-limit   - /login has no throttle/lockout (brute force / cred stuffing)
  F5 missing headers - no CSP / X-Frame-Options / X-Content-Type-Options

All state is in-memory play-money; nothing real is at stake. Run on 127.0.0.1:18815.
See gabarito.json for the planted vulns.
"""
import json
import threading
import time
import urllib.parse
import http.server
import socketserver

HOST, PORT = "127.0.0.1", 18815

USERS = {"alice": "alicepw", "bob": "bobpw"}
BALANCES = {"alice": 0, "bob": 0}
PROFILES = {
    "alice": {"display_name": "Alice", "is_admin": False},
    "bob": {"display_name": "Bob", "is_admin": False},
}
# Single-use vouchers. The race lets you redeem one of these many times.
VOUCHERS = {
    "WELCOME50": {"value": 50, "used": False},
    "BONUS25": {"value": 25, "used": False},
}
SESSIONS = {}
_SEQ = [5000]
# NOTE: there is intentionally NO lock guarding the redeem check-then-act.


def _new_session(user):
    _SEQ[0] += 1
    tok = f"sess_{_SEQ[0]}"
    SESSIONS[tok] = user
    return tok


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "RaceVault/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # F5: deliberately NO security headers.
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _qs(self):
        return {k: v[0] for k, v in
                urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query,
                                      keep_blank_values=True).items()}

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()}

    def _user(self):
        auth = self.headers.get("Authorization", "")
        tok = auth[7:].strip() if auth.lower().startswith("bearer ") else self._qs().get("token", "")
        return SESSIONS.get(tok)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        q = self._qs()
        if path == "/":
            return self._send(200, {"service": "RaceVault wallet",
                "endpoints": ["/login (POST)", "/wallet?user=", "/redeem (POST)",
                              "/profile (POST)", "/vouchers"]})
        if path == "/vouchers":
            return self._send(200, {"vouchers": {k: {"value": v["value"], "used": v["used"]}
                                                 for k, v in VOUCHERS.items()}})
        if path == "/wallet":                                   # F2: IDOR
            user = q.get("user", "")
            if user not in BALANCES:
                return self._send(404, {"error": "no such user"})
            # VULNERABLE: returns ANY user's balance with no auth / ownership check
            return self._send(200, {"user": user, "balance": BALANCES[user],
                                    "profile": PROFILES.get(user, {})})
        return self._send(404, {"error": "no such endpoint"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        data = self._body()

        if path == "/login":                                   # F4: no rate limit
            u, p = data.get("username", ""), data.get("password", "")
            # VULNERABLE: no throttle / lockout / delay — unlimited attempts.
            # (Guarded against null/ghost type-confusion: only real users with the
            # right password authenticate — keeps the lab focused on F1-F5.)
            if u in USERS and p is not None and USERS[u] == p:
                return self._send(200, {"token": _new_session(u), "user": u})
            return self._send(401, {"error": "invalid credentials"})

        if path == "/redeem":                                  # F1: RACE CONDITION
            user = self._user()
            if not user:
                return self._send(401, {"error": "login required"})
            code = data.get("voucher", "")
            v = VOUCHERS.get(code)
            if not v:
                return self._send(404, {"error": "no such voucher"})
            # *** TOCTOU: check 'used', then a window, then act — no lock. Concurrent
            #     requests all pass the check before any sets used=True. ***
            if v["used"]:
                return self._send(409, {"error": "voucher already redeemed",
                                        "balance": BALANCES[user]})
            time.sleep(0.05)                                   # widen the race window
            v["used"] = True
            BALANCES[user] += v["value"]
            return self._send(200, {"redeemed": code, "credited": v["value"],
                                    "balance": BALANCES[user]})

        if path == "/profile":                                 # F3: mass assignment
            user = self._user()
            if not user:
                return self._send(401, {"error": "login required"})
            # VULNERABLE: blindly merges the whole body into the profile/account,
            # so privileged fields (balance, is_admin) can be set by the client.
            for k, val in data.items():
                if k in ("token",):
                    continue
                if k == "balance":
                    BALANCES[user] = val
                else:
                    PROFILES.setdefault(user, {})[k] = val
            return self._send(200, {"user": user, "profile": PROFILES.get(user, {}),
                                    "balance": BALANCES[user]})

        return self._send(404, {"error": "no such endpoint"})


class TServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    srv = TServer((HOST, PORT), Handler)
    print(f"RaceVault (business-logic / race-condition lab) on http://{HOST}:{PORT}  --  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
