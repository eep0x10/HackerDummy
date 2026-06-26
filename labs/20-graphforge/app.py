#!/usr/bin/env python3
"""
GraphForge - Deliberately vulnerable GraphQL API (advanced) for pentest training.

  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

Single-file, stdlib-only. Goes beyond basic GraphQL recon (Lab 07) into the
query-execution attack surface:
  O1 dos    - NO query cost / alias / depth limiting: an aliased query that repeats
              an expensive field hundreds of times is executed in full (alias-based
              cost amplification -> resource exhaustion).
  O2 bfla   - a privileged mutation (promoteToAdmin) executes with NO authorization.
  O3 csrf   - GraphQL mutations are accepted over GET and form-encoded POST with no
              CSRF token / no JSON-content-type enforcement -> cross-site mutation.
  O4 graphql- introspection (__schema) is enabled in production.
  O5 headers- no CSP / X-Frame-Options / X-Content-Type-Options.

A deliberately simplified GraphQL executor (substring/regex based) — faithful enough
to demonstrate each issue. Run on 127.0.0.1:18821. See gabarito.json.
"""
import json
import re
import urllib.parse
import http.server
import socketserver

HOST, PORT = "127.0.0.1", 18821

USERS = {1: {"id": 1, "name": "alice", "role": "user"},
         2: {"id": 2, "name": "bob", "role": "user"}}
# an "expensive" field — each alias returns this 1KB blob (amplification unit)
EXPENSIVE_BLOB = "X" * 1024

INTROSPECTION = {"data": {"__schema": {"queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "fields": [{"name": "user"}, {"name": "users"}, {"name": "report"}]},
        {"name": "Mutation", "fields": [{"name": "promoteToAdmin"}, {"name": "updateProfile"}]},
        {"name": "User", "fields": [{"name": "id"}, {"name": "name"}, {"name": "role"}, {"name": "ssn"}]},
    ]}}}


def execute(query, method):
    q = query or ""
    low = q.lower()
    # O4: introspection enabled
    if "__schema" in q or "__type" in q:
        return INTROSPECTION
    # O2: privileged mutation with no authorization
    if "promotetoadmin" in low:
        m = re.search(r"promoteToAdmin\s*\(\s*(?:userId|id)\s*:\s*(\d+)", q, re.I)
        uid = int(m.group(1)) if m else 1
        if uid in USERS:
            USERS[uid]["role"] = "admin"
        return {"data": {"promoteToAdmin": {"id": uid, "role": "admin",
                "note": "[lab] privileged mutation executed with NO authorization"}}}
    # O1: alias-based cost amplification — count aliased 'report' fields, execute ALL
    aliases = re.findall(r"(\w+)\s*:\s*report\b", q)
    if aliases or re.search(r"\breport\b", low):
        n = max(len(aliases), 1)
        data = {a: EXPENSIVE_BLOB for a in aliases} if aliases else {"report": EXPENSIVE_BLOB}
        return {"data": data, "_lab_note": f"executed {n} expensive 'report' resolvers; "
                f"no cost/alias/depth limit (amplification {n}x)"}
    if "users" in low:
        return {"data": {"users": list(USERS.values())}}
    m = re.search(r"user\s*\(\s*id\s*:\s*(\d+)", q, re.I)
    if m:
        return {"data": {"user": USERS.get(int(m.group(1)))}}
    return {"errors": [{"message": "Cannot parse query"}], "query_echo": q[:200]}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "GraphForge/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # deliberately NO security headers.
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            return self._send(200, {"service": "GraphForge GraphQL API",
                                    "endpoint": "/graphql (GET or POST)"})
        if parsed.path == "/graphql":
            # O3: mutations accepted over GET (CSRF-able, no token / no JSON enforcement)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            return self._send(200, execute(q.get("query", ""), "GET"))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/graphql":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        ctype = self.headers.get("Content-Type", "")
        query = ""
        if "application/json" in ctype:
            try:
                query = json.loads(raw or b"{}").get("query", "")
            except Exception:
                query = ""
        else:
            # O3: also accepts form-encoded (simple content-type -> CSRF-able)
            form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()}
            query = form.get("query", "")
        return self._send(200, execute(query, "POST"))


class TServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    srv = TServer((HOST, PORT), Handler)
    print(f"GraphForge (vulnerable GraphQL lab) on http://{HOST}:{PORT}  --  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
