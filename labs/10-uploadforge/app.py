#!/usr/bin/env python3
"""
UploadForge - Deliberately vulnerable "document & avatar processing" service.

  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

Single-file, stdlib-only. Focuses on the FILE-UPLOAD attack surface, with the
crown-jewel vector a pentest must always chase: unrestricted upload -> webshell
-> remote code execution. Run on 127.0.0.1:18810.

The realistic chain it plants:
    weak/default login  ->  authenticated upload (no validation)  ->  the
    uploaded "template" is rendered server-side  ->  code execution.

SAFETY-BY-DESIGN (so the lab can't hurt the host while staying faithful):
  - /render executes an uploaded webshell template, but ONLY a read-only canary
    allow-list (whoami/id/hostname/echo/ver/uname). Anything else is intercepted
    and reported as RCE-capable, NOT executed. Confirmation without real RCE.
  - Uploads are saved with os.path.basename() so they cannot escape uploads/.
    The planted bug is the lack of TYPE/CONTENT validation (-> webshell), not a
    write-traversal that could clobber the host.
  - /files read-path traversal is genuine but READ-ONLY info disclosure.

See gabarito.json for the planted vulns.
"""
import html
import json
import mimetypes
import os
import re
import subprocess
import traceback
import urllib.parse
import http.server
import socketserver

HOST, PORT = "127.0.0.1", 18810
HERE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(HERE, "uploads")

# Default/seed accounts. operator:operator is the planted DEFAULT credential.
# (admin password is a non-functional strong placeholder.)
USERS = {
    "operator": "operator",                 # U2: default credential, never rotated
    "admin": "S3cure-Admin-#2026-placeholder",
}

# token -> username (in-memory sessions)
SESSIONS = {}
_SESS_SEQ = [1000]

# Uploaded objects, by sequential id (the IDOR surface). id -> dict(meta)
UPLOAD_DB = {}
_UP_SEQ = [0]

CANARY = {"whoami", "id", "hostname", "echo", "ver", "uname", "pwd"}


# --------------------------------------------------------------------- helpers
def _new_session(username):
    _SESS_SEQ[0] += 1
    tok = f"sess_{_SESS_SEQ[0]}"
    SESSIONS[tok] = username
    return tok


def parse_multipart(body, content_type):
    """Minimal multipart/form-data parser (cgi was removed in 3.13).
    Returns list of (field_name, filename_or_None, value_bytes)."""
    m = re.search(r'boundary=("?)([^";]+)\1', content_type or "")
    if not m:
        return []
    boundary = ("--" + m.group(2)).encode()
    out = []
    for part in body.split(boundary):
        part = part.strip(b"\r\n")
        if not part or part == b"--" or b"\r\n\r\n" not in part:
            continue
        head, _, value = part.partition(b"\r\n\r\n")
        head_text = head.decode("utf-8", "replace")
        cd = re.search(
            r'Content-Disposition:[^\r\n]*?name="([^"]*)"(?:[^\r\n]*?filename="([^"]*)")?',
            head_text, re.I)
        if not cd:
            continue
        out.append((cd.group(1), cd.group(2), value.rstrip(b"\r\n")))
    return out


def webshell_render(text):
    """U1 sink: a server-side template that supports {{exec:<cmd>}}. This is what
    turns an unrestricted upload into RCE. LAB-SAFE: only canary commands run."""
    findings = []

    def _do(mo):
        cmd = mo.group(1).strip()
        first = cmd.split()[0] if cmd.split() else ""
        if first in CANARY:
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True,
                                     text=True, timeout=5).stdout.strip()
            except Exception as e:                              # noqa: BLE001
                out = f"<exec error: {e}>"
            findings.append({"cmd": cmd, "executed": True, "output": out})
            return out
        findings.append({"cmd": cmd, "executed": False,
                         "note": "[lab] command accepted; non-canary intercepted (RCE-capable, not run)"})
        return f"[[blocked:{cmd}]]"

    rendered = re.sub(r"\{\{\s*exec:(.*?)\}\}", _do, text)
    return rendered, findings


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "UploadForge/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # NOTE: deliberately NO security headers (U7): no CSP/HSTS/X-Frame-Options/
    # X-Content-Type-Options anywhere.
    def _send(self, code, obj, ctype="application/json", extra=None):
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
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

    def _qs(self):
        return {k: v[0] for k, v in
                urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query,
                                      keep_blank_values=True).items()}

    def _raw_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def _session_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok in SESSIONS:
                return SESSIONS[tok]
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"session=([^;]+)", cookie)
        if m and m.group(1) in SESSIONS:
            return SESSIONS[m.group(1)]
        return None

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        try:
            self._route_get()
        except Exception:                                       # U6: debug on
            self._send(500, {"error": "internal error", "traceback": traceback.format_exc()})

    def _route_get(self):
        path = urllib.parse.urlparse(self.path).path
        q = self._qs()

        if path == "/":
            return self._send(200, {
                "service": "UploadForge document & avatar processor",
                "endpoints": ["/login (POST)", "/upload (POST, auth)", "/files?name=",
                              "/view?id=", "/render?doc= (auth)", "/myfiles (auth)"],
                "hint": "operator onboarding uses the default operator/operator login until rotated",
            })

        if path == "/files":                                   # U3: path traversal (read)
            name = q.get("name", "")
            if not name:
                return self._send(400, {"error": "name required"})
            full = os.path.join(UPLOADS, name)                 # no normalization -> ../ escapes
            try:
                with open(full, "rb") as fh:
                    data = fh.read(200000)
                ctype, _ = mimetypes.guess_type(full)
                return self._send(200, data, ctype or "application/octet-stream")
            except (FileNotFoundError, OSError, IsADirectoryError) as e:
                return self._send(404, {"error": str(e), "resolved": full})

        if path == "/view":                                    # U5: IDOR + U4: stored XSS
            fid = int(q.get("id", ""))                         # non-int -> traceback (U6)
            meta = UPLOAD_DB.get(fid)                           # no ownership check (IDOR)
            if not meta:
                return self._send(404, {"error": "no such file id"})
            try:
                with open(meta["stored_path"], "rb") as fh:
                    data = fh.read(200000)
            except OSError as e:
                return self._send(404, {"error": str(e)})
            # served with a content-type derived from the uploaded extension:
            # .svg/.html are served as text/html -> stored XSS executes in a browser.
            ctype = meta["served_ctype"]
            return self._send(200, data, ctype)

        if path == "/myfiles":                                 # auth-gated listing
            user = self._session_user()
            if not user:
                return self._send(401, {"error": "login required"})
            mine = [{"id": i, "filename": m["filename"], "owner": m["owner"]}
                    for i, m in UPLOAD_DB.items() if m["owner"] == user]
            return self._send(200, {"user": user, "files": mine})

        if path == "/render":                                  # U1 sink: webshell exec
            user = self._session_user()
            if not user:
                return self._send(401, {"error": "login required"})
            doc = q.get("doc", "")
            full = os.path.join(UPLOADS, os.path.basename(doc))
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            rendered, execs = webshell_render(text)
            return self._send(200, {"doc": doc, "rendered": rendered[:8000], "exec": execs})

        return self._send(404, {"error": "no such endpoint"})

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        try:
            self._route_post()
        except Exception:                                       # U6: debug on
            self._send(500, {"error": "internal error", "traceback": traceback.format_exc()})

    def _route_post(self):
        path = urllib.parse.urlparse(self.path).path
        raw = self._raw_body()

        if path == "/login":                                   # U2: default creds
            try:
                creds = json.loads(raw or b"{}")
            except Exception:
                creds = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()}
            u, p = creds.get("username", ""), creds.get("password", "")
            if u in USERS and USERS[u] == p:
                tok = _new_session(u)
                return self._send(200, {"token": tok, "user": u},
                                  extra={"Set-Cookie": f"session={tok}; Path=/"})
            return self._send(401, {"error": "invalid credentials"})

        if path == "/upload":                                  # U1: unrestricted upload
            user = self._session_user()
            if not user:
                return self._send(401, {"error": "login required"})

            filename, content = None, b""
            ctype = self.headers.get("Content-Type", "")
            if ctype.startswith("multipart/form-data"):
                for fname, fn, val in parse_multipart(raw, ctype):
                    if fn:
                        filename, content = fn, val
                        break
            if filename is None:                               # raw upload fallback
                filename = self._qs().get("filename") or self.headers.get("X-Filename") or "upload.bin"
                content = raw

            # *** THE BUG: no extension / MIME / magic-byte validation at all. ***
            safe = os.path.basename(filename)                  # host-safety only
            stored = os.path.join(UPLOADS, safe)
            with open(stored, "wb") as fh:
                fh.write(content)

            ext = os.path.splitext(safe)[1].lower()
            served = {".svg": "text/html", ".html": "text/html", ".htm": "text/html",
                      ".xml": "application/xml"}.get(ext) or \
                mimetypes.guess_type(safe)[0] or "application/octet-stream"

            _UP_SEQ[0] += 1
            fid = _UP_SEQ[0]
            UPLOAD_DB[fid] = {"filename": safe, "stored_path": stored, "owner": user,
                              "served_ctype": served}
            return self._send(200, {"id": fid, "filename": safe, "owner": user,
                                    "view": f"/view?id={fid}", "render": f"/render?doc={safe}",
                                    "stored_as": served})

        return self._send(404, {"error": "no such endpoint"})


def _ensure_lab_files():
    os.makedirs(UPLOADS, exist_ok=True)
    # a benign pre-existing upload so /view?id=1 and IDOR are demonstrable out of the box
    seed = os.path.join(UPLOADS, "welcome.txt")
    if not os.path.exists(seed):
        with open(seed, "w", encoding="utf-8") as f:
            f.write("Welcome to UploadForge. Operators can upload documents and avatars.\n")
        UPLOAD_DB[1] = {"filename": "welcome.txt", "stored_path": seed,
                        "owner": "admin", "served_ctype": "text/plain"}
        _UP_SEQ[0] = 1
    # a planted server secret reachable via the read-path traversal (U3)
    secret = os.path.join(HERE, "server-secrets.txt")
    if not os.path.exists(secret):
        with open(secret, "w", encoding="utf-8") as f:
            f.write("UPLOADFORGE_FLAG=flag{unrestricted_upload_to_webshell}\n"
                    "internal_api_token=uf_svc_3a9f1c7b5d2e8a4f6c0b\n")


class TServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    _ensure_lab_files()
    srv = TServer((HOST, PORT), Handler)
    print(f"UploadForge (vulnerable upload lab) on http://{HOST}:{PORT}  --  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
