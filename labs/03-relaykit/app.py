#!/usr/bin/env python3
"""
RelayKit - Deliberately vulnerable "integration gateway" for pentest training.

  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

Single-file, stdlib-only. Focuses on SERVER-SIDE exploitation: SSRF, XXE, LFI,
insecure deserialization, OS command injection, and SSTI. Run on 127.0.0.1:18803.

SAFETY-BY-DESIGN (so the lab can't hurt the host while staying faithful):
  - /restore (pickle) RESOLVES the malicious gadget (proving insecure deser) but
    REFUSES to execute it. Confirmation without RCE.
  - /ping (command injection) executes ONLY a read-only canary allow-list
    (whoami/hostname/id/ver/echo); anything else is intercepted, not run.
  - /render (SSTI) leaks data via format-string injection, it does not exec.
The SSRF/XXE/LFI primitives are genuine (read-only info disclosure).

See gabarito.json for the planted vulns.
"""
import base64
import io
import json
import os
import pickle
import re
import subprocess
import urllib.parse
import urllib.request
import urllib.error
import http.server
import socketserver
import xml.sax
import xml.sax.handler

HOST, PORT = "127.0.0.1", 18803
HERE = os.path.dirname(os.path.abspath(__file__))

# A planted "internal" secret only meant to be reachable server-side.
INTERNAL_SECRETS = {
    "db_password": "Pr0d-Relay-DB!2026",
    "aws_access_key": "AKIA_LAB_FAKE_EXAMPLE_KEY",
    "service_token": "relay_svc_8f1c9b7a6d5e4f3c2b1a",
}
SECRET_FILE = os.path.join(HERE, "secret.txt")
APP_CONFIG = {"SECRET_KEY": "relaykit-super-secret-do-not-leak-9f8a7c", "ENV": "production"}


# --------------------------------------------------------------------------- XXE
class _Collector(xml.sax.handler.ContentHandler):
    def __init__(self):
        self.buf = []

    def characters(self, content):
        self.buf.append(content)

    def text(self):
        return "".join(self.buf)


def parse_xml_with_xxe(xml_bytes):
    """VULNERABLE: external general entities ENABLED -> XXE (file read + SSRF)."""
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)   # the bug
    handler = _Collector()
    parser.setContentHandler(handler)
    parser.parse(io.BytesIO(xml_bytes))
    return handler.text()


# ----------------------------------------------------------------- deserialization
class _InsecureGadget(Exception):
    pass


class _LabUnpickler(pickle.Unpickler):
    """Insecure by design (would resolve arbitrary globals). For LAB SAFETY we
    intercept dangerous callables and raise instead of letting them execute."""
    _DANGER_MOD = {"os", "nt", "posix", "subprocess", "builtins", "__builtin__",
                   "shutil", "socket", "sys"}
    _DANGER_NAME = {"system", "popen", "eval", "exec", "Popen", "call",
                    "check_output", "check_call", "spawn", "fork"}

    def find_class(self, module, name):
        if module in self._DANGER_MOD or name in self._DANGER_NAME:
            raise _InsecureGadget(f"{module}.{name}")
        return super().find_class(module, name)


# -------------------------------------------------------------------- SSRF helper
def server_side_fetch(url, timeout=5):
    req = urllib.request.Request(url, headers={"User-Agent": "RelayKit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:    # noqa: S310
        return r.read(65536)


def weak_ssrf_blocklist(url):
    """SS2: naive CASE-SENSITIVE substring blocklist - bypassable with a case variation
    (LocalHost / LOCALHOST), embedded credentials, or alternate IP encodings. Returns
    True if 'blocked'."""
    return ("127.0.0.1" in url) or ("localhost" in url)   # case-sensitive bug: 'LocalHost' slips through


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "RelayKit/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

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

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        q = self._qs()

        if path == "/":
            return self._send(200, {"service": "RelayKit integration gateway",
                "endpoints": ["/fetch?url=", "/preview?url=", "/import-xml (POST)",
                              "/restore (POST)", "/ping?host=", "/download?file=",
                              "/render?name=", "/internal/secrets (server-only)"]})

        # Internal metadata-style endpoint: meant to be reachable ONLY server-side
        if path == "/internal/secrets":
            ra = self.client_address[0]
            if ra not in ("127.0.0.1", "::1"):
                return self._send(403, {"error": "internal only"})
            return self._send(200, INTERNAL_SECRETS)

        if path == "/fetch":                                  # SS1: full SSRF
            url = q.get("url", "")
            if not url:
                return self._send(400, {"error": "url required"})
            try:
                data = server_side_fetch(url)
                return self._send(200, {"url": url, "body": data.decode("utf-8", "replace")[:8000]})
            except urllib.error.URLError as e:
                return self._send(502, {"error": str(e)})

        if path == "/preview":                                # SS2: SSRF w/ weak filter
            url = q.get("url", "")
            if not url:
                return self._send(400, {"error": "url required"})
            if weak_ssrf_blocklist(url):
                return self._send(403, {"error": "internal hosts are blocked"})
            try:
                data = server_side_fetch(url)
                return self._send(200, {"url": url, "preview": data.decode("utf-8", "replace")[:8000]})
            except urllib.error.URLError as e:
                return self._send(502, {"error": str(e)})

        if path == "/ping":                                   # RC1: command injection
            host = q.get("host", "")
            cmd = f"ping -n 1 {host}"                          # vulnerable concat
            if re.search(r"[;&|`$\n]|\$\(", host):
                injected = re.split(r"[;&|]", host, maxsplit=1)[-1].strip()
                first = injected.split()[0] if injected.split() else ""
                allow = {"whoami", "hostname", "id", "ver", "echo", "uname"}
                if first in allow:                            # lab: run read-only canary only
                    try:
                        out = subprocess.run(injected, shell=True, capture_output=True,
                                             text=True, timeout=5).stdout
                    except Exception as e:
                        out = f"<exec error: {e}>"
                    return self._send(200, {"cmd": cmd, "injected": injected,
                                            "output": out, "rce": True})
                return self._send(200, {"cmd": cmd, "injected": injected, "rce": True,
                    "note": "[lab] injection accepted; non-canary command intercepted (not executed)"})
            return self._send(200, {"cmd": cmd, "result": f"PING {host}: 1 packets transmitted"})

        if path == "/download":                               # LF1: path traversal / LFI
            f = q.get("file", "")
            base = os.path.join(HERE, "files")
            full = os.path.join(base, f)                       # no normalization -> traversal
            try:
                with open(full, "rb") as fh:
                    return self._send(200, fh.read(65536), "application/octet-stream")
            except (FileNotFoundError, OSError) as e:
                return self._send(404, {"error": str(e), "resolved": full})

        if path == "/render":                                 # ST1: SSTI (format-string leak)
            name = q.get("name", "world")
            try:
                # VULNERABLE: user controls the format string; can reach object internals
                greeting = ("Hello " + name + "!").format(config=APP_CONFIG, app=self)
            except Exception as e:
                greeting = f"<template error: {e}>"
            return self._send(200, {"greeting": greeting}, "text/plain")

        return self._send(404, {"error": "no such endpoint"})

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        raw = self._raw_body()

        if path == "/import-xml":                             # XX1: XXE
            try:
                text = parse_xml_with_xxe(raw)
                return self._send(200, {"imported": True, "parsed_text": text[:8000]})
            except Exception as e:
                return self._send(400, {"error": f"xml parse error: {e}"})

        if path == "/restore":                                # DS1: insecure deserialization
            try:
                blob = base64.b64decode(raw, validate=False)
            except Exception:
                blob = raw
            try:
                obj = _LabUnpickler(io.BytesIO(blob)).load()
                return self._send(200, {"restored": True, "object": repr(obj)[:2000]})
            except _InsecureGadget as g:
                return self._send(200, {"restored": False, "insecure_deserialization": True,
                    "resolved_gadget": str(g),
                    "note": "[lab] dangerous gadget resolved -> RCE in a real deploy; "
                            "execution blocked for lab safety"})
            except Exception as e:
                return self._send(400, {"error": f"unpickle error: {e}"})

        return self._send(404, {"error": "no such endpoint"})


def _ensure_lab_files():
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w", encoding="utf-8") as f:
            f.write("RELAYKIT_FLAG=flag{xxe_and_lfi_read_local_files}\n"
                    "internal_api_token=relay_svc_8f1c9b7a6d5e4f3c2b1a\n")
    files_dir = os.path.join(HERE, "files")
    os.makedirs(files_dir, exist_ok=True)
    sample = os.path.join(files_dir, "report.txt")
    if not os.path.exists(sample):
        with open(sample, "w", encoding="utf-8") as f:
            f.write("Quarterly integration report - nothing sensitive here.\n")


class TServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    _ensure_lab_files()
    srv = TServer((HOST, PORT), Handler)
    print(f"RelayKit (vulnerable server-side lab) on http://{HOST}:{PORT}  --  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
