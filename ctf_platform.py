#!/usr/bin/env python3
"""
ctf_platform.py — HackerDummy CTF web console (stdlib-only, cross-platform).

A zero-dependency local dashboard to start/stop the HTTP labs and watch their
status. Each lab is a card showing status / port / planted-vuln count / attack
surface. No Flask, no pip install — pure http.server, runs on Windows/Linux/mac.

    python ctf_platform.py                 # -> http://127.0.0.1:8088
    python ctf_platform.py --port 9000

Mobile labs (labs/mobile/*) are static artifacts (no server) and aren't booted
here; analyze them with jadx/apktool. See labs/mobile/MOBILE.md.

Bind stays on 127.0.0.1 by default. State-changing calls require an X-CTF-Token
header (issued to the page) so a random localhost page can't drive your labs.
"""
import os
import re
import sys
import json
import time
import socket
import signal
import secrets
import argparse
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT_DIR = Path(__file__).resolve().parent
LABS_DIR = ROOT_DIR / "labs"
LOG_DIR = ROOT_DIR / ".lab_logs"
PYTHON_BIN = sys.executable
IS_WIN = os.name == "nt"
CSRF_TOKEN = secrets.token_urlsafe(32)

LAB_COMMAND_OVERRIDES = {"11-legacyportal": ["bash", "serve.sh"]}
_URL_RE = re.compile(r"(?:http://)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[[^\]]+\]):(\d{2,5})")

# surface descriptions (vuln counts come from each lab's gabarito.json at runtime)
LAB_METADATA = {
    "01-vulnshop": "Classic web injection: SQLi, XSS, IDOR, SSRF, open-redirect, exposed .git/.env/backup, dir-listing, headers, cookie, info-disc, admin panel.",
    "02-vaultauth": "Auth / JWT / session: alg:none, weak secret, user-enum, no-rate-limit, OTP bypass, mass-assignment, MD5 storage, broken session.",
    "03-relaykit": "Server-side: SSRF + filter bypass, XXE, insecure deserialization, command injection, LFI, SSTI.",
    "04-shopapi": "OWASP API Top 10: BOLA, BFLA, mass-assignment, excessive data exposure, JWT, rate-limit, SSRF, verbose errors.",
    "05-springvault": "Java / Spring Boot Actuator: /env, /heapdump, Jolokia, H2 console, cleartext credentials.",
    "06-openservices": "Infra: Redis, Elasticsearch, Mongo, CouchDB, Docker, Memcached, MySQL unauthenticated + default credentials.",
    "07-graphvault": "GraphQL: introspection, BOLA, excessive data, BFLA, batching, depth DoS, SQLi, field suggestions.",
    "08-trustedge": "Trust-boundary / header: CORS reflection, Host-header injection, X-Forwarded-Host, CRLF splitting, cache poisoning.",
    "09-injectarena": "Beyond-SQL injection: NoSQL operator, LDAP, XPath, SSI, CSV / formula injection.",
    "10-uploadforge": "File-upload: unrestricted upload -> webshell/RCE, default-creds chain, traversal read, SVG stored-XSS, IDOR.",
    "11-legacyportal": "PHP LFI-wrappers: php://filter disclosure, traversal, upload->LFI->RCE polyglot, phpinfo, type-juggling auth bypass.",
    "12-cloudpivot": "Chaining: SSRF -> cloud IMDS instance-role credential theft -> token reuse -> RCE, plus verbose errors.",
    "13-aspnetvault": ".NET / IIS: exposed web.config (connStrings/machineKey), ViewState deserialization, ASP.NET trace viewer, version banners.",
    "14-clientforge": "Client-side: DOM XSS, prototype pollution, DOM open-redirect, hardcoded JS secret, missing CSP.",
    "15-racevault": "Business-logic / concurrency: TOCTOU voucher double-redeem, wallet IDOR, mass-assignment, no-rate-limit.",
    "16-samlforge": "SAML 2.0 SP: signature-bypass auth, XXE via SAMLResponse, RelayState open-redirect, verbose errors.",
    "17-oauthforge": "OAuth2 / OIDC AS: unvalidated redirect_uri, missing state/CSRF, broken token endpoint, verbose errors.",
    "18-javaforge": "Java / Tomcat: native deserialization (rO0AB) -> RCE, default Manager creds, verbose Java stack traces, EOL stack.",
    "19-smuggleforge": "HTTP request smuggling: genuine CL.TE front-end/back-end desync, Server-banner disclosure, missing headers.",
    "20-graphforge": "Advanced GraphQL: alias cost-amplification DoS, unauth promoteToAdmin (BFLA), GraphQL CSRF via GET/form, introspection.",
}

_LOCK = threading.RLock()
LABS = {}  # name -> {index, folder, command, process, log_file}


# ── lab control (cross-platform) ────────────────────────────────────────────
def resolve_command(folder):
    if folder.name in LAB_COMMAND_OVERRIDES:
        cmd = LAB_COMMAND_OVERRIDES[folder.name]
        return cmd if (folder / cmd[-1]).is_file() else None
    if (folder / "app.py").is_file():
        return [PYTHON_BIN, "app.py"]
    if (folder / "serve.sh").is_file():
        return ["bash", "serve.sh"]
    return None


def sort_key(folder):
    m = re.match(r"^(\d+)-", folder.name)
    return int(m.group(1)) if m else 9999


def discover():
    if not LABS_DIR.exists():
        return []
    return sorted((f for f in LABS_DIR.iterdir() if f.is_dir() and resolve_command(f)), key=sort_key)


def vuln_count(folder):
    gab = folder / "gabarito.json"
    if not gab.is_file():
        return 0
    try:
        data = json.loads(gab.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return 0
    if isinstance(data, dict) and isinstance(data.get("vulns"), list):
        return len(data["vulns"])
    return len(data) if isinstance(data, list) else 0


def refresh_inventory():
    with _LOCK:
        live = set()
        for i, folder in enumerate(discover(), start=1):
            live.add(folder.name)
            if folder.name not in LABS:
                LABS[folder.name] = {"index": i, "folder": folder, "command": resolve_command(folder),
                                     "process": None, "log_file": LOG_DIR / f"{folder.name}.log"}
            else:
                LABS[folder.name].update(index=i, folder=folder, command=resolve_command(folder))


def is_alive(lab):
    p = lab.get("process")
    return bool(p) and p.poll() is None


def tcp_open(port, timeout=0.3):
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def detect_port(lab):
    try:
        size = lab["log_file"].stat().st_size
        with open(lab["log_file"], "rb") as f:
            f.seek(max(size - 16000, 0))
            content = f.read().decode(errors="ignore")
    except FileNotFoundError:
        return None
    for port in reversed(_URL_RE.findall(content)):
        if tcp_open(port):
            return f"127.0.0.1:{port}"
    return None


def start_lab(lab, timeout=5.0):
    with _LOCK:
        if is_alive(lab):
            return
        command = lab.get("command") or resolve_command(lab["folder"])
        if not command:
            raise RuntimeError(f"no entrypoint for {lab['folder'].name}")
        LOG_DIR.mkdir(exist_ok=True)
        with open(lab["log_file"], "ab", buffering=0) as log:
            log.write(f"\n\n===== START {datetime.now().isoformat()} =====\n".encode())
            log.write(f"COMMAND: {' '.join(command)}\n".encode())
            kwargs = dict(cwd=str(lab["folder"]), stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                          env={**os.environ, "PYTHONUNBUFFERED": "1"})
            if IS_WIN:
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True
            lab["process"] = subprocess.Popen(command, **kwargs)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_alive(lab):
            break
        if detect_port(lab):
            break
        time.sleep(0.2)


def stop_lab(lab):
    proc = lab.get("process")
    if not proc or proc.poll() is not None:
        return
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            for _ in range(20):
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass
    with _LOCK:
        lab["process"] = None


def serialize():
    refresh_inventory()
    out = []
    with _LOCK:
        for lab in sorted(LABS.values(), key=lambda x: x["index"]):
            alive = is_alive(lab)
            port = detect_port(lab) if alive else None
            out.append({"id": lab["folder"].name, "lab": lab["index"], "folder": lab["folder"].name,
                        "status": "UP" if alive else "DOWN", "port": port or "N/A",
                        "url": f"http://{port}" if port else None,
                        "vulns": vuln_count(lab["folder"]),
                        "description": LAB_METADATA.get(lab["folder"].name, "—")})
    return out


def start_all():
    refresh_inventory()
    for lab in sorted(LABS.values(), key=lambda x: x["index"]):
        start_lab(lab)


def stop_all():
    with _LOCK:
        targets = list(LABS.values())
    for lab in targets:
        stop_lab(lab)


# ── HTTP console ────────────────────────────────────────────────────────────
PAGE = r"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>HackerDummy CTF</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/logo.png">
<style>
:root{--bg:#05070c;--border:#1e3a8a;--cyan:#00e5ff;--green:#00ff88;--red:#ff3b5c;--yellow:#ffd166;--text:#e5e7eb;--muted:#8b949e}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top left,rgba(0,229,255,.12),transparent 32%),radial-gradient(circle at bottom right,rgba(37,99,235,.18),transparent 30%),var(--bg);color:var(--text);font-family:ui-monospace,Menlo,Consolas,monospace}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
.wrap{width:min(1360px,calc(100% - 32px));margin:0 auto;padding:28px 0 42px}
.hero{border:1px solid var(--border);background:linear-gradient(135deg,rgba(11,16,32,.96),rgba(17,24,39,.9));border-radius:18px;padding:24px;display:flex;justify-content:space-between;align-items:center;gap:24px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:18px}.logo{width:88px;height:auto;filter:drop-shadow(0 0 12px rgba(0,255,136,.28))}
.title{margin:0;color:var(--green);font-size:clamp(24px,4vw,40px);letter-spacing:.08em;text-transform:uppercase;text-shadow:0 0 18px rgba(0,255,136,.32)}
.subtitle{margin:8px 0 0;color:var(--muted);font-size:14px}
.btn{border:1px solid rgba(0,229,255,.34);background:rgba(37,99,235,.16);color:var(--text);padding:10px 14px;border-radius:12px;cursor:pointer;font:inherit}
.btn:hover{border-color:var(--cyan)}.btn.green{border-color:rgba(0,255,136,.45);color:var(--green)}.btn.red{border-color:rgba(255,59,92,.45);color:var(--red)}
.btn.small{padding:6px 9px;font-size:13px;border-radius:10px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}
.stat{border:1px solid rgba(30,58,138,.9);background:rgba(11,16,32,.78);border-radius:16px;padding:14px}
.stat span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.1em}
.stat strong{display:block;margin-top:6px;font-size:26px;color:var(--cyan)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin-top:20px}
.card{border:1px solid rgba(30,58,138,.85);background:linear-gradient(180deg,rgba(17,24,39,.96),rgba(11,16,32,.96));border-radius:18px;padding:16px}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px}
.lt{margin:0;font-size:16px}.ln{margin:3px 0 0;color:var(--muted);font-size:12px}
.chip{border-radius:999px;padding:4px 9px;font-weight:800;font-size:11px;letter-spacing:.08em;margin-left:6px}
.chip.up{color:var(--green);border:1px solid rgba(0,255,136,.45)}.chip.down{color:var(--red);border:1px solid rgba(255,59,92,.45)}
.chip.v{color:var(--yellow);border:1px solid rgba(255,209,102,.45)}
.target{border:1px dashed rgba(0,229,255,.32);border-radius:12px;padding:10px;background:rgba(0,229,255,.05);margin-bottom:10px;font-size:13px}
.target strong{display:block;margin-top:5px;color:var(--cyan);font-size:14px}
.surface{border:1px solid rgba(255,209,102,.22);border-radius:12px;padding:10px;background:rgba(255,209,102,.05);margin-bottom:12px;color:var(--muted);font-size:12px;line-height:1.5;min-height:90px}
.acts{display:flex;gap:8px;flex-wrap:wrap}.footer{margin-top:18px;color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
<section class="hero"><div class="brand"><img class="logo" src="/logo.png" alt="HackerDummy">
<div><h1 class="title">HackerDummy CTF</h1>
<p class="subtitle">Console local dos labs. Cada porta = um LAB diferente.</p></div></div>
<div><button class="btn green" onclick="all('start')">Start all</button>
<button class="btn red" onclick="all('stop')">Stop all</button>
<button class="btn" onclick="load()">Refresh</button></div></section>
<section class="stats"><div class="stat"><span>Total labs</span><strong id="t">0</strong></div>
<div class="stat"><span>UP</span><strong id="u">0</strong></div>
<div class="stat"><span>DOWN</span><strong id="d">0</strong></div>
<div class="stat"><span>Total vulns</span><strong id="v">0</strong></div></section>
<section class="grid" id="cards"></section>
<div class="footer">Disponível apenas localmente. Logs em <code>.lab_logs/</code>. Mobile labs são estáticos (jadx/apktool) — ver labs/mobile/MOBILE.md.</div>
</div><script>
const TOK="__CSRF__";
async function api(p,m){const o={headers:{}};if(m&&m!=="GET"){o.method=m;o.headers["X-CTF-Token"]=TOK}const r=await fetch(p,o);if(!r.ok)throw new Error("HTTP "+r.status);return r.json()}
async function all(a){await api("/api/labs/"+a,"POST");load()}
async function one(id,a){await api("/api/labs/"+encodeURIComponent(id)+"/"+a,"POST");load()}
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
function card(l){const c=el("article","card");const top=el("div","top");const w=el("div");
w.appendChild(el("h3","lt","LAB "+l.lab));w.appendChild(el("p","ln",l.folder));
const b=el("div");const v=el("span","chip v",l.vulns+" vulns");const s=el("span","chip "+(l.status==="UP"?"up":"down"),l.status);
b.appendChild(v);b.appendChild(s);top.appendChild(w);top.appendChild(b);
const tg=el("div","target","Target");const st=el("strong");
if(l.url){const a=el("a",null,l.port);a.href=l.url;a.target="_blank";st.appendChild(a)}else st.textContent="N/A";
tg.appendChild(st);const sf=el("div","surface");sf.innerHTML="<strong>Surface:</strong> ";sf.appendChild(document.createTextNode(l.description));
const ac=el("div","acts");const bs=el("button","btn small green","Start");bs.onclick=()=>one(l.id,"start");
const bt=el("button","btn small red","Stop");bt.onclick=()=>one(l.id,"stop");
const bl=el("button","btn small","Logs");bl.onclick=()=>window.open("/logs/"+encodeURIComponent(l.id),"_blank");
ac.appendChild(bs);ac.appendChild(bt);ac.appendChild(bl);
if(l.url){const bo=el("button","btn small","Open");bo.onclick=()=>window.open(l.url,"_blank");ac.appendChild(bo)}
c.appendChild(top);c.appendChild(tg);c.appendChild(sf);c.appendChild(ac);return c}
async function load(){const d=await api("/api/labs");const labs=d.labs;
document.getElementById("t").textContent=labs.length;
document.getElementById("u").textContent=labs.filter(x=>x.status==="UP").length;
document.getElementById("d").textContent=labs.filter(x=>x.status!=="UP").length;
document.getElementById("v").textContent=labs.reduce((a,x)=>a+(+x.vulns||0),0);
const root=document.getElementById("cards");root.innerHTML="";labs.forEach(l=>root.appendChild(card(l)))}
load();setInterval(load,3000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HackerDummyCTF/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code, text, ctype="text/html; charset=utf-8"):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, fpath, ctype):
        try:
            data = Path(fpath).read_bytes()
        except OSError:
            return self._text(404, "not found", "text/plain")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._text(200, PAGE.replace("__CSRF__", CSRF_TOKEN))
        if path in ("/logo.png", "/favicon.ico"):
            name = "hackerdummy-icon-96.png" if path == "/favicon.ico" else "hackerdummy-logo-560.png"
            return self._file(ROOT_DIR / "assets" / name, "image/png")
        if path == "/api/labs":
            return self._json(200, {"labs": serialize()})
        if path.startswith("/logs/"):
            name = path[len("/logs/"):]
            with _LOCK:
                lab = LABS.get(name)
            if not lab:
                return self._text(404, "not found", "text/plain")
            f = lab["log_file"]
            data = "log ainda não criado.\n"
            if f.exists():
                with open(f, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    end = fh.tell()
                    fh.seek(max(end - 50000, 0))
                    data = fh.read().decode(errors="replace")
            return self._text(200, data, "text/plain; charset=utf-8")
        return self._text(404, "not found", "text/plain")

    def do_POST(self):
        if self.headers.get("X-CTF-Token") != CSRF_TOKEN:
            return self._text(403, "forbidden", "text/plain")
        path = self.path.split("?")[0]
        if path == "/api/labs/start":
            start_all(); return self._json(200, {"ok": True, "labs": serialize()})
        if path == "/api/labs/stop":
            stop_all(); return self._json(200, {"ok": True, "labs": serialize()})
        m = re.match(r"^/api/labs/(.+)/(start|stop)$", path)
        if m:
            refresh_inventory()
            with _LOCK:
                lab = LABS.get(m.group(1))
            if not lab:
                return self._text(404, "not found", "text/plain")
            (start_lab if m.group(2) == "start" else stop_lab)(lab)
            return self._json(200, {"ok": True, "labs": serialize()})
        return self._text(404, "not found", "text/plain")


def main():
    ap = argparse.ArgumentParser(description="HackerDummy CTF web console (stdlib).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    args = ap.parse_args()
    LOG_DIR.mkdir(exist_ok=True)
    refresh_inventory()
    labs = serialize()
    total_vulns = sum(l["vulns"] for l in labs)

    def shutdown(*_):
        print("\n[!] Encerrando — derrubando labs...")
        stop_all()
        print("[+] Todos os labs finalizados.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    try:
        signal.signal(signal.SIGTERM, shutdown)
    except (ValueError, AttributeError):
        pass

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"HackerDummy CTF console  ->  http://{args.host}:{args.port}")
    print(f"  labs: {len(labs)}   vulns catalogadas: {total_vulns}   logs: {LOG_DIR}")
    print("  Ctrl+C para encerrar (derruba todos os labs).")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        shutdown()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
