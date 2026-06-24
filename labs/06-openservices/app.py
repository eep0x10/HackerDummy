#!/usr/bin/env python3
"""
OpenServices - Deliberately vulnerable INFRA host for pentest training.
*** INTENTIONALLY VULNERABLE - LOCALHOST ONLY ***

A SINGLE stdlib-only Python file that simulates ONE host carelessly exposing a
fleet of data/infra services on their STANDARD ports, each bound to 127.0.0.1,
each with no authentication (or trivial default creds). No real Redis/Mongo/etc
required -- each service is faithful enough that a banner-grabber + a curious
client can confirm the exposure (PING->PONG, version strings, RESP/text framing,
a MySQL handshake whose readable portion contains the EOL version, etc.).

Each listener: free-port check first, SO_REUSEADDR on, its own thread; a bind
failure prints a warning and is skipped (never crash). A startup summary lists
which ports actually bound. See gabarito.json / README.md.

Planted (port -> vuln id):
  6379  Redis,         no auth                       -> I1
  9200  Elasticsearch, no auth + outdated (1.4.2)    -> I2
  27017 MongoDB,       no auth                       -> I3
  5984  CouchDB,       "admin party" (no auth)       -> I4
  2375  Docker Engine API, no TLS / no auth          -> I5
  11211 Memcached,     no auth                        -> I6
  3306  MySQL,         EOL 5.5.62                      -> I7
  8080  HTTP admin panel, DEFAULT CREDS admin:admin  -> I8
"""
import base64
import json
import socket
import threading

HOST = "127.0.0.1"


# --------------------------------------------------------------------------- #
#  Tiny TCP listener scaffold (raw-socket services)
# --------------------------------------------------------------------------- #
def _recv_line(conn, maxlen=4096):
    """Read until CRLF/LF or maxlen; return bytes (may be b'' on close)."""
    buf = b""
    while b"\n" not in buf and len(buf) < maxlen:
        try:
            chunk = conn.recv(256)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def serve(port, handler, bound, lock):
    """Bind one raw-TCP port, accept forever, dispatch each conn to `handler`.

    Returns True if it bound (caller records it), False otherwise. The accept
    loop runs in its own daemon thread so we never block the caller.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((HOST, port))
        srv.listen(50)
    except OSError as e:
        print(f"  [skip] port {port}: bind failed ({e})")
        try:
            srv.close()
        except OSError:
            pass
        return False

    with lock:
        bound.append(port)

    def _accept_loop():
        while True:
            try:
                conn, _addr = srv.accept()
            except OSError:
                break
            t = threading.Thread(target=_safe, args=(handler, conn), daemon=True)
            t.start()

    threading.Thread(target=_accept_loop, daemon=True).start()
    return True


def _safe(handler, conn):
    """Run a handler on a connection; never let an exception kill a thread."""
    try:
        handler(conn)
    except (OSError, ValueError):
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
#  I1 - Redis (6379), no auth. Minimal RESP protocol.
# --------------------------------------------------------------------------- #
REDIS_INFO = (
    "# Server\r\n"
    "redis_version:2.8.0\r\n"
    "redis_git_sha1:00000000\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux 3.13.0-44-generic x86_64\r\n"
    "arch_bits:64\r\n"
    "process_id:1\r\n"
    "tcp_port:6379\r\n"
    "uptime_in_seconds:864000\r\n"
    "# Clients\r\n"
    "connected_clients:1\r\n"
    "# Memory\r\n"
    "used_memory:1015920\r\n"
    "used_memory_human:992.11K\r\n"
    "# Persistence\r\n"
    "loading:0\r\n"
    "rdb_last_save_time:1466200000\r\n"
    "# Replication\r\n"
    "role:master\r\n"
    "connected_slaves:0\r\n"
    "master_repl_offset:0\r\n"
    "# CPU\r\n"
    "used_cpu_sys:1.20\r\n"
    "# Keyspace\r\n"
    "db0:keys=3,expires=0,avg_ttl=0\r\n"
)


def _resp_bulk(s):
    b = s.encode("utf-8", "replace")
    return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"


def _resp_array(items):
    out = b"*" + str(len(items)).encode() + b"\r\n"
    for it in items:
        out += _resp_bulk(it)
    return out


def _parse_redis_cmd(data):
    """Parse one command, supporting both inline ('PING\\r\\n') and RESP arrays
    ('*1\\r\\n$4\\r\\nPING\\r\\n'). Returns a list of string tokens."""
    if not data:
        return []
    if data[:1] == b"*":
        toks, lines = [], data.split(b"\r\n")
        i = 0
        while i < len(lines):
            ln = lines[i]
            if ln[:1] == b"$":
                if i + 1 < len(lines):
                    toks.append(lines[i + 1].decode("utf-8", "replace"))
                i += 2
            else:
                i += 1
        return [t for t in toks if t != ""]
    # inline
    return data.decode("utf-8", "replace").strip().split()


def handle_redis(conn):
    # NO AUTH gate: every command is served, authenticated or not.
    while True:
        data = _recv_line(conn)
        if not data:
            return
        toks = _parse_redis_cmd(data)
        if not toks:
            continue
        cmd = toks[0].upper()
        if cmd == "PING":
            conn.sendall(b"+PONG\r\n")
        elif cmd == "INFO":
            conn.sendall(_resp_bulk(REDIS_INFO))
        elif cmd == "AUTH":
            # Server has no password configured -> AUTH is an error, access stays open.
            conn.sendall(b"-ERR Client sent AUTH, but no password is set\r\n")
        elif cmd == "CONFIG":
            sub = toks[1].upper() if len(toks) > 1 else ""
            key = toks[2].lower() if len(toks) > 2 else ""
            if sub == "GET" and key == "dir":
                conn.sendall(_resp_array(["dir", "/var/lib/redis"]))
            elif sub == "GET" and key == "dbfilename":
                conn.sendall(_resp_array(["dbfilename", "dump.rdb"]))
            elif sub == "GET":
                conn.sendall(_resp_array([toks[2] if len(toks) > 2 else "", ""]))
            else:
                conn.sendall(b"+OK\r\n")
        elif cmd == "KEYS":
            conn.sendall(_resp_array(["session:admin", "config:db", "flag"]))
        elif cmd == "GET":
            conn.sendall(_resp_bulk("flag{redis_no_auth_open}"))
        elif cmd in ("SELECT", "SET"):
            conn.sendall(b"+OK\r\n")
        elif cmd == "DBSIZE":
            conn.sendall(b":3\r\n")
        elif cmd in ("QUIT", "EXIT"):
            conn.sendall(b"+OK\r\n")
            return
        elif cmd == "COMMAND":
            conn.sendall(b"*0\r\n")
        else:
            conn.sendall(b"-ERR unknown command\r\n")


# --------------------------------------------------------------------------- #
#  I6 - Memcached (11211), no auth. Plain text protocol.
# --------------------------------------------------------------------------- #
MEMCACHED_STATS = (
    "STAT pid 1\r\n"
    "STAT uptime 864000\r\n"
    "STAT version 1.4.15\r\n"
    "STAT pointer_size 64\r\n"
    "STAT curr_connections 1\r\n"
    "STAT total_connections 5\r\n"
    "STAT cmd_get 10\r\n"
    "STAT cmd_set 7\r\n"
    "STAT get_hits 8\r\n"
    "STAT get_misses 2\r\n"
    "STAT bytes 512\r\n"
    "STAT curr_items 3\r\n"
    "STAT total_items 7\r\n"
    "STAT limit_maxbytes 67108864\r\n"
    "END\r\n"
)


def handle_memcached(conn):
    # NO AUTH: every command served immediately.
    while True:
        data = _recv_line(conn)
        if not data:
            return
        line = data.decode("utf-8", "replace").strip()
        cmd = line.split()[0].lower() if line.split() else ""
        if cmd == "stats":
            conn.sendall(MEMCACHED_STATS.encode())
        elif cmd == "version":
            conn.sendall(b"VERSION 1.4.15\r\n")
        elif cmd == "get":
            # pretend a couple of keys exist (cached session token)
            parts = line.split()
            key = parts[1] if len(parts) > 1 else "session"
            val = b"flag{memcached_no_auth}"
            conn.sendall(
                b"VALUE " + key.encode() + b" 0 " + str(len(val)).encode()
                + b"\r\n" + val + b"\r\nEND\r\n"
            )
        elif cmd in ("set", "add", "replace"):
            conn.sendall(b"STORED\r\n")
        elif cmd == "quit":
            return
        else:
            conn.sendall(b"ERROR\r\n")


# --------------------------------------------------------------------------- #
#  I3 - MongoDB (27017), no auth. Lab banner instead of real wire protocol.
# --------------------------------------------------------------------------- #
def handle_mongo(conn):
    # Real MongoDB is a binary wire protocol; for the lab we emit a clear,
    # human-readable banner so the open port is unmistakable, then close.
    conn.sendall(b"MongoDB server (no auth)\r\n")
    # Drain anything the client sends, briefly, then the wrapper closes us.
    conn.settimeout(0.5)
    try:
        conn.recv(256)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
#  I7 - MySQL (3306), EOL 5.5.62. Send a real-shaped handshake greeting.
# --------------------------------------------------------------------------- #
def _mysql_handshake():
    """Build a MySQL v10 handshake initial packet whose server-version field is
    the NUL-terminated string b'5.5.62'. A plain recv(160) on connect sees it."""
    proto = b"\x0a"                       # protocol version 10
    server_version = b"5.5.62" + b"\x00"  # NUL-terminated version string
    thread_id = b"\x10\x00\x00\x00"       # connection id = 16
    auth_plugin_data_1 = b"ABCDEFGH"      # 8 bytes of salt
    filler = b"\x00"
    cap_low = b"\xff\xf7"                 # capability flags (lower)
    charset = b"\x21"                     # utf8_general_ci
    status = b"\x02\x00"                  # server status
    cap_high = b"\x0f\x80"                # capability flags (upper)
    auth_len = b"\x15"                    # length of auth-plugin-data = 21
    reserved = b"\x00" * 10
    auth_plugin_data_2 = b"IJKLMNOPQRS\x00"     # remaining salt (12 incl NUL)
    auth_plugin_name = b"mysql_native_password\x00"

    payload = (proto + server_version + thread_id + auth_plugin_data_1 + filler
               + cap_low + charset + status + cap_high + auth_len + reserved
               + auth_plugin_data_2 + auth_plugin_name)

    # 4-byte packet header: 3-byte little-endian length + 1-byte sequence id.
    length = len(payload)
    header = bytes([length & 0xff, (length >> 8) & 0xff, (length >> 16) & 0xff, 0x00])
    return header + payload


MYSQL_GREETING = _mysql_handshake()


def handle_mysql(conn):
    # Server speaks first (as real MySQL does): emit the handshake, then close.
    conn.sendall(MYSQL_GREETING)
    conn.settimeout(0.5)
    try:
        conn.recv(256)   # let the client send its login attempt, then drop it
    except OSError:
        pass


# --------------------------------------------------------------------------- #
#  HTTP services (raw, no http.server needed): I2 Elastic, I4 CouchDB,
#  I5 Docker, I8 admin panel. One tiny HTTP responder, per-service routing.
# --------------------------------------------------------------------------- #
def _read_http_request(conn):
    """Read an HTTP request; return (method, path, headers dict)."""
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        try:
            chunk = conn.recv(1024)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    if not lines or not lines[0]:
        return None, None, {}
    parts = lines[0].split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, path, headers


def _http_response(code, reason, body, server, ctype="application/json", extra=None):
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    head = (
        f"HTTP/1.1 {code} {reason}\r\n"
        f"Server: {server}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
    )
    for k, v in (extra or {}).items():
        head += f"{k}: {v}\r\n"
    head += "Connection: close\r\n\r\n"
    return head.encode("latin-1", "replace") + body


def _make_http_handler(router, server_header):
    def handler(conn):
        method, path, headers = _read_http_request(conn)
        if method is None:
            return
        path = path.split("?")[0]
        code, reason, body, ctype, extra = router(method, path, headers)
        conn.sendall(_http_response(code, reason, body, server_header, ctype, extra))
    return handler


# ---- I2  Elasticsearch (9200), no auth, outdated 1.4.2 -------------------- #
def route_elastic(method, path, headers):
    p = path.rstrip("/") or "/"
    if p == "/":
        body = json.dumps({
            "status": 200,
            "name": "node-1",
            "cluster_name": "elasticsearch",
            "version": {"number": "1.4.2", "build_hash": "927caff6f05403e936c20bf4529f144f0c89fd8c",
                        "build_timestamp": "2014-12-16T14:11:12Z", "build_snapshot": False,
                        "lucene_version": "4.10.2"},
            "tagline": "You Know, for Search",
        })
        return 200, "OK", body, "application/json", None
    if p == "/_cat/indices":
        body = (
            "green open .kibana          1 0    1 0   3.1kb   3.1kb\n"
            "green open secrets          5 1  142 0   1.2mb   1.2mb\n"
            "green open users            5 1  908 3   4.7mb   4.7mb\n"
            "green open app-logs-2026    5 1 5051 0  88.4mb  88.4mb\n"
        )
        return 200, "OK", body, "text/plain; charset=UTF-8", None
    if p == "/_cluster/health":
        body = json.dumps({
            "cluster_name": "elasticsearch", "status": "green", "timed_out": False,
            "number_of_nodes": 1, "number_of_data_nodes": 1, "active_primary_shards": 16,
            "active_shards": 16, "relocating_shards": 0, "initializing_shards": 0,
            "unassigned_shards": 0,
        })
        return 200, "OK", body, "application/json", None
    if p == "/secrets/_search" or p.endswith("/_search"):
        body = json.dumps({
            "took": 2, "timed_out": False,
            "hits": {"total": 1, "max_score": 1.0, "hits": [
                {"_index": "secrets", "_type": "cred", "_id": "1", "_source": {
                    "db_password": "Pr0d-Elastic-DB!2026",
                    "flag": "flag{elasticsearch_no_auth_dump}"}}]},
        })
        return 200, "OK", body, "application/json", None
    return 404, "Not Found", json.dumps({"error": "IndexMissingException", "status": 404}), \
        "application/json", None


# ---- I4  CouchDB (5984), admin party ------------------------------------- #
def route_couchdb(method, path, headers):
    p = path.rstrip("/") or "/"
    if p == "/":
        body = json.dumps({"couchdb": "Welcome", "uuid": "a1b2c3d4e5f6",
                           "version": "1.6.0", "vendor": {"name": "The Apache Software Foundation",
                                                          "version": "1.6.0"}})
        return 200, "OK", body, "application/json", None
    if p == "/_all_dbs":
        return 200, "OK", json.dumps(["_users", "_replicator", "secrets"]), "application/json", None
    if p == "/_config":
        # admin party = empty admins section -> everyone is admin
        body = json.dumps({"admins": {}, "httpd": {"bind_address": "0.0.0.0"}})
        return 200, "OK", body, "application/json", None
    if p == "/secrets/_all_docs":
        body = json.dumps({"total_rows": 1, "offset": 0, "rows": [
            {"id": "cred", "key": "cred", "value": {"rev": "1-abc"}}]})
        return 200, "OK", body, "application/json", None
    return 404, "Object Not Found", json.dumps({"error": "not_found", "reason": "missing"}), \
        "application/json", None


# ---- I5  Docker Engine API (2375), no TLS, no auth ----------------------- #
def route_docker(method, path, headers):
    p = path.rstrip("/") or "/"
    # tolerate versioned prefixes like /v1.40/version
    if p.startswith("/v1.") and "/" in p[1:]:
        p = "/" + p.split("/", 2)[2] if p.count("/") >= 2 else p
    if p == "/version":
        body = json.dumps({
            "Version": "19.03.5", "ApiVersion": "1.40", "MinAPIVersion": "1.12",
            "GitCommit": "633a0ea838", "GoVersion": "go1.12.12", "Os": "linux",
            "Arch": "amd64", "KernelVersion": "4.15.0-66-generic", "BuildTime": "2019-11-13",
        })
        return 200, "OK", body, "application/json", None
    if p == "/containers/json":
        return 200, "OK", json.dumps([]), "application/json", None
    if p == "/info":
        body = json.dumps({
            "ID": "PROD:DOCKER:01", "Name": "prod-docker-01", "Containers": 3,
            "ContainersRunning": 2, "Images": 12, "ServerVersion": "19.03.5",
            "OperatingSystem": "Ubuntu 18.04.3 LTS", "Architecture": "x86_64",
            "DockerRootDir": "/var/lib/docker",
        })
        return 200, "OK", body, "application/json", None
    if p == "/_ping":
        return 200, "OK", "OK", "text/plain", None
    return 404, "Not Found", json.dumps({"message": "page not found"}), "application/json", None


def make_docker_handler(server_header):
    """Docker /_ping returns plain 'OK' with no JSON; reuse generic responder."""
    return _make_http_handler(route_docker, server_header)


# ---- I8  HTTP admin panel (8080), DEFAULT CREDS admin:admin -------------- #
ADMIN_HTML = """<!doctype html>
<html><head><title>OpenServices Admin</title></head>
<body>
<h1>OpenServices Admin Dashboard</h1>
<p>Authenticated. Welcome, <b>admin</b>.</p>
<h2>Users</h2>
<table border="1">
<tr><th>user</th><th>role</th></tr>
<tr><td>admin</td><td>superuser</td></tr>
<tr><td>backup</td><td>operator</td></tr>
<tr><td>svc-deploy</td><td>service</td></tr>
</table>
<h2>Managed hosts</h2>
<table border="1">
<tr><th>host</th><th>service</th></tr>
<tr><td>prod-redis-01</td><td>redis:6379</td></tr>
<tr><td>prod-es-01</td><td>elasticsearch:9200</td></tr>
<tr><td>prod-docker-01</td><td>docker:2375</td></tr>
</table>
<p>flag{admin_panel_default_creds}</p>
</body></html>"""


def route_admin(method, path, headers):
    p = path.rstrip("/") or "/"
    if p in ("/", "/admin"):
        auth = headers.get("authorization", "")
        ok = False
        if auth.lower().startswith("basic "):
            try:
                dec = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
                ok = (dec == "admin:admin")
            except (ValueError, base64.binascii.Error):
                ok = False
        if ok:
            return 200, "OK", ADMIN_HTML, "text/html; charset=UTF-8", None
        return 401, "Unauthorized", \
            "<html><body><h1>401 Unauthorized</h1></body></html>", \
            "text/html; charset=UTF-8", {"WWW-Authenticate": 'Basic realm="Admin"'}
    return 404, "Not Found", "<html><body><h1>404 Not Found</h1></body></html>", \
        "text/html; charset=UTF-8", None


# --------------------------------------------------------------------------- #
#  Service registry  (port -> (label, vuln id, handler))
# --------------------------------------------------------------------------- #
SERVICES = [
    (6379,  "Redis (no auth)",                 "I1", handle_redis),
    (9200,  "Elasticsearch 1.4.2 (no auth)",   "I2", _make_http_handler(route_elastic, "")),
    (27017, "MongoDB (no auth)",               "I3", handle_mongo),
    (5984,  "CouchDB 1.6.0 (admin party)",     "I4", _make_http_handler(route_couchdb, "CouchDB/1.6.0 (Erlang OTP/R16B03)")),
    (2375,  "Docker Engine API (no TLS)",      "I5", make_docker_handler("Docker/19.03.5 (linux)")),
    (11211, "Memcached 1.4.15 (no auth)",      "I6", handle_memcached),
    (3306,  "MySQL 5.5.62 (EOL)",              "I7", handle_mysql),
    (8080,  "Admin panel (default creds)",     "I8", _make_http_handler(route_admin, "Apache/2.2.15")),
]


def main():
    bound = []
    lock = threading.Lock()
    print("OpenServices - INTENTIONALLY VULNERABLE infra host (127.0.0.1 only)")
    print("Starting service listeners on standard ports...")
    for port, label, vid, handler in SERVICES:
        serve(port, handler, bound, lock)

    bound.sort()
    print("\n=== Startup summary ===")
    if not bound:
        print("  (no ports bound -- everything was already in use?)")
    for port, label, vid, _ in SERVICES:
        status = "BOUND " if port in bound else "SKIP  "
        print(f"  [{status}] {vid}  {port:<6} {label}")
    print(f"\n{len(bound)}/{len(SERVICES)} services listening. Ctrl+C to stop.")

    # Keep the main thread alive; all accept loops run as daemons.
    try:
        ev = threading.Event()
        ev.wait()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
