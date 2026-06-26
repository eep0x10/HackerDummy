#!/usr/bin/env python3
"""
SmuggleForge - Deliberately vulnerable HTTP request smuggling lab.

  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

A GENUINE front-end/back-end desync, not a mock. Two stdlib raw-socket servers:

  - BACK-END  (127.0.0.1:18820, internal)  honours Transfer-Encoding: chunked over
    Content-Length, and serves an internal-only `/admin` (no auth — it trusts that
    the front-end blocks external access).
  - FRONT-END (127.0.0.1:18819, the target) routes/length-delimits by Content-Length
    and IGNORES Transfer-Encoding, and BLOCKS /admin for external clients (403).

Because the two tiers disagree on which header delimits the body (CL.TE), an attacker
can smuggle a second request past the front-end's /admin block to the back-end:

    POST /search HTTP/1.1
    Content-Length: <covers the smuggled request>
    Transfer-Encoding: chunked

    0

    GET /admin HTTP/1.1
    ...

The front-end (CL) forwards the whole thing; the back-end (TE) ends the chunked body
at `0` and treats `GET /admin ...` as a SECOND request -> serves the admin secret,
whose response the front-end relays back. Run: targets the FRONT-END on 18819.

See gabarito.json. Nothing here executes code; the only "secret" is a lab flag.
"""
import socket
import threading

FRONT_HOST, FRONT_PORT = "127.0.0.1", 18819
BACK_HOST, BACK_PORT = "127.0.0.1", 18820
ADMIN_SECRET = "flag{http_request_smuggling_cl_te_desync}"


# --------------------------------------------------------------------------- utils
def _recv_until_headers(sock, buf):
    while b"\r\n\r\n" not in buf:
        data = sock.recv(4096)
        if not data:
            return None, buf
        buf += data
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _parse(head):
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return method, path, headers


def _read_chunked(sock, rest):
    """Read a chunked body from `rest` (+socket). Return (body, leftover-after-body)."""
    body = b""
    while True:
        while b"\r\n" not in rest:
            d = sock.recv(4096)
            if not d:
                return body, rest
            rest += d
        size_line, _, rest = rest.partition(b"\r\n")
        try:
            size = int(size_line.strip().split(b";")[0], 16)
        except ValueError:
            return body, rest
        if size == 0:
            # consume the trailing CRLF after the last chunk
            while len(rest) < 2:
                rest += sock.recv(4096)
            rest = rest[2:] if rest[:2] == b"\r\n" else rest
            return body, rest
        while len(rest) < size + 2:
            rest += sock.recv(4096)
        body += rest[:size]
        rest = rest[size + 2:]   # skip chunk data + CRLF


def _read_cl(sock, rest, n):
    while len(rest) < n:
        d = sock.recv(4096)
        if not d:
            break
        rest += d
    return rest[:n], rest[n:]


def _resp(body, ctype="text/plain", status=b"200 OK"):
    if isinstance(body, str):
        body = body.encode()
    return (b"HTTP/1.1 " + status + b"\r\nServer: SmuggleForge-backend/1.0\r\n"
            b"Content-Type: " + ctype.encode() + b"\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + body)


# --------------------------------------------------------------------------- backend
def backend_handle(conn):
    """Back-end: Transfer-Encoding takes precedence over Content-Length."""
    conn.settimeout(4)
    buf = b""
    try:
        while True:
            head, rest = _recv_until_headers(conn, buf)
            if head is None:
                return
            method, path, headers = _parse(head)
            te = headers.get("transfer-encoding", "").lower()
            if "chunked" in te:                         # *** back-end honours TE ***
                _, rest = _read_chunked(conn, rest)
            elif "content-length" in headers:
                _, rest = _read_cl(conn, rest, int(headers["content-length"] or 0))
            p = path.split("?")[0]
            if p == "/admin":
                conn.sendall(_resp(f"INTERNAL ADMIN PANEL (back-end). secret={ADMIN_SECRET}"))
            elif p == "/":
                conn.sendall(_resp('{"service":"SmuggleForge","endpoints":["/search (POST)"]}',
                                   "application/json"))
            elif p == "/search":
                conn.sendall(_resp('{"results":[]}', "application/json"))
            else:
                conn.sendall(_resp("404 Not Found", status=b"404 Not Found"))
            buf = rest                                  # leftover bytes = smuggled request
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


# -------------------------------------------------------------------------- frontend
def frontend_handle(client):
    """Front-end: length-delimits by Content-Length, ignores TE; blocks /admin."""
    client.settimeout(4)
    buf = b""
    try:
        head, rest = _recv_until_headers(client, buf)
        if head is None:
            return
        method, path, headers = _parse(head)
        # *** front-end security control: external /admin is forbidden ***
        if path.split("?")[0] == "/admin":
            body = b"403 Forbidden: /admin is internal-only (front-end blocked)"
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nServer: SmuggleForge/1.0\r\n"
                           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            return
        # *** front-end length-delimits by Content-Length only (ignores TE) ***
        n = int(headers.get("content-length", 0) or 0)
        fbody, _ = _read_cl(client, rest, n)
        # forward the raw bytes (head + CL body) to the back-end and relay the reply
        back = socket.create_connection((BACK_HOST, BACK_PORT), timeout=4)
        back.sendall(head + b"\r\n\r\n" + fbody)
        back.settimeout(2)
        try:
            while True:
                data = back.recv(4096)
                if not data:
                    break
                client.sendall(data)                    # relays BOTH responses on a smuggle
        except socket.timeout:
            pass
        back.close()
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        return
    finally:
        try:
            client.close()
        except OSError:
            pass


def _serve(host, port, handler, name):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def main():
    threading.Thread(target=_serve, args=(BACK_HOST, BACK_PORT, backend_handle, "backend"),
                     daemon=True).start()
    print(f"SmuggleForge: back-end (internal) on {BACK_HOST}:{BACK_PORT}")
    print(f"SmuggleForge: FRONT-END (target) on http://{FRONT_HOST}:{FRONT_PORT}  --  Ctrl+C to stop")
    try:
        _serve(FRONT_HOST, FRONT_PORT, frontend_handle, "frontend")
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
