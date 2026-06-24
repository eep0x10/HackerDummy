#!/usr/bin/env python3
"""
TrustEdge - Deliberately-vulnerable web app lab.

INTENTIONALLY VULNERABLE. For local security training only.
Bind: 127.0.0.1:18808. Stdlib only (http.server + json + threading).

TrustEdge is a tiny "account portal" whose every bug comes from blindly
TRUSTING attacker-controlled request headers / params: CORS Origin reflection,
Host / X-Forwarded-Host header injection, CRLF response splitting, and an
unkeyed-header web-cache-poisoning primitive. Planted vulns T1..T7 (see
README.md). The app fakes a "logged-in" user (a session cookie is assumed
present) - there is no real auth; the point is the trust-boundary bugs.
"""
import http.server
import json
import socketserver
import urllib.parse

HOST = "127.0.0.1"
PORT = 18808

# Fake "currently logged-in" user. In a real app this would come from the
# session cookie; here it is hardcoded so the trust-boundary bugs are the
# only moving part.
ACCOUNT = {
    "user": "victim",
    "email": "victim@trustedge.local",
    "balance": 4242.00,
    "apiKey": "te_live_9f3c2a1b8e7d6c5f",
    "ssn": "555-12-9999",
}

DATA = {
    "records": [
        {"id": 1, "label": "Q1 revenue", "value": 120000},
        {"id": 2, "label": "Q2 revenue", "value": 138500},
        {"id": 3, "label": "internal note", "value": "merger pending"},
    ],
    "owner": "victim",
}

# Toy in-memory token store for the password-reset flow (T3).
RESET_TOKENS = {}


def _origin_of(handler):
    """Return the request's Origin header (or None)."""
    return handler.headers.get("Origin")


def _effective_host(handler):
    """
    T4 / T6: trust X-Forwarded-Host over the real Host header when present.
    This is the unkeyed, attacker-controlled value the app builds URLs from.
    """
    xfh = handler.headers.get("X-Forwarded-Host")
    if xfh:
        return xfh
    return handler.headers.get("Host", "%s:%d" % (HOST, PORT))


def html_escape(s):
    """Minimal HTML-attribute/body escaping (does NOT neutralize the planted
    trust bugs - the attacker-controlled host still lands in href/src, which
    is the whole point of T4/T6)."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Page rendering
# ---------------------------------------------------------------------------
def render_home(handler):
    """
    GET / home page.

    T4: builds absolute URLs / a canonical link from X-Forwarded-Host (else Host).
    T6: reflects that same unkeyed header into the response BODY (canonical link,
        asset <script src>) AND the response is marked Cache-Control: public.
    """
    host = _effective_host(handler)
    base = "http://%s" % host
    canon = html_escape(base + "/")
    asset = html_escape(base + "/static/app.js")
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TrustEdge - account portal</title>
<!-- T4/T6: canonical + asset built from (X-Forwarded-)Host, attacker controlled -->
<link rel="canonical" href="%s">
<script src="%s"></script>
</head>
<body>
<h1>TrustEdge</h1>
<p>Signed in as <b>victim</b> (session cookie assumed present).</p>
<p>Canonical base for this response: <code>%s</code></p>
<ul>
  <li><a href="/profile">/profile</a> - your profile (absolute links use X-Forwarded-Host)</li>
  <li><a href="/api/account">/api/account</a> - JSON account data (CORS)</li>
  <li><a href="/api/data">/api/data</a> - JSON business data (CORS)</li>
  <li><a href="/reset">/reset</a> - password reset (POST user=...)</li>
  <li><a href="/redirect?next=/profile">/redirect?next=...</a> - safe redirector</li>
</ul>
<form action="/reset" method="post">
  <label>Reset password for: <input name="user" value="victim"></label>
  <button type="submit">Send reset link</button>
</form>
</body>
</html>
""" % (canon, asset, html_escape(host))


def render_profile(handler):
    """
    GET /profile page.

    T4: canonical link + absolute action URLs built from X-Forwarded-Host.
    """
    host = _effective_host(handler)
    base = "http://%s" % host
    canon = html_escape(base + "/profile")
    avatar = html_escape(base + "/static/avatar/victim.png")
    home = html_escape(base + "/")
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TrustEdge - profile</title>
<!-- T4: canonical built from (X-Forwarded-)Host -->
<link rel="canonical" href="%s">
</head>
<body>
<h1>Profile: victim</h1>
<img src="%s" alt="avatar" width="48" height="48">
<p>Email: victim@trustedge.local</p>
<p>Absolute home link (built from X-Forwarded-Host): <a href="%s">%s</a></p>
<p><a href="/">back home</a></p>
</body>
</html>
""" % (canon, avatar, home, home)


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # quiet

    # -- low-level senders ---------------------------------------------------
    def _send(self, body, code=200, content_type="text/html; charset=utf-8",
              extra_headers=None, cacheable=False):
        """
        Send a normal response.

        T7: deliberately NEVER emits Content-Security-Policy,
            X-Content-Type-Options, X-Frame-Options or Strict-Transport-Security.
        """
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cacheable:
            # T6: mark the (reflected, unkeyed-header) response as cacheable.
            self.send_header("Cache-Control", "public, max-age=300")
        else:
            self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _cors_headers(self, allow_null_default=False):
        """
        Build the (broken) CORS headers.

        T1/T2: reflect the request Origin verbatim into Access-Control-Allow-Origin
               and always set Access-Control-Allow-Credentials: true. Origin "null"
               is reflected just like any other (T2).
        """
        origin = _origin_of(self)
        headers = []
        if origin is not None:
            headers.append(("Access-Control-Allow-Origin", origin))
            headers.append(("Access-Control-Allow-Credentials", "true"))
        elif allow_null_default:
            headers.append(("Access-Control-Allow-Origin", "null"))
            headers.append(("Access-Control-Allow-Credentials", "true"))
        return headers

    def _send_json(self, obj, code=200, extra_headers=None):
        body = json.dumps(obj, indent=2).encode("utf-8")
        # T7: no security headers here either.
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    # -- routing -------------------------------------------------------------
    def do_OPTIONS(self):
        # Friendly CORS preflight that mirrors the broken policy.
        cors = self._cors_headers(allow_null_default=False)
        cors.append(("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
        cors.append(("Access-Control-Allow-Headers", "*"))
        self._send("", code=204, extra_headers=cors)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path

        if path in ("/", "/index.html"):
            # T4 + T6: reflected, X-Forwarded-Host-built, cacheable HTML.
            self._send(render_home(self), cacheable=True)
            return

        if path == "/profile":
            # T4: absolute links built from X-Forwarded-Host.
            self._send(render_profile(self), cacheable=True)
            return

        if path == "/api/account":
            # T1: CORS reflects Origin + credentials -> any site reads this.
            self._send_json(ACCOUNT, extra_headers=self._cors_headers())
            return

        if path == "/api/data":
            # T2: also reflects Origin, and defaults ACAO:null when none given.
            self._send_json(
                DATA, extra_headers=self._cors_headers(allow_null_default=True)
            )
            return

        if path == "/redirect":
            self._do_redirect()
            return

        if path == "/reset":
            # Friendly GET form for discoverability; the bug is in POST.
            self._send(
                "<!doctype html><meta charset=utf-8>"
                "<form action='/reset' method='post'>"
                "<input name='user' value='victim'>"
                "<button>Send reset link</button></form>"
            )
            return

        self._send("<h1>404</h1><p>Not found: %s</p>" % html_escape(path),
                   code=404)

    def do_HEAD(self):
        # Mirror GET / headers (no body). T7: still no security headers, and
        # T6: still cacheable - so `curl -I /` reflects the real header set.
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/", "/index.html", "/profile"):
            body = (render_home(self) if path != "/profile"
                    else render_profile(self)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=300")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/reset":
            self._do_reset()
            return
        self._send_json({"error": "not found", "path": path}, code=404)

    # -- T3: Host header injection in password reset -------------------------
    def _do_reset(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        params = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        user = (params.get("user", [""])[0]) or "unknown"

        # Generate a (predictable, toy) reset token.
        token = "tok_%08x" % (abs(hash(user)) & 0xFFFFFFFF)
        RESET_TOKENS[user] = token

        # T3: the reset LINK is built from the attacker-controlled Host header.
        # Send Host: evil.example and the victim's email gets a link pointing
        # at evil.example -> poisoned reset -> account takeover.
        host = self.headers.get("Host", "%s:%d" % (HOST, PORT))
        link = "http://%s/reset-confirm?token=%s" % (host, token)

        self._send_json({
            "message": "reset link sent",
            "user": user,
            "link": link,
        })

    # -- T5: CRLF injection / HTTP response splitting ------------------------
    def _do_redirect(self):
        """
        GET /redirect?next=<url> -> 302 Location: <next>, with the raw value
        (including any CR/LF) written straight into the header block. We bypass
        send_header entirely and write the status line + headers to self.wfile
        so that an injected CRLF in `next` actually splits the response and the
        attacker's extra header (e.g. Set-Cookie: admin=1) lands.
        """
        qs = urllib.parse.urlsplit(self.path).query
        # Do NOT use parse_qs here: it would split on '&' etc. but more
        # importantly we must preserve the decoded CR/LF bytes verbatim.
        nxt = ""
        for part in qs.split("&"):
            if part.startswith("next="):
                # unquote_plus turns %0d%0a into real CR LF (the vuln).
                nxt = urllib.parse.unquote_plus(part[len("next="):])
                break

        body = (
            "<!doctype html><meta charset=utf-8>"
            "<p>Redirecting to <code>%s</code></p>" % html_escape(nxt)
        ).encode("utf-8")

        # Manually serialize the response so CR/LF inside `nxt` is NOT
        # rejected/stripped by http.client's header validation.
        # T7: still no security headers.
        head = (
            "HTTP/1.1 302 Found\r\n"
            "Location: " + nxt + "\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: " + str(len(body)) + "\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        try:
            self.wfile.write(head.encode("utf-8", "replace"))
            self.wfile.write(body)
        except Exception:
            pass
        # We wrote a Connection: close response by hand; make sure the server
        # closes rather than trying to keep-alive on a hand-rolled response.
        self.close_connection = True


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("TrustEdge listening on http://%s:%d  (GET /) "
          "- INTENTIONALLY VULNERABLE, localhost only" % (HOST, PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
