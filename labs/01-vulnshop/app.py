#!/usr/bin/env python3
"""
VulnShop - Deliberately vulnerable e-commerce app for pentest training.

  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

Single-file, stdlib-only (http.server + sqlite3 + urllib). No external deps.
Run:  python app.py    -> http://127.0.0.1:18801

Planted vulns (see gabarito.json / README.md):
  RECON: V01 .git, V02 .env, V03 backup.sql, V04 dir-listing, V05 missing
         security headers, V06 insecure cookie, V07 verbose errors,
         V08 admin panel, + robots.txt -> /secret-admin breadcrumb.
  EXPLOIT: V09 SQLi auth bypass, V10 SQLi product, V11 reflected XSS,
           V12 stored XSS, V13 IDOR, V14 open redirect, V15 SSRF.
"""

import http.server
import socketserver
import sqlite3
import threading
import traceback
import urllib.parse
import urllib.request
import urllib.error
import html as _html_mod

HOST = "127.0.0.1"
PORT = 18801

# ---------------------------------------------------------------------------
# Database (single shared in-memory sqlite, accessed across threads)
# ---------------------------------------------------------------------------
# check_same_thread=False so the ThreadingHTTPServer can share it; we guard
# every query with a lock so the lab is stable under a crawler's concurrency.
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.row_factory = sqlite3.Row
_DB_LOCK = threading.Lock()


def init_db():
    cur = _DB.cursor()
    cur.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            total REAL
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            author TEXT,
            body TEXT
        );
        """
    )
    cur.executemany(
        "INSERT INTO users (id, username, password, email, role) VALUES (?,?,?,?,?)",
        [
            (1, "admin", "S3cr3tAdminP@ss", "admin@vulnshop.local", "admin"),
            (2, "alice", "alice123", "alice@vulnshop.local", "customer"),
            (3, "bob", "bobpassword", "bob@vulnshop.local", "customer"),
            (4, "carol", "letmein2024", "carol@vulnshop.local", "customer"),
        ],
    )
    cur.executemany(
        "INSERT INTO products (id, name, price, description) VALUES (?,?,?,?)",
        [
            (1, "Quantum Toaster", 79.99, "Toasts bread across parallel universes."),
            (2, "Nano Umbrella", 19.50, "Folds down to the size of an atom."),
            (3, "Self-Stirring Mug", 14.25, "Never stir your coffee again."),
            (4, "Holographic Sticky Notes", 9.99, "Notes that float above your desk."),
        ],
    )
    cur.executemany(
        "INSERT INTO orders (id, user_id, item, total) VALUES (?,?,?,?)",
        [
            (1, 2, "Quantum Toaster", 79.99),
            (2, 3, "Nano Umbrella", 19.50),
            (3, 4, "Self-Stirring Mug", 14.25),
            (4, 2, "Holographic Sticky Notes", 9.99),
            (5, 3, "Quantum Toaster", 79.99),
        ],
    )
    cur.executemany(
        "INSERT INTO comments (id, author, body) VALUES (?,?,?)",
        [
            (1, "alice", "Love the Quantum Toaster, 5 stars!"),
            (2, "bob", "Fast shipping, would buy again."),
        ],
    )
    _DB.commit()


def db_execute(sql):
    """Run a raw SQL string and return list of sqlite3.Row. Raises on error."""
    with _DB_LOCK:
        cur = _DB.cursor()
        cur.execute(sql)
        try:
            return cur.fetchall()
        except sqlite3.Error:
            return []


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------
PAGE = """<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body style="font-family:sans-serif;max-width:800px;margin:2em auto">
{body}
</body></html>"""


def page(title, body):
    return PAGE.format(title=title, body=body).encode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
class VulnShopHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    sys_version = "(Ubuntu)"
    protocol_version = "HTTP/1.1"

    # -- low-level helpers --------------------------------------------------
    def _send(self, code, body, content_type="text/html; charset=utf-8",
              extra_headers=None, set_cookie=None):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # V05: deliberately DO NOT send X-Frame-Options, CSP,
        # X-Content-Type-Options, or Strict-Transport-Security.
        if set_cookie:
            # V06: insecure cookie - no HttpOnly / Secure / SameSite.
            self.send_header("Set-Cookie", set_cookie)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _redirect(self, location, set_cookie=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def _query(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def _body_params(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return urllib.parse.parse_qs(raw, keep_blank_values=True), raw

    def _qp(self, params, name, default=""):
        vals = params.get(name)
        return vals[0] if vals else default

    # Quiet the default logging to one tidy line.
    def log_message(self, fmt, *args):
        try:
            print("[req] %s - %s" % (self.address_string(), fmt % args))
        except Exception:
            pass

    # -- routing ------------------------------------------------------------
    def do_GET(self):
        try:
            path, params = self._query()
            self.route_get(path, params)
        except VerboseError:
            # V07: intentional verbose traceback (re-raised to the wrapper).
            self._send(500, verbose_traceback_page(),
                       content_type="text/html; charset=utf-8")
        except Exception:
            # Safety net so the server never dies on unexpected input.
            self._send(500, verbose_traceback_page())

    def do_POST(self):
        try:
            path, params = self._query()
            self.route_post(path, params)
        except VerboseError:
            self._send(500, verbose_traceback_page())
        except Exception:
            self._send(500, verbose_traceback_page())

    # -- GET routes ---------------------------------------------------------
    def route_get(self, path, params):
        # --- RECON breadcrumbs ---
        if path == "/robots.txt":
            return self._send(
                200,
                "User-agent: *\nDisallow: /secret-admin\nDisallow: /admin\n",
                content_type="text/plain; charset=utf-8",
            )
        if path == "/.git/config":
            return self._send(200, GIT_CONFIG,
                              content_type="text/plain; charset=utf-8")
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n",
                              content_type="text/plain; charset=utf-8")
        if path == "/.env":  # V02
            return self._send(200, ENV_FILE,
                              content_type="text/plain; charset=utf-8")
        if path == "/backup.sql":  # V03
            return self._send(200, BACKUP_SQL,
                              content_type="text/plain; charset=utf-8")
        if path == "/uploads/" or path == "/uploads":  # V04
            return self._send(200, DIR_LISTING)
        if path == "/secret-admin":
            return self._send(200, page(
                "Secret Admin",
                "<h1>secret-admin</h1><p>You found the breadcrumb from "
                "robots.txt. Hidden ops console. Try <a href='/admin'>/admin"
                "</a>.</p>"))

        # --- core pages ---
        if path == "/" or path == "/index.html":
            return self._send(200, home_page())
        if path == "/login":
            return self._send(200, login_page())
        if path == "/dashboard":
            return self._send(200, page(
                "Dashboard",
                "<h1>Welcome to your dashboard</h1>"
                "<p>You are logged in.</p>"
                "<p><a href='/admin'>Admin panel</a></p>"))

        # --- V08: admin panel, no auth ---
        if path == "/admin":
            rows = db_execute("SELECT id, username, email, role FROM users")
            items = "".join(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    r["id"], r["username"], r["email"], r["role"]) for r in rows)
            return self._send(200, page(
                "Admin Panel",
                "<h1>Admin Panel</h1><p>User management (no auth required!)</p>"
                "<table border=1 cellpadding=4><tr><th>id</th><th>username</th>"
                "<th>email</th><th>role</th></tr>" + items + "</table>"))

        # --- V11: reflected XSS ---
        if path == "/search":
            q = self._qp(params, "q")
            # Reflected unencoded - intentional XSS.
            return self._send(200, page(
                "Search",
                "<h1>Search results</h1>"
                "<form action='/search'><input name='q' value=''>"
                "<button>Search</button></form>"
                "<p>You searched for: " + q + "</p>"))

        # --- V10: SQLi in product (verbose error) ---
        if path == "/product":
            pid = self._qp(params, "id", "1")
            sql = "SELECT id, name, price, description FROM products WHERE id=" + pid
            try:
                rows = db_execute(sql)
            except sqlite3.Error as e:
                # V07/V10: verbose SQL error leaked to the client.
                return self._send(200, page(
                    "Product error",
                    "<h1>Database error</h1><pre>OperationalError: %s</pre>"
                    "<p>Query: <code>%s</code></p>" % (
                        _html_mod.escape(str(e)), _html_mod.escape(sql))))
            if not rows:
                return self._send(200, page(
                    "Product", "<h1>No product found</h1>"
                    "<p>Query returned 0 rows.</p>"))
            body = "<h1>Products</h1>"
            for r in rows:
                body += ("<div><h2>%s (#%s)</h2><p>$%s</p><p>%s</p></div>" % (
                    r["name"], r["id"], r["price"], r["description"]))
            return self._send(200, page("Product", body))

        # --- V12: stored XSS render ---
        if path == "/comments":
            rows = db_execute("SELECT author, body FROM comments ORDER BY id")
            items = ""
            for r in rows:
                # Rendered unencoded - stored XSS.
                items += "<li><b>%s</b>: %s</li>" % (r["author"], r["body"])
            return self._send(200, page(
                "Comments",
                "<h1>Customer Comments</h1><ul>" + items + "</ul>"
                "<h2>Leave a comment</h2>"
                "<form method='POST' action='/comment'>"
                "<input name='author' placeholder='name'><br>"
                "<textarea name='body' placeholder='comment'></textarea><br>"
                "<button>Post</button></form>"))

        # --- V13: IDOR (path or query form) ---
        if path.startswith("/api/order"):
            oid = None
            if path == "/api/order":
                oid = self._qp(params, "id")
            else:  # /api/order/<id>
                oid = path.rsplit("/", 1)[-1]
            try:
                oid_i = int(oid)
            except (ValueError, TypeError):
                return self._send(400, '{"error":"id must be int"}',
                                  content_type="application/json")
            rows = db_execute(
                "SELECT id, user_id, item, total FROM orders WHERE id=%d" % oid_i)
            if not rows:
                return self._send(404, '{"error":"not found"}',
                                  content_type="application/json")
            r = rows[0]
            # No ownership check - returns ANY user's order.
            j = ('{"id":%s,"user_id":%s,"item":"%s","total":%s}' % (
                r["id"], r["user_id"], r["item"], r["total"]))
            return self._send(200, j, content_type="application/json")

        # --- V14: open redirect ---
        if path == "/redirect":
            url = self._qp(params, "url")
            if not url:
                return self._send(200, page(
                    "Redirect",
                    "<h1>Redirector</h1>"
                    "<p>Usage: <code>/redirect?url=https://example.com</code></p>"))
            # No validation - open redirect.
            return self._redirect(url)

        # --- V15: SSRF ---
        if path == "/fetch":
            url = self._qp(params, "url")
            if not url:
                return self._send(200, page(
                    "Fetch",
                    "<h1>URL Fetcher</h1>"
                    "<p>Server-side fetch. Usage: "
                    "<code>/fetch?url=http://127.0.0.1:18801/</code></p>"))
            scheme = urllib.parse.urlparse(url).scheme.lower()
            if scheme not in ("http", "https"):
                return self._send(400, page(
                    "Fetch", "<h1>Only http/https allowed</h1>"))
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "VulnShop-Fetch"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = resp.read(65536)
                return self._send(
                    200, data,
                    content_type="text/plain; charset=utf-8")
            except urllib.error.URLError as e:
                return self._send(502, page(
                    "Fetch", "<h1>Fetch failed</h1><pre>%s</pre>"
                    % _html_mod.escape(str(e))))

        # --- favicon to keep crawler logs clean ---
        if path == "/favicon.ico":
            return self._send(404, "")

        # Unknown -> 404 with a couple of recon hints.
        return self._send(404, page(
            "404", "<h1>404 Not Found</h1>"
            "<p>No such page: %s</p>" % _html_mod.escape(path)))

    # -- POST routes --------------------------------------------------------
    def route_post(self, path, params):
        # --- V09: SQLi auth bypass ---
        if path == "/login":
            body, _ = self._body_params()
            u = self._qp(body, "username")
            p = self._qp(body, "password")
            # String-concat SQL - classic auth bypass.
            sql = ("SELECT id, username, role FROM users WHERE username='%s' "
                   "AND password='%s'" % (u, p))
            try:
                rows = db_execute(sql)
            except sqlite3.Error as e:
                return self._send(200, page(
                    "Login error",
                    "<h1>Database error</h1><pre>%s</pre><p>Query: <code>%s</code></p>"
                    % (_html_mod.escape(str(e)), _html_mod.escape(sql))))
            if rows:
                r = rows[0]
                # V06: insecure session cookie.
                cookie = "session=user-%s-%s; Path=/" % (r["id"], r["role"])
                return self._redirect("/dashboard", set_cookie=cookie)
            return self._send(200, page(
                "Login", "<h1>Invalid credentials</h1>"
                "<p><a href='/login'>Try again</a></p>"))

        # --- V12: store comment ---
        if path == "/comment":
            body, _ = self._body_params()
            author = self._qp(body, "author") or "anonymous"
            text = self._qp(body, "body")
            with _DB_LOCK:
                cur = _DB.cursor()
                cur.execute("INSERT INTO comments (author, body) VALUES (?, ?)",
                            (author, text))
                _DB.commit()
            return self._redirect("/comments")

        return self._send(404, page("404", "<h1>404</h1><p>No POST here.</p>"))


class VerboseError(Exception):
    pass


def verbose_traceback_page():
    """V07: full Python traceback in the response body."""
    tb = traceback.format_exc()
    if not tb or tb.strip() == "NoneType: None":
        tb = "Traceback (most recent call last):\n  (no active exception)\n"
    return page(
        "500 Internal Server Error",
        "<h1>500 Internal Server Error</h1>"
        "<p>An unhandled exception occurred. Debug mode is ON.</p>"
        "<pre style='background:#eee;padding:1em'>%s</pre>"
        % _html_mod.escape(tb))


# ---------------------------------------------------------------------------
# Static-ish content for recon vulns
# ---------------------------------------------------------------------------
GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/vulnshop-internal/vulnshop.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = deploy-bot
\temail = deploy@vulnshop.local
"""

ENV_FILE = """# VulnShop production environment - DO NOT COMMIT
APP_ENV=production
DEBUG=true
DB_HOST=127.0.0.1
DB_NAME=vulnshop
DB_USER=vulnshop_app
DB_PASSWORD=Pr0d_DB_P@ssw0rd_2024
SECRET_KEY=lab_fake_flask_secret_key_not_real_do_not_use
STRIPE_KEY=sk_live_LAB_FAKE_placeholder_not_a_real_stripe_key
JWT_SECRET=super-insecure-jwt-signing-secret-change-me
ADMIN_EMAIL=admin@vulnshop.local
"""

BACKUP_SQL = """-- VulnShop database backup
-- Generated by deploy-bot. Contains plaintext credentials.
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    email TEXT,
    role TEXT
);
INSERT INTO users VALUES (1,'admin','S3cr3tAdminP@ss','admin@vulnshop.local','admin');
INSERT INTO users VALUES (2,'alice','alice123','alice@vulnshop.local','customer');
INSERT INTO users VALUES (3,'bob','bobpassword','bob@vulnshop.local','customer');
INSERT INTO users VALUES (4,'carol','letmein2024','carol@vulnshop.local','customer');
-- legacy md5 hashes (pre-migration)
-- admin: 8e8b6151c44e8d77e8aa9f4b6f6a6e3b
-- bcrypt sample: $2b$12$Km0Q1Q9Q9Q9Q9Q9Q9Q9Qeu
"""

DIR_LISTING = """<!DOCTYPE html>
<html><head><title>Index of /uploads</title></head>
<body>
<h1>Index of /uploads</h1>
<table>
<tr><th>Name</th><th>Last modified</th><th>Size</th></tr>
<tr><td><a href="../">Parent Directory</a></td><td></td><td>-</td></tr>
<tr><td><a href="invoice_1.pdf">invoice_1.pdf</a></td><td>2024-05-01 12:03</td><td>48K</td></tr>
<tr><td><a href="invoice_2.pdf">invoice_2.pdf</a></td><td>2024-05-02 09:11</td><td>51K</td></tr>
<tr><td><a href="db_dump.sql">db_dump.sql</a></td><td>2024-05-03 23:47</td><td>12K</td></tr>
<tr><td><a href="users_export.csv">users_export.csv</a></td><td>2024-05-04 08:20</td><td>3.1K</td></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at 127.0.0.1 Port 18801</address>
</body></html>"""


def login_page():
    return page(
        "Login",
        "<h1>VulnShop Login</h1>"
        "<form method='POST' action='/login'>"
        "<p>Username: <input name='username'></p>"
        "<p>Password: <input type='password' name='password'></p>"
        "<button>Log in</button></form>")


def home_page():
    return page(
        "VulnShop - Home",
        "<h1>VulnShop</h1>"
        "<p>The store at the end of the universe. <em>(Training lab - "
        "intentionally vulnerable.)</em></p>"
        "<h2>Browse</h2><ul>"
        "<li><a href='/search?q=toaster'>Search</a></li>"
        "<li><a href='/product?id=1'>Featured product</a></li>"
        "<li><a href='/login'>Login</a></li>"
        "<li><a href='/comments'>Customer comments</a></li>"
        "<li><a href='/admin'>Admin panel</a></li>"
        "<li><a href='/uploads/'>Uploads</a></li>"
        "<li><a href='/redirect?url=https://example.com'>Go to partner</a></li>"
        "<li><a href='/fetch?url=http://127.0.0.1:18801/'>URL fetcher</a></li>"
        "<li><a href='/api/order?id=1'>Order API</a></li>"
        "</ul>")


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    init_db()
    httpd = ThreadingTCPServer((HOST, PORT), VulnShopHandler)
    print("VulnShop (vulnerable training lab) listening on "
          "http://%s:%d  --  Ctrl+C to stop" % (HOST, PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
