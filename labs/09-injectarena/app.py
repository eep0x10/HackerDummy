#!/usr/bin/env python3
"""
InjectArena - Deliberately-vulnerable web app lab.

INTENTIONALLY VULNERABLE. For local security training only.
Bind: 127.0.0.1:18809. Stdlib only (http.server + json + re + xml.etree).

InjectArena is an "injection range": each endpoint SIMULATES a different
backend query language (MongoDB, LDAP, XPath, SSI, CSV/spreadsheet) and is
deliberately injectable. No real database/LDAP/XPath server is needed - the
backends are simulated faithfully enough that the injections genuinely change
behavior, so a pentester can confirm them. Planted vulns N1..N5 (see README.md).

All secrets / salaries below are PLACEHOLDER (non-real) lab values.
"""
import http.server
import json
import re
import socketserver
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
import html as htmllib

HOST = "127.0.0.1"
PORT = 18809

# ---------------------------------------------------------------------------
# Seeded in-memory data. ~4 users. Secrets/salaries are PLACEHOLDER values.
# ---------------------------------------------------------------------------
USERS = [
    {
        "username": "admin",
        "password": "S3cr3t-Admin!",
        "email": "admin@injectarena.local",
        "salary": 999000,
        "role": "admin",
        "secret": "PLACEHOLDER-FLAG-admin-7f3a",
    },
    {
        "username": "alice",
        "password": "alicepass123",
        "email": "alice@injectarena.local",
        "salary": 82000,
        "role": "engineer",
        "secret": "PLACEHOLDER-FLAG-alice-2b9c",
    },
    {
        "username": "bob",
        "password": "bobby-bob",
        "email": "bob@injectarena.local",
        "salary": 64000,
        "role": "support",
        "secret": "PLACEHOLDER-FLAG-bob-1d4e",
    },
    {
        "username": "carol",
        "password": "carolSecure!!",
        "email": "carol@injectarena.local",
        "salary": 120000,
        "role": "manager",
        "secret": "PLACEHOLDER-FLAG-carol-9a0f",
    },
]

# In-memory feedback store for N5 (CSV / formula injection).
FEEDBACK = []  # list of {"name": str, "comment": str}


# ---------------------------------------------------------------------------
# N1 - NoSQL injection (simulated MongoDB find)
# ---------------------------------------------------------------------------
MONGO_OPERATORS = {"$ne", "$gt", "$gte", "$lt", "$lte", "$regex", "$in",
                   "$nin", "$exists", "$eq", "$not", "$regex"}


def _mongo_match_field(stored_value, condition):
    """Simulate Mongo matching of a single field against `condition`.

    If `condition` is a plain string/number -> exact equality (the safe path).
    If `condition` is a dict of Mongo operators -> evaluate the operator. This
    is what makes the auth bypass possible: e.g. {"$ne": null} matches any
    non-null stored value, {"$gt": ""} matches any non-empty string, etc.
    """
    if isinstance(condition, dict):
        for op, operand in condition.items():
            if op == "$ne":
                if stored_value == operand:
                    return False
            elif op == "$eq":
                if stored_value != operand:
                    return False
            elif op == "$gt":
                try:
                    if not (stored_value > operand):
                        return False
                except TypeError:
                    return False
            elif op == "$gte":
                try:
                    if not (stored_value >= operand):
                        return False
                except TypeError:
                    return False
            elif op == "$lt":
                try:
                    if not (stored_value < operand):
                        return False
                except TypeError:
                    return False
            elif op == "$lte":
                try:
                    if not (stored_value <= operand):
                        return False
                except TypeError:
                    return False
            elif op == "$in":
                if not isinstance(operand, list) or stored_value not in operand:
                    return False
            elif op == "$nin":
                if not isinstance(operand, list) or stored_value in operand:
                    return False
            elif op == "$exists":
                exists = stored_value is not None
                if bool(operand) != exists:
                    return False
            elif op == "$regex":
                try:
                    if stored_value is None or re.search(str(operand), str(stored_value)) is None:
                        return False
                except re.error:
                    return False
            else:
                # Unknown operator: treat as non-matching to be conservative.
                return False
        return True
    # Plain value -> exact equality (the intended, safe comparison).
    return stored_value == condition


def mongo_find_one(query):
    """Return the first user matching ALL fields in `query`, or None."""
    for user in USERS:
        ok = True
        for field, condition in query.items():
            if field not in ("username", "password"):
                ok = False
                break
            if not _mongo_match_field(user.get(field), condition):
                ok = False
                break
        if ok:
            return user
    return None


# ---------------------------------------------------------------------------
# N2 - LDAP injection (string-concat filter + tiny interpreter)
# ---------------------------------------------------------------------------
def build_ldap_filter(user_value):
    """Vulnerable: builds the filter by raw concatenation (no escaping)."""
    return "(&(objectClass=person)(uid=" + user_value + "))"


def _ldap_value_match(stored, pattern):
    """LDAP substring/equality match. '*' is a wildcard (any value)."""
    if pattern == "*":
        return stored is not None
    if "*" in pattern:
        # LDAP substring filter (a*b*c): split on '*' and require the literal
        # parts to appear in order -> turn it into an anchored regex.
        parts = pattern.split("*")
        rx = "^" + ".*".join(re.escape(p) for p in parts) + "$"
        return stored is not None and re.match(rx, str(stored)) is not None
    return str(stored) == pattern


def _ldap_eval_node(node, user):
    """Evaluate a parsed LDAP filter node against a single user dict."""
    op = node[0]
    if op == "&":
        return all(_ldap_eval_node(c, user) for c in node[1])
    if op == "|":
        return any(_ldap_eval_node(c, user) for c in node[1])
    if op == "!":
        return not _ldap_eval_node(node[1], user)
    if op == "=":
        attr, pattern = node[1], node[2]
        if attr == "objectClass":
            # Every seeded entry IS a person.
            return pattern in ("person", "*")
        if attr == "uid":
            return _ldap_value_match(user.get("username"), pattern)
        # Unknown attribute -> map onto username/email best-effort.
        return _ldap_value_match(user.get(attr), pattern)
    return False


def _ldap_parse(s, i=0):
    """Tiny recursive-descent parser for RFC-4515-ish filter strings.

    Returns (node, next_index). Tolerant of the broken/unbalanced filters that
    an injection produces - if parsing runs off the rails it degrades to a
    match-all so the injection visibly 'opens the filter up'.
    """
    # Expect '(' at s[i]
    if i >= len(s) or s[i] != "(":
        # Malformed: treat remaining as a bare uid=* (match-all).
        return ("=", "uid", "*"), len(s)
    i += 1
    if i < len(s) and s[i] in "&|!":
        op = s[i]
        i += 1
        children = []
        while i < len(s) and s[i] == "(":
            child, i = _ldap_parse(s, i)
            children.append(child)
        # consume closing ')'
        if i < len(s) and s[i] == ")":
            i += 1
        if op == "!":
            inner = children[0] if children else ("=", "uid", "*")
            return ("!", inner), i
        return (op, children), i
    # Simple comparison attr=value up to next ')'
    j = s.find(")", i)
    if j == -1:
        j = len(s)
    expr = s[i:j]
    if "=" in expr:
        attr, _, pattern = expr.partition("=")
        node = ("=", attr.strip(), pattern)
    else:
        node = ("=", "uid", "*")
    i = j
    if i < len(s) and s[i] == ")":
        i += 1
    return node, i


def ldap_search(filter_str):
    """Evaluate `filter_str` against the seeded users; return matching entries.

    Robust against unbalanced/injected filters. If the top-level parse does not
    consume the whole (injected) string, that means extra ')(' or '|' branches
    were appended - we OR-in a match-all so the classic
    `*)(uid=*))(|(uid=*` payload returns everyone.
    """
    try:
        node, consumed = _ldap_parse(filter_str, 0)
        matched = [u for u in USERS if _ldap_eval_node(node, u)]
        # Detect appended/injected branches: leftover '(' after the parsed
        # top-level node, or an explicit lone '*' uid wildcard.
        leftover = filter_str[consumed:]
        if "(" in leftover or "(uid=*)" in filter_str or "(|(" in filter_str:
            matched = list(USERS)
        return matched
    except Exception:
        # Never crash on a hostile filter - degrade to match-all (filter broke
        # open, which is itself the injection signal).
        return list(USERS)


# ---------------------------------------------------------------------------
# N3 - XPath injection (users as an XML doc + concat query)
# ---------------------------------------------------------------------------
def _build_employee_xml():
    root = ET.Element("employees")
    for u in USERS:
        emp = ET.SubElement(root, "employee")
        ET.SubElement(emp, "name").text = u["username"].capitalize()
        ET.SubElement(emp, "username").text = u["username"]
        ET.SubElement(emp, "email").text = u["email"]
        ET.SubElement(emp, "salary").text = str(u["salary"])
        ET.SubElement(emp, "role").text = u["role"]
        ET.SubElement(emp, "secret").text = u["secret"]
    return root


EMPLOYEE_XML = _build_employee_xml()


def build_xpath(name_value):
    """Vulnerable: builds XPath by raw concatenation (no quoting/escaping)."""
    return "//employee[name='" + name_value + "']"


# Patterns that indicate a broken-out-of-quote XPath boolean injection.
_XPATH_TAUTOLOGY = re.compile(
    r"'\s*or\s*'|or\s+'1'\s*=\s*'1|or\s+1\s*=\s*1|'\s*or\s*1|\)\s*or\s*\(",
    re.IGNORECASE,
)


def xpath_search(name_value):
    """Simulate evaluating the concatenated XPath against EMPLOYEE_XML.

    Faithful behavior:
      * a benign name like 'Alice' selects the single matching employee;
      * a tautology injection (x' or '1'='1) breaks out of the string literal,
        so the predicate is always-true -> ALL employees are returned.
    """
    employees = EMPLOYEE_XML.findall("employee")
    if _XPATH_TAUTOLOGY.search(name_value):
        return list(employees)  # predicate forced true -> dump everything
    # Benign path: exact match on <name> (the value the literal was meant to be)
    matched = [e for e in employees if (e.findtext("name") or "") == name_value]
    return matched


def _employee_to_dict(emp):
    return {child.tag: child.text for child in list(emp)}


# ---------------------------------------------------------------------------
# N4 - SSI injection (server-side includes processed in the template)
# ---------------------------------------------------------------------------
# exec cmd allow-list: only these read-only commands actually run.
SSI_EXEC_ALLOW = {"whoami", "hostname", "id", "echo", "ver"}

SSI_FAKE_VARS = {
    "DOCUMENT_NAME": "greet.shtml",
    "DOCUMENT_URI": "/greet",
    "DATE_LOCAL": "Tue, 24 Jun 2026 00:00:00 GMT",
    "SERVER_NAME": "injectarena.local",
    "REMOTE_ADDR": "127.0.0.1",
}

_SSI_DIRECTIVE = re.compile(r"<!--#\s*(\w+)\s+(.*?)-->", re.IGNORECASE | re.DOTALL)
_SSI_ATTR = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def _run_allowed_cmd(cmdline):
    """Run only allow-listed read-only commands; reflect their output."""
    parts = cmdline.strip().split()
    if not parts:
        return "[ssi] empty exec cmd"
    program = parts[0].lower()
    if program not in SSI_EXEC_ALLOW:
        return "[ssi] directive processed (cmd intercepted for lab safety): " + cmdline
    try:
        out = subprocess.run(
            parts, capture_output=True, text=True, timeout=5, shell=False
        )
        result = (out.stdout or "") + (out.stderr or "")
        return result.strip() or "[ssi] (no output)"
    except Exception as e:
        return "[ssi] exec error: " + str(e)


def _ssi_replace(match):
    directive = match.group(1).lower()
    rest = match.group(2)
    attrs = dict(_SSI_ATTR.findall(rest))
    if directive == "exec":
        cmd = attrs.get("cmd", "")
        return _run_allowed_cmd(cmd)
    if directive == "echo":
        var = attrs.get("var", "")
        return SSI_FAKE_VARS.get(var, "[ssi] echo var " + var + " = (unset)")
    if directive == "include":
        target = attrs.get("virtual") or attrs.get("file") or ""
        return "[ssi] include processed (intercepted for lab safety): " + target
    return "[ssi] directive '" + directive + "' processed"


def process_ssi(template):
    """Process SSI directives anywhere in the rendered template (the bug:
    attacker input was placed into the template BEFORE SSI processing)."""
    return _SSI_DIRECTIVE.sub(_ssi_replace, template)


# ---------------------------------------------------------------------------
# N5 - CSV / formula injection
# ---------------------------------------------------------------------------
def _csv_cell(value):
    """VULNERABLE: writes the cell with minimal CSV quoting but does NOT strip
    or neutralize dangerous formula prefixes (= + - @ TAB CR). So a value like
    '=1+1' or '=cmd|...' lands in the sheet as a live formula."""
    s = "" if value is None else str(value)
    if any(c in s for c in [",", '"', "\n"]):
        s = '"' + s.replace('"', '""') + '"'
    return s


def build_csv():
    lines = ["name,comment"]
    for row in FEEDBACK:
        lines.append(_csv_cell(row["name"]) + "," + _csv_cell(row["comment"]))
    return "\r\n".join(lines) + "\r\n"


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------
def e(s):
    return htmllib.escape("" if s is None else str(s))


INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>InjectArena</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;line-height:1.5}
code{background:#f3f3f3;padding:.1rem .3rem;border-radius:3px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}
.warn{background:#fff3cd;border:1px solid #ffe69c;padding:.6rem .8rem;border-radius:6px}
</style></head><body>
<h1>InjectArena</h1>
<p class="warn"><b>INTENTIONALLY VULNERABLE.</b> Local security training only
(127.0.0.1:18809). Every secret/salary is a placeholder.</p>
<p>An injection range. Each endpoint simulates a different backend query
language and is deliberately injectable.</p>
<table>
<tr><th>ID</th><th>Backend</th><th>Endpoint</th><th>Try</th></tr>
<tr><td>N1</td><td>NoSQL (MongoDB)</td><td><code>POST /login</code> (JSON body)</td>
<td><code>{"username":"admin","password":{"$ne":null}}</code></td></tr>
<tr><td>N2</td><td>LDAP</td><td><a href="/directory?user=alice"><code>GET /directory?user=</code></a></td>
<td><code>user=*)(uid=*))(|(uid=*</code></td></tr>
<tr><td>N3</td><td>XPath</td><td><a href="/employee?name=Alice"><code>GET /employee?name=</code></a></td>
<td><code>name=x' or '1'='1</code></td></tr>
<tr><td>N4</td><td>SSI</td><td><a href="/greet?name=Hacker"><code>GET /greet?name=</code></a></td>
<td><code>name=&lt;!--#exec cmd="whoami"--&gt;</code></td></tr>
<tr><td>N5</td><td>CSV/formula</td><td><code>POST /feedback</code> + <a href="/export"><code>GET /export</code></a></td>
<td><code>name==1+1</code></td></tr>
</table>
<h3>N5 quick form</h3>
<form method="POST" action="/feedback">
  name: <input name="name" value="=1+1"><br>
  comment: <input name="comment" value="hello"><br>
  <button type="submit">Submit feedback</button>
</form>
<p>POST /login expects a JSON body (<code>Content-Type: application/json</code>),
not a form.</p>
</body></html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "InjectArena/1.0"

    def log_message(self, fmt, *args):
        return  # quiet

    def _send(self, body, code=200, content_type="text/html; charset=utf-8",
              extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, obj, code=200):
        self._send(json.dumps(obj, indent=2), code=code,
                   content_type="application/json; charset=utf-8")

    # ----- routing -----
    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if path == "/" or path == "/index.html":
                return self._send(INDEX_HTML)
            if path == "/directory":
                return self._h_directory(qs)
            if path == "/employee":
                return self._h_employee(qs)
            if path == "/greet":
                return self._h_greet(qs)
            if path == "/export":
                return self._h_export()
            return self._send_json({"error": "not found", "path": path}, code=404)
        except Exception as ex:  # never crash
            return self._send_json({"error": "server error", "detail": str(ex)},
                                   code=500)

    def do_HEAD(self):
        return self.do_GET()

    def do_POST(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            if path == "/login":
                return self._h_login(raw)
            if path == "/feedback":
                return self._h_feedback(raw)
            return self._send_json({"error": "not found", "path": path}, code=404)
        except Exception as ex:  # never crash
            return self._send_json({"error": "server error", "detail": str(ex)},
                                   code=500)

    # ----- N1 /login (NoSQL) -----
    def _h_login(self, raw):
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return self._send_json(
                {"error": "invalid JSON body",
                 "hint": 'POST JSON like {"username":"admin","password":"..."}'},
                code=400)
        if not isinstance(body, dict):
            return self._send_json({"error": "body must be a JSON object"}, code=400)
        query = {}
        if "username" in body:
            query["username"] = body["username"]
        if "password" in body:
            query["password"] = body["password"]
        if not query:
            return self._send_json(
                {"error": "username and/or password required"}, code=400)
        # Flag whether operators were used (for the lab to make the bug visible).
        used_ops = any(
            isinstance(v, dict) and any(k in MONGO_OPERATORS for k in v)
            for v in query.values()
        )
        user = mongo_find_one(query)
        if user:
            return self._send_json({
                "authenticated": True,
                "user": user["username"],
                "role": user["role"],
                "simulated_query": query,
                "operator_injection": used_ops,
                "note": ("operator object matched without knowing the password"
                         if used_ops else "exact credential match"),
            })
        return self._send_json({
            "authenticated": False,
            "simulated_query": query,
            "note": "no user matched the simulated Mongo find()",
        }, code=401)

    # ----- N2 /directory (LDAP) -----
    def _h_directory(self, qs):
        user_value = qs.get("user", [""])[0]
        filt = build_ldap_filter(user_value)
        matched = ldap_search(filt)
        entries = [{
            "uid": u["username"],
            "objectClass": "person",
            "mail": u["email"],
            "role": u["role"],
        } for u in matched]
        return self._send_json({
            "ldap_filter": filt,
            "count": len(entries),
            "entries": entries,
            "note": ("filter broke open - returned all entries"
                     if len(entries) == len(USERS) and len(USERS) > 1
                     else "filter matched normally"),
        })

    # ----- N3 /employee (XPath) -----
    def _h_employee(self, qs):
        name_value = qs.get("name", [""])[0]
        query = build_xpath(name_value)
        matched = xpath_search(name_value)
        employees = [_employee_to_dict(e) for e in matched]
        return self._send_json({
            "xpath_query": query,
            "count": len(employees),
            "employees": employees,
            "note": ("tautology broke the predicate - all employees dumped "
                     "(incl. salary/secret)"
                     if len(employees) == len(USERS) and len(USERS) > 1
                     else "matched normally"),
        })

    # ----- N4 /greet (SSI) -----
    def _h_greet(self, qs):
        name_value = qs.get("name", [""])[0]
        # The bug: attacker input is placed into the template, THEN SSI is run.
        template = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>Greeting</title></head><body>"
            "<h1>Hello, " + name_value + "!</h1>"
            "<p>Welcome to InjectArena. Page: "
            "<!--#echo var=\"DOCUMENT_NAME\"--></p>"
            "</body></html>"
        )
        rendered = process_ssi(template)
        return self._send(rendered)

    # ----- N5 /feedback + /export (CSV) -----
    def _h_feedback(self, raw):
        ctype = (self.headers.get("Content-Type") or "").lower()
        name = comment = ""
        text = raw.decode("utf-8", "replace")
        if "application/json" in ctype:
            try:
                body = json.loads(text or "{}")
                name = str(body.get("name", ""))
                comment = str(body.get("comment", ""))
            except Exception:
                pass
        else:
            form = urllib.parse.parse_qs(text, keep_blank_values=True)
            name = form.get("name", [""])[0]
            comment = form.get("comment", [""])[0]
        FEEDBACK.append({"name": name, "comment": comment})
        return self._send_json({
            "stored": True,
            "name": name,
            "comment": comment,
            "total_rows": len(FEEDBACK),
            "note": "values stored WITHOUT formula-prefix sanitization; see /export",
        })

    def _h_export(self):
        csv_body = build_csv()
        return self._send(
            csv_body,
            content_type="text/csv; charset=utf-8",
            extra_headers={
                "Content-Disposition": 'attachment; filename="feedback.csv"'
            },
        )


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("[InjectArena] INTENTIONALLY VULNERABLE injection range.")
    print("[InjectArena] listening on http://%s:%d/  (Ctrl-C to stop)" % (HOST, PORT))
    print("[InjectArena] vulns: N1 NoSQL  N2 LDAP  N3 XPath  N4 SSI  N5 CSV/formula")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[InjectArena] shutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
