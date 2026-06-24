#!/usr/bin/env python3
"""
GraphVault - Deliberately-vulnerable GraphQL-style API lab.

INTENTIONALLY VULNERABLE. For local security training only.
Bind: 127.0.0.1:18807. Stdlib only (http.server + sqlite3 + json + re).

This is NOT a real GraphQL engine. It is a simplified parser that recognizes
specific query/mutation shapes via regex/string parsing and returns
GraphQL-style JSON. Planted vulns G1..G8 (see README.md).
"""
import hashlib
import http.server
import json
import re
import socketserver
import sqlite3
import threading
import traceback

HOST = "127.0.0.1"
PORT = 18807

# ---------------------------------------------------------------------------
# Schema metadata (used for introspection G1 + field suggestions G8)
# ---------------------------------------------------------------------------
USER_FIELDS = [
    "id", "username", "passwordHash", "email", "ssn", "apiKey", "role", "friends",
]
QUERY_FIELDS = ["user", "users", "search"]
MUTATION_FIELDS = ["makeAdmin", "login"]

# Map the resolver-exposed field name -> sqlite column name.
FIELD_TO_COLUMN = {
    "id": "id",
    "username": "username",
    "passwordHash": "password",   # G3: exposes the md5 hash
    "email": "email",
    "ssn": "ssn",
    "apiKey": "apiKey",
    "role": "role",
}


# ---------------------------------------------------------------------------
# In-memory database seed
# ---------------------------------------------------------------------------
_DB_LOCK = threading.Lock()


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def build_db():
    """Create a shared in-memory sqlite DB and seed ~4 users + friends."""
    # check_same_thread=False because the threaded server hits it from many
    # threads; a module-level lock serializes access.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,   -- md5 hash
            email    TEXT,
            ssn      TEXT,
            apiKey   TEXT,
            role     TEXT
        )
        """
    )
    cur.execute("CREATE TABLE friends (user_id INTEGER, friend_id INTEGER)")

    # Placeholder / non-real secrets.
    users = [
        # id, username, password(plain), email, ssn, apiKey, role
        (1, "alice",   "password1",   "alice@graphvault.lab",   "111-11-1111", "gv_live_AAAA1111placeholder", "user"),
        (2, "bob",     "hunter2",     "bob@graphvault.lab",     "222-22-2222", "gv_live_BBBB2222placeholder", "user"),
        (3, "carol",   "letmein",     "carol@graphvault.lab",   "333-33-3333", "gv_live_CCCC3333placeholder", "user"),
        (4, "admin",   "s3cr3tAdmin", "admin@graphvault.lab",   "444-44-4444", "gv_live_DDDD4444placeholder", "admin"),
    ]
    for uid, uname, pw, email, ssn, apikey, role in users:
        cur.execute(
            "INSERT INTO users (id, username, password, email, ssn, apiKey, role) "
            "VALUES (?,?,?,?,?,?,?)",
            (uid, uname, md5(pw), email, ssn, apikey, role),
        )

    # Each user has a couple of friend ids so nested queries resolve (G6).
    friend_pairs = [
        (1, 2), (1, 3),
        (2, 1), (2, 4),
        (3, 1), (3, 4),
        (4, 2), (4, 3),
    ]
    cur.executemany("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)", friend_pairs)
    conn.commit()
    return conn


DB = build_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def gql_error(message):
    return {"errors": [{"message": message}]}


def gql_data(data):
    return {"data": data}


def row_to_user(row, requested_fields):
    """Return dict of only the requested scalar fields for a user row."""
    # row is a dict keyed by sqlite column name (from a Row factory).
    out = {}
    for f in requested_fields:
        if f == "friends":
            continue  # handled by caller (nested)
        col = FIELD_TO_COLUMN.get(f)
        if col is not None:
            out[f] = row[col]
    return out


def parse_selection_set(block):
    """
    Given the inside of a {...} selection set, return:
      - list of top-level scalar field names (in order)
      - dict mapping nested-field-name -> its inner selection-set text
    Very loose parser: scans tokens, when it sees `name {` it captures the
    balanced inner block as a nested selection.
    """
    scalars = []
    nested = {}
    i = 0
    n = len(block)
    while i < n:
        ch = block[i]
        if ch.isspace() or ch in ",":
            i += 1
            continue
        # read an identifier
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", block[i:])
        if not m:
            i += 1
            continue
        name = m.group(0)
        j = i + len(name)
        # skip whitespace
        k = j
        while k < n and block[k].isspace():
            k += 1
        # is there an argument list? skip (...)
        if k < n and block[k] == "(":
            depth = 0
            while k < n:
                if block[k] == "(":
                    depth += 1
                elif block[k] == ")":
                    depth -= 1
                    if depth == 0:
                        k += 1
                        break
                k += 1
            while k < n and block[k].isspace():
                k += 1
        # nested selection?
        if k < n and block[k] == "{":
            depth = 0
            start = k
            while k < n:
                if block[k] == "{":
                    depth += 1
                elif block[k] == "}":
                    depth -= 1
                    if depth == 0:
                        k += 1
                        break
                k += 1
            inner = block[start + 1:k - 1]
            nested[name] = inner
            i = k
        else:
            scalars.append(name)
            i = k
    return scalars, nested


def extract_top_block(query, keyword_index):
    """Return the balanced {...} block starting at/after keyword_index."""
    start = query.find("{", keyword_index)
    if start == -1:
        return None
    depth = 0
    i = start
    n = len(query)
    while i < n:
        if query[i] == "{":
            depth += 1
        elif query[i] == "}":
            depth -= 1
            if depth == 0:
                return query[start + 1:i]
        i += 1
    return query[start + 1:]  # unbalanced; return rest


def suggest_field(bad, candidates):
    """Cheap edit-distance based suggestion for G8."""
    def dist(a, b):
        # Levenshtein
        if a == b:
            return 0
        la, lb = len(a), len(b)
        prev = list(range(lb + 1))
        for i in range(1, la + 1):
            cur = [i] + [0] * lb
            for j in range(1, lb + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            prev = cur
        return prev[lb]

    best = None
    best_d = 99
    for c in candidates:
        d = dist(bad.lower(), c.lower())
        if d < best_d:
            best_d = d
            best = c
    # only suggest if reasonably close
    if best is not None and best_d <= max(2, len(bad) // 2):
        return best
    return None


# ---------------------------------------------------------------------------
# DB query helpers
# ---------------------------------------------------------------------------
def fetch_user_row(uid):
    with _DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
        cols = [d[0] for d in cur.description]
        r = cur.fetchone()
    if r is None:
        return None
    return dict(zip(cols, r))


def fetch_all_user_rows():
    with _DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM users ORDER BY id")
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    return [dict(zip(cols, r)) for r in rows]


def fetch_friend_ids(uid):
    with _DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT friend_id FROM friends WHERE user_id = ?", (uid,))
        return [r[0] for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# G8: validate requested fields, raising for unknown ones with a suggestion
# ---------------------------------------------------------------------------
class FieldError(Exception):
    pass


def validate_user_fields(scalars, nested):
    for f in scalars:
        if f not in USER_FIELDS:
            sug = suggest_field(f, USER_FIELDS)
            if sug:
                raise FieldError(
                    'Cannot query field "%s" on type "User". Did you mean "%s"?'
                    % (f, sug)
                )
            raise FieldError('Cannot query field "%s" on type "User".' % f)
    for f in nested:
        if f not in USER_FIELDS:
            sug = suggest_field(f, USER_FIELDS)
            if sug:
                raise FieldError(
                    'Cannot query field "%s" on type "User". Did you mean "%s"?'
                    % (f, sug)
                )
            raise FieldError('Cannot query field "%s" on type "User".' % f)


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------
RECURSION_CAP = 25  # G6: cap actual recursion so it never truly hangs


def resolve_user_object(uid, scalars, nested, depth=0):
    """Resolve a single user's requested fields, recursing into friends (G6)."""
    row = fetch_user_row(uid)
    if row is None:
        return None
    validate_user_fields(scalars, nested)
    out = row_to_user(row, scalars)
    if "friends" in nested and depth < RECURSION_CAP:
        f_scalars, f_nested = parse_selection_set(nested["friends"])
        friends_out = []
        for fid in fetch_friend_ids(uid):
            fo = resolve_user_object(fid, f_scalars, f_nested, depth + 1)
            if fo is not None:
                friends_out.append(fo)
        out["friends"] = friends_out
    elif "friends" in nested:
        # at the cap we still return an (empty) list, never a depth error (G6)
        out["friends"] = []
    return out


def resolve_introspection():
    """G1: full introspection result incl. sensitive fields + mutations."""
    def field(name, type_name):
        return {
            "name": name,
            "type": {"kind": "SCALAR", "name": type_name, "ofType": None},
        }

    user_type = {
        "kind": "OBJECT",
        "name": "User",
        "description": "An application user (sensitive fields exposed!).",
        "fields": [
            field("id", "ID"),
            field("username", "String"),
            field("passwordHash", "String"),   # sensitive
            field("email", "String"),
            field("ssn", "String"),             # sensitive
            field("apiKey", "String"),          # sensitive
            field("role", "String"),
            {
                "name": "friends",
                "type": {"kind": "LIST", "name": None,
                         "ofType": {"kind": "OBJECT", "name": "User"}},
            },
        ],
    }
    query_type = {
        "kind": "OBJECT",
        "name": "Query",
        "fields": [
            {"name": "user",
             "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "Int"}}],
             "type": {"kind": "OBJECT", "name": "User"}},
            {"name": "users",
             "type": {"kind": "LIST", "name": None,
                      "ofType": {"kind": "OBJECT", "name": "User"}}},
            {"name": "search",
             "args": [{"name": "filter", "type": {"kind": "SCALAR", "name": "String"}}],
             "type": {"kind": "LIST", "name": None,
                      "ofType": {"kind": "OBJECT", "name": "User"}}},
        ],
    }
    mutation_type = {
        "kind": "OBJECT",
        "name": "Mutation",
        "fields": [
            {"name": "makeAdmin",   # dangerous
             "args": [{"name": "username", "type": {"kind": "SCALAR", "name": "String"}}],
             "type": {"kind": "OBJECT", "name": "User"}},
            {"name": "login",       # dangerous
             "args": [
                 {"name": "username", "type": {"kind": "SCALAR", "name": "String"}},
                 {"name": "password", "type": {"kind": "SCALAR", "name": "String"}},
             ],
             "type": {"kind": "SCALAR", "name": "Boolean"}},
        ],
    }
    return {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [user_type, query_type, mutation_type],
        }
    }


def resolve_search(filter_value):
    """G7: SQL injection by string-concatenating the filter arg.

    The filter is concatenated straight into a LIKE clause. We use a leading
    wildcard and close the literal with a single quote, e.g.
        SELECT username FROM users WHERE username LIKE '%<filter>'
    so the canonical `x' OR '1'='1` payload lands in boolean context and
    returns every row (no trailing `%'` to strand the OR), while benign
    substring/suffix searches and `UNION SELECT ...` injection both work.
    """
    sql = ("SELECT username FROM users WHERE username LIKE '%" +
           filter_value + "'")
    with _DB_LOCK:
        cur = DB.cursor()
        try:
            cur.execute(sql)
            rows = cur.fetchall()
        except Exception as e:  # G7: leak the SQL error
            raise FieldError("SQL error: %s | query: %s" % (e, sql))
    # The first selected column is reported as `username` (UNION can leak others).
    return [{"username": r[0]} for r in rows]


# ---------------------------------------------------------------------------
# login parsing (G5: aliases / batching)
# ---------------------------------------------------------------------------
LOGIN_CALL_RE = re.compile(
    r"""
    (?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*)?   # optional alias:
    login\s*\(
        (?P<args>[^)]*)
    \)
    """,
    re.VERBOSE,
)

MAKEADMIN_RE = re.compile(
    r"""makeAdmin\s*\(\s*username\s*:\s*(?P<q>["'])(?P<username>.*?)(?P=q)\s*\)""",
    re.VERBOSE,
)


def parse_kwargs(argstr):
    """Parse `username: "x", password: "y"` style args."""
    args = {}
    for m in re.finditer(
        r"""(?P<k>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<q>["'])(?P<v>.*?)(?P=q)""",
        argstr,
    ):
        args[m.group("k")] = m.group("v")
    return args


def do_login(username, password):
    """G5: check credentials. No throttle, no lockout."""
    row = None
    with _DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    if row is None:
        return {"success": False, "reason": "no such user"}
    ok = (row[0] == md5(password))
    return {"success": ok, "reason": "ok" if ok else "bad password"}


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------
def execute_query(query, variables):
    query = query or ""

    # ---- G1: introspection -------------------------------------------------
    if "__schema" in query or "__type" in query:
        return gql_data(resolve_introspection())

    is_mutation = re.match(r"\s*mutation\b", query) is not None

    # ---- Mutations ---------------------------------------------------------
    if is_mutation:
        # G4: makeAdmin
        m = MAKEADMIN_RE.search(query)
        if m:
            uname = m.group("username")
            with _DB_LOCK:
                cur = DB.cursor()
                cur.execute("UPDATE users SET role = 'admin' WHERE username = ?", (uname,))
                DB.commit()
                cur.execute("SELECT username, role FROM users WHERE username = ?", (uname,))
                r = cur.fetchone()
            if r is None:
                return gql_error('User "%s" not found.' % uname)
            return gql_data({"makeAdmin": {"username": r[0], "role": r[1]}})

        # G5: one or more (possibly aliased) login(...) calls
        login_calls = list(LOGIN_CALL_RE.finditer(query))
        if login_calls:
            data = {}
            idx = 0
            for lm in login_calls:
                alias = lm.group("alias")
                kwargs = parse_kwargs(lm.group("args"))
                uname = kwargs.get("username", "")
                pw = kwargs.get("password", "")
                key = alias if alias else "login%d" % idx
                if not alias and len(login_calls) == 1:
                    key = "login"
                result = do_login(uname, pw)
                data[key] = result
                idx += 1
            return gql_data(data)

        return gql_error("Unknown mutation. Supported: makeAdmin, login.")

    # ---- Queries -----------------------------------------------------------
    try:
        # G2: user(id: N) { ... }
        um = re.search(r"\buser\s*\(\s*id\s*:\s*(?P<id>\d+)\s*\)", query)
        if um:
            uid = int(um.group("id"))
            block = extract_top_block(query, um.end())
            if block is None:
                raise FieldError('Field "user" must have a selection of subfields.')
            scalars, nested = parse_selection_set(block)
            obj = resolve_user_object(uid, scalars, nested)
            if obj is None:
                return gql_data({"user": None})
            return gql_data({"user": obj})

        # G7: search(filter: "...") { username }
        sm = re.search(
            r"""\bsearch\s*\(\s*filter\s*:\s*(?P<q>["'])(?P<filter>.*?)(?P=q)\s*\)""",
            query, re.DOTALL,
        )
        if sm:
            results = resolve_search(sm.group("filter"))
            # validate requested subfields exist (best-effort, G8)
            block = extract_top_block(query, sm.end())
            if block:
                scalars, nested = parse_selection_set(block)
                # only 'username' is meaningfully returned; still validate
                for f in scalars:
                    if f not in USER_FIELDS:
                        sug = suggest_field(f, USER_FIELDS)
                        if sug:
                            raise FieldError(
                                'Cannot query field "%s" on type "User". '
                                'Did you mean "%s"?' % (f, sug))
                        raise FieldError('Cannot query field "%s" on type "User".' % f)
            return gql_data({"search": results})

        # G3 + G2: users { ... }
        usm = re.search(r"\busers\b\s*\{", query)
        if usm:
            block = extract_top_block(query, usm.end() - 1)
            scalars, nested = parse_selection_set(block) if block else ([], {})
            rows = fetch_all_user_rows()
            out = []
            for row in rows:
                validate_user_fields(scalars, nested)
                obj = row_to_user(row, scalars)
                if "friends" in nested:
                    f_scalars, f_nested = parse_selection_set(nested["friends"])
                    friends_out = []
                    for fid in fetch_friend_ids(row["id"]):
                        fo = resolve_user_object(fid, f_scalars, f_nested, 1)
                        if fo is not None:
                            friends_out.append(fo)
                    obj["friends"] = friends_out
                out.append(obj)
            return gql_data({"users": out})

        # Nothing matched -> G8 verbose error (try to suggest a Query field)
        fm = re.search(r"\{\s*([A-Za-z_][A-Za-z0-9_]*)", query)
        if fm:
            bad = fm.group(1)
            sug = suggest_field(bad, QUERY_FIELDS)
            if sug:
                raise FieldError(
                    'Cannot query field "%s" on type "Query". Did you mean "%s"?'
                    % (bad, sug))
            raise FieldError('Cannot query field "%s" on type "Query".' % bad)
        raise FieldError("Syntax error: could not parse query.")

    except FieldError as fe:
        return gql_error(str(fe))
    except Exception:
        # G8: verbose traceback leaked in the errors message (no 500 crash)
        tb = traceback.format_exc()
        return gql_error("Internal resolver error:\n" + tb)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
INDEX = {
    "service": "GraphVault",
    "description": "Deliberately-vulnerable GraphQL-style API lab. "
                   "INTENTIONALLY VULNERABLE - localhost only.",
    "endpoints": {
        "/graphql": "POST a JSON body {\"query\": \"...\", \"variables\": {...}} "
                    "to execute GraphQL-style queries/mutations.",
    },
    "hint": "Introspection is enabled. Try {\"query\":\"{ __schema { types { name } } }\"}",
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # quiet

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        if self.path.split("?")[0] in ("/", "/index", "/index.json"):
            self._send_json(INDEX)
        elif self.path.split("?")[0] == "/graphql":
            # be friendly: explain how to use it
            self._send_json({
                "message": "Send a POST with JSON body {\"query\": \"...\"}.",
            })
        else:
            self._send_json(gql_error("Not found: %s" % self.path), code=404)

    def do_POST(self):
        if self.path.split("?")[0] != "/graphql":
            self._send_json(gql_error("Not found: %s" % self.path), code=404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw.decode() or "{}")
            except Exception as e:
                # G8: verbose parse error
                self._send_json(gql_error("Invalid JSON body: %s" % e))
                return
            query = payload.get("query", "")
            variables = payload.get("variables", {}) or {}
            result = execute_query(query, variables)
            self._send_json(result)
        except Exception:
            # never crash with a 500; surface the traceback (G8)
            tb = traceback.format_exc()
            self._send_json(gql_error("Server error:\n" + tb))


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("GraphVault listening on http://%s:%d  (POST /graphql) "
          "- INTENTIONALLY VULNERABLE, localhost only" % (HOST, PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
