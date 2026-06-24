# GraphVault — Deliberately-Vulnerable GraphQL-Style API Lab

> ⚠️ **INTENTIONALLY VULNERABLE. Localhost only.**
> This server plants real, exploitable vulnerabilities on purpose for security
> training. **Never** expose it to a network. All secrets, API keys, SSNs and
> passwords are **placeholder / non-real** values.

GraphVault is a single-file, stdlib-only (`http.server` + `sqlite3` + `json` +
`re`) lab that *simulates* a GraphQL API. It is **not** a real GraphQL engine —
it recognizes a handful of specific query/mutation shapes via regex/string
parsing and answers with GraphQL-style JSON (`{"data": {...}}` or
`{"errors":[{"message":"..."}]}`). The goal is to practice GraphQL-specific
attack techniques (introspection abuse, BOLA/BFLA, excessive data exposure,
batching brute-force, injection through args, DoS via nesting, info leak via
verbose errors).

## How to run

```bash
python app.py
# -> GraphVault listening on http://127.0.0.1:18807  (POST /graphql)
```

- `GET  /`        — tiny JSON index advertising the `/graphql` endpoint.
- `POST /graphql` — JSON body `{"query": "...", "variables": {...}}`.

Example:

```bash
curl -s http://127.0.0.1:18807/
curl -s -X POST http://127.0.0.1:18807/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ user(id: 2) { username email ssn } }"}'
```

## Seeded users

In-memory SQLite, seeded at startup. Passwords are stored as **MD5** hashes
(weak on purpose). All values below are **fake / placeholder**.

| id | username | password (plain) | role  | email                  | ssn         | apiKey (placeholder)            |
|----|----------|------------------|-------|------------------------|-------------|---------------------------------|
| 1  | alice    | `password1`      | user  | alice@graphvault.lab   | 111-11-1111 | `gv_live_AAAA1111placeholder`   |
| 2  | bob      | `hunter2`        | user  | bob@graphvault.lab     | 222-22-2222 | `gv_live_BBBB2222placeholder`   |
| 3  | carol    | `letmein`        | user  | carol@graphvault.lab   | 333-33-3333 | `gv_live_CCCC3333placeholder`   |
| 4  | admin    | `s3cr3tAdmin`    | admin | admin@graphvault.lab   | 444-44-4444 | `gv_live_DDDD4444placeholder`   |

`friends` relation (so nested queries resolve):
`alice↔{bob,carol}`, `bob↔{alice,admin}`, `carol↔{alice,admin}`, `admin↔{bob,carol}`.

User type fields the client may request:
`id, username, passwordHash, email, ssn, apiKey, role, friends`.

## Planted vulnerabilities (G1–G8)

All vulns live on `POST /graphql`.

| ID | Name | Route | Example query / mutation | Impact |
|----|------|-------|--------------------------|--------|
| **G1** | Introspection enabled | `/graphql` | `{"query":"{ __schema { types { name fields { name } } queryType { name } mutationType { name } } }"}` | Full schema (incl. sensitive `passwordHash`/`ssn`/`apiKey` fields and dangerous `makeAdmin`/`login` mutations) is disclosed. Production should disable introspection. |
| **G2** | BOLA (Broken Object Level Authorization) | `/graphql` | `{"query":"{ user(id: 2) { id username email ssn } }"}` | Any user's full record is returned by id with **no** ownership/auth check. |
| **G3** | Excessive data exposure | `/graphql` | `{"query":"{ users { username passwordHash ssn apiKey } }"}` | The User type lets clients request `passwordHash`, `ssn`, `apiKey` — credentials/PII/secrets leak directly. |
| **G4** | BFLA (Broken Function Level Authorization) | `/graphql` | `{"query":"mutation { makeAdmin(username: \"bob\") { username role } }"}` | Privilege escalation: any caller can promote any user to `admin`, no caller-role check. |
| **G5** | No rate limiting + query batching | `/graphql` | `{"query":"mutation { a: login(username: \"admin\", password: \"admin\") b: login(username: \"admin\", password: \"s3cr3tAdmin\") c: login(username: \"admin\", password: \"password\") }"}` | All aliased `login` calls execute in one request → password brute-force, no throttle/lockout. |
| **G6** | No depth/complexity limit (DoS) | `/graphql` | `{"query":"{ user(id:1){ friends{ friends{ friends{ friends{ friends{ username }}}}}} }"}` | Arbitrarily deep nested queries are accepted and processed — no depth/complexity rejection (resource exhaustion / DoS). Recursion is internally capped at ~25 only to avoid truly hanging; the server never returns a depth-limit error. |
| **G7** | SQL injection via GraphQL arg | `/graphql` | `{"query":"{ search(filter: \"x' OR '1'='1\") { username } }"}` and `{"query":"{ search(filter: \"x' UNION SELECT apiKey FROM users--\") { username } }"}` | The `filter` arg is string-concatenated into `SELECT username FROM users WHERE username LIKE '%<filter>'`. Boolean injection (`x' OR '1'='1`) dumps all users; UNION (`x' UNION SELECT apiKey FROM users--`) leaks any column (e.g. `apiKey`); SQL errors are leaked verbatim. |
| **G8** | Verbose errors + field suggestions | `/graphql` | `{"query":"{ user(id:1){ usernam } }"}` → `Cannot query field "usernam" on type "User". Did you mean "username"?` | Field typos return GraphQL "Did you mean" suggestions and malformed input returns a verbose traceback in `errors` — schema/internal details leak even with introspection off. |

## Notes / methodology hints

- G1 → enumerate the schema, then drive G2/G3/G4 against the fields/mutations it reveals.
- G3 + G2 combine: `{ users { username passwordHash } }` dumps every MD5 hash → crack offline (`password1`, `hunter2`, `letmein`, `s3cr3tAdmin`).
- G5 lets you confirm cracked/guessed passwords in bulk via batched aliases.
- G4 escalates any account to `admin`.
- G7 is the cleanest exfil path for `apiKey`/`ssn` via `UNION`.
- G6 and G8 are info/availability issues that broaden the attack surface.

## Teardown

Stop with `Ctrl+C`. The server binds `127.0.0.1:18807` with
`allow_reuse_address=True`, so it can be restarted immediately.
