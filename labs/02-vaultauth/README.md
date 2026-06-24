# Lab 02 — VaultAuth

> ⚠️ **INTENTIONALLY VULNERABLE — LOCALHOST TRAINING ONLY.**
> Real, exploitable authentication flaws on purpose. Binds to `127.0.0.1`.
> Never expose it; never reuse the seed credentials.

## What it is

**VaultAuth** is a fake JWT-based **identity / authentication API** for
practicing auth, JWT, and session-management testing. Single self-contained
Python file, **stdlib only** (`http.server` + `sqlite3` + `hmac`/`hashlib`/
`base64`). JWTs are built and verified **by hand** (no PyJWT) so every flaw is
explicit in the source. In-memory SQLite, seeded fresh at startup — restart to
reset state.

## How to run

```bash
python app.py        # -> http://127.0.0.1:18802
```

No args, no deps. Requires Python 3.8+. The root `/` returns the endpoint list.

### Flow

`POST /register` → `POST /login` (returns the OTP hint 😬) → `POST /verify-otp`
(returns a **JWT**) → `GET /me` / `GET /admin` with `Authorization: Bearer <jwt>`.
Account recovery: `POST /reset-request` → `POST /reset`.

## Seeded users

| username | password          | role  | otp    |
|----------|-------------------|-------|--------|
| admin    | `S3cr3tAdminP@ss` | admin | 000000 |
| alice    | `alice123`        | user  | 111111 |
| bob      | `bobpassword`     | user  | 222222 |

(The point is to forge access **without** these.)

## Planted vulnerabilities

Answer key: [`gabarito.json`](gabarito.json). 12 vulns, 1 point each.

| ID  | Class           | Sev      | Route            | How to exploit |
|-----|-----------------|----------|------------------|----------------|
| J1  | jwt             | critical | `/me`,`/admin`   | Forge a token with header `{"alg":"none"}` and empty signature → server skips verification. Set `role:admin` → full admin. |
| J2  | jwt             | critical | `/me`            | HS256 secret is `secret` — crack offline (`hashcat -m 16500`) and re-sign any token. |
| J3  | jwt             | high     | `/me`            | `exp` is never validated → captured tokens replay forever. |
| A1  | user-enum       | medium   | `/login`         | `no such user` (404) vs `incorrect password` (401); `/register` 409 on existing user → enumerate accounts. |
| A2  | no-rate-limit   | medium   | `/login`         | No lockout/throttle on `/login` or `/verify-otp` → brute-force passwords and the 6-digit OTP. |
| A3  | auth            | high     | `/reset-request` | Reset token is a **sequential int** *and* returned in the response body → reset anyone's password. |
| A4  | 2fa-bypass      | high     | `/verify-otp`    | OTP echoed in the `/login` response (`otp_hint`); master code `000000` accepted; not rate-limited. |
| A5  | mass-assignment | high     | `/register`      | `POST /register {"role":"admin"}` → instant admin account. |
| A6  | weak-crypto     | high     | `/debug`,`/admin`| Passwords stored as **unsalted MD5**, leaked unauthenticated at `/debug`. |
| A7  | idor            | high     | `/api/user/<id>` | `GET /api/user/1..N` → any user's record, no auth. |
| S2  | session         | medium   | `/logout`        | Stateless JWT + no deny-list → token still valid after `/logout`. |
| S3  | session         | medium   | `/login`         | `remember` cookie = `base64(username)` → forge to impersonate anyone. |

## Suggested attack walk-through

1. **Recon:** `GET /` for endpoints, `GET /debug` → MD5 hashes (crack `admin`).
2. **Forge admin (no creds):** craft an `alg:none` token with `role:admin` →
   `GET /admin` dumps all hashes (J1). Or crack the `secret` HMAC and re-sign (J2).
3. **Account takeover:** `POST /reset-request {admin}` → token in body →
   `POST /reset` (A3). Or `register role=admin` (A5).
4. **2FA is theatre:** OTP is leaked and `000000` always works (A4).
5. **Persistence:** token survives logout (S2); forge `remember` cookie (S3).

## Notes / design

- JWT verifier intentionally (a) accepts `alg:none`, (b) uses the weak secret
  `secret`, (c) never checks `exp`.
- In-memory DB resets on restart — re-seed after takeover tests.
- This lab is auth-focused on purpose; classic web-injection bugs live in
  [Lab 01 — VulnShop](../01-vulnshop/).
