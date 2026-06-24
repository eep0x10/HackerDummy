# TrustEdge

> **INTENTIONALLY VULNERABLE - localhost only.** TrustEdge is a deliberately
> broken training app. Every bug is exploitable by design. Bind is fixed to
> `127.0.0.1:18808`. Never expose it to a network, never run it on a machine
> you care about, and never reuse any of its code.

TrustEdge is a tiny "account portal" written as a **single stdlib-only Python
file** (`http.server`, no dependencies). Its entire theme is **trusting
attacker-controlled request headers and parameters**: CORS `Origin` reflection,
`Host` / `X-Forwarded-Host` header injection, CRLF / HTTP response splitting,
and an unkeyed-header web-cache-poisoning primitive.

The app fakes a logged-in user (`victim`) - it assumes a session cookie is
present and does **no real authentication**. That is intentional: the point of
the lab is the trust-boundary bugs, not the login.

## Run

```bash
python app.py
# -> TrustEdge listening on http://127.0.0.1:18808/  (GET /)
```

Then browse / curl `http://127.0.0.1:18808`. The home page links to every
endpoint (`/profile`, `/api/account`, `/api/data`, `/reset`, `/redirect`) so the
attack surface is discoverable.

## Planted vulnerabilities (T1..T7)

| ID | Name | Route | Trusted input | Confirm with curl | Impact |
|----|------|-------|---------------|-------------------|--------|
| **T1** | CORS reflects Origin + credentials | `GET /api/account` | `Origin` header (reflected verbatim) | `curl -s -i -H 'Origin: https://evil.example' http://127.0.0.1:18808/api/account` -> `Access-Control-Allow-Origin: https://evil.example` **+** `Access-Control-Allow-Credentials: true` | Any website can read the victim's authenticated account JSON (api key, ssn, balance) cross-origin with the victim's cookies. |
| **T2** | CORS allows `null` origin | `GET /api/data` | `Origin` header (incl. `null`) | `curl -s -i -H 'Origin: null' http://127.0.0.1:18808/api/data` -> `Access-Control-Allow-Origin: null` **+** credentials | `Origin: null` (sandboxed iframe, `data:`/`file:` document) bypasses origin checks and reads authenticated business data. Other origins are reflected too. |
| **T3** | Host header injection in password reset | `POST /reset` | `Host` header | `curl -s -H 'Host: evil.example' -d 'user=victim' http://127.0.0.1:18808/reset` -> `"link":"http://evil.example/reset-confirm?token=..."` | Attacker poisons the reset link sent to the victim; victim clicks, token leaks to attacker host -> **account takeover**. |
| **T4** | `X-Forwarded-Host` trusted for absolute URLs | `GET /`, `GET /profile` | `X-Forwarded-Host` header (else `Host`) | `curl -s -H 'X-Forwarded-Host: evil.example' http://127.0.0.1:18808/` -> `<link rel="canonical" href="http://evil.example/">` and asset/home links point at evil.example | Canonical/absolute links (SEO, asset loads, password-reset-style flows) are redirected to an attacker domain. |
| **T5** | CRLF injection / HTTP response splitting | `GET /redirect?next=` | `next` param (CR/LF not stripped) | `curl -s -i 'http://127.0.0.1:18808/redirect?next=/x%0d%0aSet-Cookie:admin=1'` -> response contains injected `Set-Cookie: admin=1` header | Inject arbitrary response headers (`Set-Cookie`, cache directives) / split the response -> session fixation, XSS via injected body, cache poisoning. |
| **T6** | Web cache poisoning via unkeyed header | `GET /` | `X-Forwarded-Host` (unkeyed) reflected into a **cacheable** body | `curl -s -i -H 'X-Forwarded-Host: evil.example' http://127.0.0.1:18808/` -> `evil.example` in the HTML body **+** `Cache-Control: public, max-age=300` | Response is cacheable and reflects an attacker-controlled, unkeyed header into `<link canonical>` / `<script src>`; a poisoned cache entry serves the attacker's host/asset to **all** users. |
| **T7** | Missing security headers | every response | n/a (omission) | `curl -s -I http://127.0.0.1:18808/` -> no `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` | No defense-in-depth: clickjacking, MIME sniffing, downgrade, and reflected-content attacks are unmitigated. |

### Notes on confirming T5

`http.client` / `BaseHTTPRequestHandler.send_header` may reject or strip CR/LF.
The `/redirect` handler therefore writes the status line and headers **by hand**
to the socket, so an injected CRLF in `next` genuinely splits the response. In
the raw output you will see the attacker's `Set-Cookie: admin=1` as a real
header line, not as part of the `Location` value.

## Endpoints

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home page; reflects `X-Forwarded-Host`, cacheable (T4, T6, T7). |
| `/profile` | GET | Profile page; absolute links from `X-Forwarded-Host` (T4). |
| `/api/account` | GET | Account JSON; reflective CORS + credentials (T1). |
| `/api/data` | GET | Business JSON; reflective CORS incl. `null` (T2). |
| `/reset` | GET/POST | Password reset; link built from `Host` header (T3). |
| `/redirect` | GET | `next=` redirector with CRLF injection (T5). |
