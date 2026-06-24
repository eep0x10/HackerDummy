# Lab 08 — TrustEdge — Results

Scoring the reference agent against 7 planted **trust-boundary** vulns — bugs
that come from trusting attacker-controlled request headers/params (CORS, Host,
X-Forwarded-Host, CRLF). Ran **blind**.

## Score

| Pass        | Recall        | Precision | Notes |
|-------------|---------------|-----------|-------|
| Baseline    | **1/7 (14%)** | 17%       | only `headers` had a class |
| After fix   | **7/7 (100%)**| 100%      | +4 trust-boundary classes |

The blind agent confirmed all 7 with raw header evidence (CORS reflecting both
`evil.example` and `Origin: null` with credentials, Host-header reset poisoning,
X-Forwarded-Host reflected + cacheable, and a real CRLF response split injecting
`Set-Cookie: admin=1`). Zero false positives.

## The gap this lab exposed

These are classic but easily-missed **header-trust** issues, and the engine had
no vocabulary for any of them — the findings scattered into `auth` (the reset
poisoning, via "password reset"), `creds` (CORS, via "credentials"), `session`,
and `other`. Added:

| Class | CWE | Catches |
|-------|-----|---------|
| `cors-misconfig` | 942 | reflected/`null`/wildcard `Access-Control-Allow-Origin` (+ credentials) |
| `host-header-injection` | 644 | Host / X-Forwarded-Host trusted into links/redirects (reset poisoning, ATO) |
| `crlf` | 113 | CRLF in a header value → HTTP response splitting / header injection |
| `cache-poisoning` | 349 | unkeyed header reflected into a cacheable response |

Ordering mattered: `cors-misconfig` had to sit **before** `creds` (its title says
"credentials") and `host-header-injection` **before** `auth` (its title says
"password reset"), so the specific class wins. Both the plugin's `finding_model`
and the benchmark's standalone `harness/classify.py` were updated in lockstep.

Re-score: **7/7, 100%**. Regression: Labs 01-07 all unchanged.

## Strong points confirmed

- The blind agent read response headers carefully (these bugs are invisible in
  the body) and proved the CRLF split at the raw-bytes level — exactly the rigor
  these subtle issues need.
- It correctly separated the two X-Forwarded-Host impacts (host-header trust vs
  the cacheable cache-poisoning variant) into distinct findings.
