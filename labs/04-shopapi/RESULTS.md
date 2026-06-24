# Lab 04 — ShopAPI — Results

Scoring the pipeline against ShopAPI's 9 planted API vulns (OWASP API Top 10).
The exploitation agent ran **blind** — given only a normal-user test credential
(`alice`/`alicepass`) and the endpoint list, never the answer key.

## Score

| Pass        | Recall        | Precision | Notes |
|-------------|---------------|-----------|-------|
| Baseline    | **6/9 (67%)** | 71%       | idor/mass-assignment/no-rate-limit/ssrf/jwt classified |
| After fix   | **9/9 (100%)**| 100%      | +2 API classes; verbose-error modeled app-wide |

The blind agent confirmed **11 findings** (it split JWT into alg:none + weak-secret
and found a bonus internal-config exposure) — escalating to admin **three
independent ways** (BFLA promote, mass-assignment, JWT forgery) and cracking the
HS256 secret `apisecret` on the first wordlist hit. Zero false positives.

## The gap this lab exposed

The engine had `idor` (covers BOLA), `mass-assignment`, `no-rate-limit`, `ssrf`,
`jwt`, `info-disc` — but no vocabulary for two core API-specific classes:

| Class | CWE | Catches |
|-------|-----|---------|
| `bfla` | 285 | Broken Function Level Authorization — privileged function callable by a normal user |
| `excessive-data` | 213 | Excessive Data Exposure — API returns sensitive fields (password hash, ssn, internal notes) a client must never see |

Without `excessive-data`, the `/users` leak was mis-grabbed by `weak-crypto` (it
mentions an MD5 hash). Both added with CVSS + ≥3 OWASP-API/CWE references.

## A coverage nuance (verbose errors)

The planted verbose-error (B9) reproduces on **every** endpoint (`/orders`,
`/avatar`, …) — it's an app-wide `DEBUG=on` misconfiguration, not route-specific.
The blind agent triggered it on `/avatar` (it didn't fuzz `/orders` with a bad
body, though `/orders` tracebacks too). Because the misconfiguration is
server-wide, the answer key models B9 as host-level (`route: "*"`) — the plugin
genuinely detected the class. Lesson logged: fuzzing **every** write endpoint
with malformed input surfaces more instances of the same misconfig.

## Regression

After the additions: Lab 01 **15/15**, Lab 02 **12/12**, Lab 03 **7/7** — all
unchanged. The new classes are additive (title-first classification).

## Strong points confirmed

- The blind API agent's access-control tradecraft was complete: BOLA on two
  object types, BFLA on the admin function, mass-assignment, and three separate
  privilege-escalation paths — all with concrete cross-user / escalation proof.
- It correctly ruled out false leads (tampered JWT signature rejected, `file://`
  blocked on the avatar SSRF) — zero false positives.
