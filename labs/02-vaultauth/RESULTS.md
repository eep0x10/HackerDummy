# Lab 02 — VaultAuth — Results

Scoring the automated pentest pipeline against VaultAuth's 12 planted
authentication / JWT / session vulns. The exploitation agent ran **blind** (it
got only the root endpoint list, never the answer key).

## Method

A blind auth-pentest agent decoded a real JWT, attacked the signature
(`alg:none`, offline secret crack, `exp`), probed login/register/reset for
enumeration and rate-limiting, tested OTP/2FA, mass-assignment, credential
storage, IDOR, and session/logout behaviour — confirming each with live
requests — then `harness/score_lab.py` matched the findings against
`gabarito.json` by class + route.

## Score

| Pass            | Recall           | Precision | Notes |
|-----------------|------------------|-----------|-------|
| Baseline        | **1/12 (8%)**    | 33%       | agent found all 13, engine could classify only IDOR |
| After fix       | **12/12 (100%)** | **100%**  | 8 new auth classes added |

The agent **confirmed all 12 planted vulns** on the first pass (it even cracked
the HS256 secret `secret`, forged `alg:none` *and* re-signed admin tokens, took
over accounts via sequential reset tokens, and used OTP master-code `000000`).
The baseline score was 8% **not** because detection failed, but because the
report engine had **no vocabulary for authentication bugs** — 11 of 13 findings
collapsed into generic `creds`/`other` buckets and deduped away.

## The gap this lab exposed

`finding_model.py` classified findings into web-injection and
exposure classes but had **zero auth/JWT/session classes**. Every auth finding
fell through to `other` (and merged into a single bucket), so the pipeline
*found* the bugs but couldn't *name* or *report* them distinctly.

### Fix — 8 new classes added to the shared engine

| Class | CWE | Catches |
|-------|-----|---------|
| `jwt` | 347 | alg:none, weak signing secret, missing `exp`/claim validation |
| `2fa-bypass` | 287 | OTP/MFA leaked, master codes, second factor not enforced |
| `user-enum` | 204 | response discrepancies revealing valid accounts |
| `no-rate-limit` | 307 | missing brute-force / credential-stuffing protection |
| `mass-assignment` | 915 | unexpected attributes (e.g. `role`) → privilege escalation |
| `weak-crypto` | 916 | unsalted MD5/SHA1/plaintext password storage |
| `session` | 384 | session fixation, no-invalidation-on-logout, predictable tokens |
| `auth` | 640 | weak password recovery / reset-token takeover, broken auth |

Each ships its own CVSS vector and **≥3 targeted remediation references**
(OWASP cheat sheets + WSTG + CWE). Re-score: **12/12 recall, 100% precision**.

### Regression

Re-scored **Lab 01 — VulnShop** with the updated engine: still **15/15**, no
regression. The new classes are additive (matched on the specialist's title via
the title-first classifier from Lab 01).

## Strong points confirmed

- The blind agent's JWT tradecraft was complete: decode → `alg:none` forge →
  offline secret crack → re-sign → `exp` replay, all confirmed against the
  live server with zero false positives.
- It correctly chained primitives (leaked MD5 → cracked admin password; reset
  token → account takeover; mass-assignment → admin JWT).

## Follow-up (logged, not yet done)

- **Auto-detection.** These bugs are found by *active* testing, so the fix sits
  at the classification layer (done). A complementary improvement: have recon
  emit a `jwt_alg` signal when a Bearer/JWT is observed, to auto-trigger the
  existing `specialist-jwt-attack` (registry WEB-023). Worth wiring next.
- **Methodology coverage.** Confirm the `droidagent-web` exploitation phase
  explicitly prompts for JWT alg-confusion, OTP bypass, mass-assignment, and
  reset-token analysis, so a real engagement reaches these without a
  hand-written prompt.
