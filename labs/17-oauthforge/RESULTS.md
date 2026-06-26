# Lab 17 — OAuthForge — Results

The first **OAuth 2.0 / OIDC** lab — modern federated auth, distinct from SAML
(Lab 16). A stdlib-Python authorization server with the classic OAuth mistakes: an
authorize endpoint that doesn't validate `redirect_uri` (auth-code theft), a flow
with no `state` binding (OAuth CSRF), and a token endpoint that reuses codes, skips
client authentication, and accepts a code without the PKCE verifier (PKCE downgrade).

## Method

Full pipeline; the exploitation agent ran **blind**. It read
`/.well-known/openid-configuration`, recognised the OAuth flow, and worked the OAuth
checklist against the live server: sent an attacker `redirect_uri` (code 302'd to it),
ran the flow with no `state`, exchanged a code with no `client_secret`, replayed the
same code for multiple tokens, and redeemed a PKCE-challenged code with no verifier.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **2/5 (40%)** | 40% | missing-state → `other` (no CSRF class); token flaws → `other`; verbose error not triggered |
| After fix | **5/5 (100%)** | 80% | extras (redirect scheme injection, response_type) are real bonus, zero false positives |

The blind agent **found every OAuth flaw** (and extras — `javascript:`/`data:`
redirect_uri, response_type not validated). The gaps were all classification, plus
one lab-discoverability fix.

## The gaps this lab exposed

**1. New class: `csrf` (CWE-352).** The missing-`state` / OAuth-CSRF finding had no
class. Added `csrf` (cross-site request forgery / missing anti-CSRF token /
unvalidated OAuth `state` / missing SameSite) to both classifiers + `TAXONOMY.md`.
It is placed **before `auth`**: a "missing state → OAuth CSRF / authorization-code
injection" finding is primarily CSRF, but the OAuth auth-vocab (below) would
otherwise grab "code injection". csrf-before-auth keeps CSRF findings as CSRF while
the token-endpoint flaws still fall through to `auth`.

**2. `auth` now recognises OAuth token-endpoint flaws.** "Authorization Code Reuse",
"PKCE Not Enforced", and "Client Authentication Not Enforced" all classified as
`other`. Added OAuth vocabulary to `auth`: `pkce | code_challenge/verifier |
authorization code reuse/replay | code reuse | client authentication not enforced |
oauth downgrade/reuse/replay`. (A SAML signature bypass still → `auth`; Lab 02 JWT
stays `jwt`.)

**3. Lab discoverability (info-disc).** The verbose-error trigger (a malformed OIDC
`claims` JSON) was both undiscoverable (not advertised) and gated behind a valid
authorization code — so an error-fuzzer always hit the graceful `invalid_grant` and
concluded "debug off". Fixed the lab: the discovery document now advertises
`claims_parameter_supported`, and the `claims` JSON is parsed *before* grant
validation, so fuzzing the documented parameter reliably surfaces the traceback.
(A faithful fix — a real OIDC server advertises `claims` support — not a give-away.)

Re-score: **5/5**, all 17 labs still 100%.

## Lab note

In-memory; nothing real is at stake. Token/secret strings are non-functional
placeholders. Registered client: `webapp`, redirect_uri `http://127.0.0.1:18817/callback`.

## Run it

```bash
python labs/17-oauthforge/app.py        # -> http://127.0.0.1:18817
# GET /.well-known/openid-configuration ; GET /authorize ; POST /token
```
