# Lab 16 — SamlForge — Results

The first **SSO / SAML** lab — enterprise federated auth, a surface none of the
prior 15 labs touched. A stdlib-Python mock of a SAML 2.0 Service Provider that
reproduces the classic SAML attack chain: an ACS that never verifies the assertion
signature (auth bypass), an XML parser with external entities enabled (XXE via the
SAMLResponse), and an unvalidated RelayState (open redirect).

## Method

The plugin ran the full pipeline; the exploitation agent ran **blind** with a
methodology-driven prompt (no hint which SAML attacks were present). It enumerated
the SSO endpoints, pulled a sample SAMLResponse from `/sso/login`, recognised the
SAML flow, and worked the SAML checklist: it tampered the NameID/role to `admin`
(accepted — `signature_verified:false`), stripped the `<ds:Signature>` entirely
(still accepted), injected a DOCTYPE external entity in the NameID to read a server
file (XXE), and pointed RelayState at an external URL (302 open redirect). Exactly
how a SAML SP is pentested.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **4/5 (80%)** | 57% | the SAML signature bypass mis-classified (`jwt` / `other`) |
| After fix | **5/5 (100%)** | 83% | extra (XSW dual-assertion, clickjacking) are real bonus, zero false positives |

The blind agent **found all five** (plus XSW). The single gap was classification.

## The gap this lab exposed

**SAML auth-bypass vocabulary — and a too-greedy `jwt` regex.** The SAML signature
bypass ("SAML Signature Bypass — Tampered Assertion") classified as `jwt`, and
"Signature Stripping" / "XSW" fell to `other`. Two fixes:

1. The `jwt` class had a bare `signature.*bypass` alternative that grabbed *any*
   signature bypass — including SAML. Narrowed it to `(jwt|token).*signature.*bypass`
   (real JWT signature issues are still covered by `jwt.*(secret|signature|forge)`).
2. Added SAML / XML-signature vocabulary to the canonical `auth` class:
   `saml signature/assertion bypass | signature bypass/strip/exclusion/wrapping |
   XSW | assertion forge/inject/tamper/strip | unsigned assertion`. A SAML signature
   bypass is, canonically, an authentication bypass.

Verified: SAML bypass/stripping/XSW → `auth`; JWT `alg:none` / weak-HMAC still →
`jwt`; Lab 02 (JWT) stays 12/12; all 16 labs 100%.

## A lab-integrity fix the run surfaced

The verbose-error traceback (and an XXE source read) exposed the lab's own inline
comments — which had carried the gabarito IDs (`# G2: parsed with XXE enabled`). That
leaks the answer key to anyone fuzzing the SP. Stripped the `Gn` labels from the
served source; the descriptive comments remain (a pentester would derive them anyway).

## Lab note

Signature "validation" is a deliberate no-op (auth logic only). The XXE is genuine
but read-only. Secret-shaped strings are non-functional placeholders.

## Run it

```bash
python labs/16-samlforge/app.py        # -> http://127.0.0.1:18816
# GET /sso/login for a sample SAMLResponse to tamper and replay to /sso/acs
```
