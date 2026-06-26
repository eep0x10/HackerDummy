# Lab 20 — GraphForge — Results

Advanced GraphQL — beyond the basic recon of Lab 07 (GraphVault) into the
query-execution attack surface: alias-based cost amplification (DoS), an
unauthenticated privileged mutation (BFLA), GraphQL CSRF via GET / form-encoded POST,
and introspection enabled in production.

## Result: 100% on the FIRST pass — a clean coverage confirmation

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **5/5 (100%)** | 83% | no fix needed — every finding classified correctly out of the box |

The blind GraphQL specialist found everything: it dumped the schema via introspection
(noting the sensitive `User.ssn` field and the `promoteToAdmin` mutation), fired the
unauthenticated `promoteToAdmin` mutation (privilege escalation, no creds), proved the
same mutation works over **GET** and **form-encoded POST** (CSRF, no token / no
JSON enforcement), and amplified an aliased `report` query to ~1 MB with no cost limit.

Notably, all five classified correctly with **no classifier change**:
- the alias-amplification finding → `dos`,
- the unauth mutation → `bfla`,
- the GraphQL-over-GET mutation → `csrf` — the class added at Lab 17 (OAuthForge)
  **generalised cleanly** to GraphQL CSRF,
- introspection → `graphql`,
- missing headers → `headers`.

This is the value of a benchmark even when nothing breaks: Lab 20 confirms the plugin
handles the advanced GraphQL surface — and that the recently-added `csrf` class isn't
OAuth-specific but covers cross-site state-changing requests generally.

## Lab note

A deliberately simplified GraphQL executor (substring/regex), faithful enough to
demonstrate each issue. Nothing executes code; play data only.

## Run it

```bash
python labs/20-graphforge/app.py       # -> http://127.0.0.1:18821  (/graphql)
```
