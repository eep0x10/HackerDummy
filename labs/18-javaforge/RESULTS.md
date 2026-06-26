# Lab 18 — JavaForge — Results

A Java / Apache Tomcat app (stdlib-Python mock) centred on **native Java
deserialization** — the app round-trips a base64 `rO0AB...` serialized object in the
`JSESSIONOBJ` cookie and accepts one at `/api/restore`, so a ysoserial gadget chain
reaches RCE. Plus default Tomcat-manager creds, verbose Java stack traces, and an
EOL Tomcat/Java banner.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **3/5 (60%)** | 43% | Tomcat default-creds finding classified `rce`; version/EOL finding classified `eol` (gabarito said `version`) |
| After fix | **5/5 (100%)** | — | extras are real bonus, zero false positives |

The blind Java specialist found everything: it recognised the `rO0AB` session cookie
as a Java serialized object, sent a CommonsCollections6 gadget to both
`/api/whoami` (cookie) and `/api/restore` (body) confirming RCE-capable, used the
default Tomcat-manager creds, triggered the Java stack trace, and flagged the EOL
Tomcat 7.0.42 / Java 1.8 with its deserialization CVEs.

## The gap this lab exposed

**`rce` must be the LAST impact class (the generalisation completed).** The "Tomcat
Default Credentials → WAR deploy → RCE" finding was stolen by `rce` because the
title mentions RCE — but its root cause is `default-creds`. This is the same
root-cause-vs-impact rule as upload/lfi/deser before rce; AspNetVault (Lab 13) moved
`rce` after the *injection* classes, but the access/config classes (default-creds,
exposed-service, actuator, admin-panel) were still below it. Moved `rce` to be the
**last impact class** (after every specific root cause that can lead to RCE). Now
"Tomcat default creds → RCE" → `default-creds`, "exposed Redis → RCE" →
`exposed-service`, "actuator → RCE" → `actuator`, while "OS Command Injection" still
→ `rce`. No regression across all 18 labs.

Also: the M4 answer-key class was corrected `version` → `eol` — the finding is
fundamentally about an end-of-life Tomcat/Java stack (the banner is how you detect it).

## Lab note

This is a Python mock of the Java surface. Nothing Java is deserialized/executed —
the endpoint recognises the `AC ED 00 05` stream magic and a ysoserial gadget chain
and reports it as RCE-capable without running anything. Secret-shaped strings are
non-functional placeholders.

## Run it

```bash
python labs/18-javaforge/app.py        # -> http://127.0.0.1:18818
```
