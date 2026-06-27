# M06 — VaultSecure / Hardened (Android)

Rung 6, the **capstone**. A banking-grade hardened app modeled on a real
mobile-banking target: correct OkHttp certificate pinning, a native anti-tamper
library, and ProGuard/R8 obfuscation. None of those are the bug. The test is
whether the agent can **find three real flaws despite the hardening — without
false-positiving the strong controls.**

## Artifact

Decompiled **apktool tree** at [`app/`](app/). See [`../MOBILE.md`](../MOBILE.md).

```
app/
  AndroidManifest.xml                       # not debuggable, allowBackup=false; QaActivity exported
  lib/arm64-v8a/libtamper.so                # native anti-debug/anti-Frida (STRONG, placeholder)
  smali/com/vault/secure/
    NetSecurity.smali                         # OkHttp CertificatePinner — real pins, no bypass (STRONG)
    Guard.smali                               # native check BUT a qa_disable_checks backdoor in front
    a/c.smali                                 # obfuscated class hiding a base64 HMAC secret
    a/QaActivity.smali                        # leftover exported debug screen, flips the backdoor
```

> Intentionally vulnerable, training only. The "secret" is a non-functional placeholder.

## Planted vulnerabilities (3) — and what NOT to flag

| id | class | severity | evidence |
|----|-------|:--------:|----------|
| H1 | `creds` | high | base64 HMAC signing secret in the **obfuscated** class `a/c` (obfuscation ≠ secret store) |
| H2 | `exported-component` | high | leftover `QaActivity` exported in release; flips the RASP backdoor + dumps config |
| H3 | `weak-anti-tampering` | high | `Guard.isTampered()` short-circuits on a `qa_disable_checks` pref — a soft backdoor in front of the strong native check |

**Must NOT be reported as vulns (precision test):** the OkHttp `CertificatePinner`
(correct pins, no network bypass), the native `libtamper.so` anti-debug, and the
obfuscation itself. They are noted as observations, not findings.

Details in [`gabarito.json`](gabarito.json).

## Analyze & score

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M06-hardened/gabarito.json \
  --findings your_agent_findings.json
```
