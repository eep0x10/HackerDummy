# HackerDummy — Mobile labs (Android)

A parallel track that extends the benchmark from *live web exploitation* to
**Android app assessment** — the methodology a mobile pentester applies to a
decompiled APK and to its runtime protections.

## Why a different artifact

Web labs are HTTP servers you attack live. A mobile target is an **APK**: you
*decompile* it (jadx / apktool) and reason over the result — `AndroidManifest.xml`,
`smali`/Java, resources, assets, native libs — then, dynamically, defeat its
protections (root/emulator detection, anti-Frida, cert pinning, obfuscation).

So each mobile lab ships as a **decompiled-APK project tree** — exactly the form
`apktool d app.apk` / `jadx` produce:

```
labs/mobile/MNN-name/
  app/
    AndroidManifest.xml         # text manifest (apktool form)
    apktool.yml                 # so `apktool b app/` rebuilds a real APK
    smali/.../*.smali           # classes carrying the planted signals
    res/values/strings.xml      # resources / hardcoded strings
    assets/                     # bundled files (configs, keys, JS)
    lib/<abi>/                  # native .so placeholders (later rungs)
  gabarito.json                 # answer key (same schema as web labs)
  README.md                     # what it is, the planted-vuln table
  RESULTS.md                    # the reference run's score
```

This single artifact is:
- **greppable today** — a static-analysis agent runs its real methodology
  (manifest flags, secret grep, storage/crypto/IPC/WebView/TLS patterns) on it;
- **buildable** — `apktool b labs/mobile/MNN-name/app` yields a real, decompilable
  APK once you want to install/instrument it.

> Nothing here executes code or talks to a real backend. All endpoints are
> `example`/`127.0.0.1` placeholders; all secret-shaped strings are non-functional.

## Scoring

Identical contract to the web labs — `harness/score_lab.py` matches a finding by
**class + location**. For mobile, `route` in the gabarito is the *location of the
evidence*: a file path (`AndroidManifest.xml`, `res/values/strings.xml`, a smali
class) or `*` for app-wide. Run it in generic mode:

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M01-leakyvault/gabarito.json \
  --findings your_agent_findings.json
```

The mobile vulnerability classes live in the same taxonomy
([`harness/classify.py`](../../harness/classify.py) / [`TAXONOMY.md`](../../TAXONOMY.md)) —
e.g. `exported-component`, `cleartext-traffic`, `debuggable`, `backup-allowed`,
`insecure-storage`, `improper-tls`, `webview`, `deeplink`, `weak-anti-tampering`
(plus reused `creds`, `weak-crypto`, `lfi`, `info-disc`).

## The ladder (simple → hardened)

Modeled to escalate from a wide-open app to one hardened like a real
mobile-banking target (the kind shipping AllowMe-style RASP, native pinning,
liveness/attestation SDKs, and heavy obfuscation):

| Rung | Lab | Theme | Headline classes |
|------|-----|-------|------------------|
| M01 | LeakyVault | Static fruit | debuggable, backup-allowed, exported-component, cleartext-traffic, creds |
| M02 | StorageCrypt | Insecure storage & crypto | insecure-storage, weak-crypto, sensitive-log |
| M03 | NetForge | Network trust & WebView | improper-tls, webview |
| M04 | DeepLinkForge | IPC / deep links | deeplink, exported-component, lfi (provider traversal) |
| M05 | RootLite | RASP entry (bypassable) | weak-anti-tampering |
| M06 | Hardened | Banking-grade protections guarding a real flaw | weak-anti-tampering + the flaw behind it |

Each lab plants **distinct classes** (so the `(host, class)` dedup never collapses
two findings) and is built/scored/fixed to 100% recall before the next rung —
same loop as the web campaign.

## Tooling

`jadx` and `apktool` (both installable via scoop / their releases) for decompile
and rebuild. The reference agent is DroidAgent's `droidagent-mobile` skill, run
**blind** (never sees the gabarito), reading its mobile knowledge base.
