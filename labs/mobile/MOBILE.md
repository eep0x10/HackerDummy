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

## Honest blind protocol (DEFAULT — do not weaken)

"Blind" must mean blind to *how to find it*, not just blind to the answer key.
Every mobile lab is authored and run under these rules so the score reflects real
detection, not a guided tour:

1. **Generic prompt — no thematic steering.** The agent gets a plain "statically
   assess this decompiled Android app and report every issue you can substantiate
   from the files" — **never** a hint about the category of the planted vuln (no
   "focus on TLS/WebView", no "this is a RASP lab"). It must pick the right areas
   itself.
2. **No signposting comments.** The shipped tree carries **no prose comments that
   name or explain a vuln** — not in smali (`#`), not in the manifest (`<!-- -->`),
   not in resources. The vuln must be discoverable from the *code/config itself*
   (a `MODE_WORLD_READABLE`, an `AES/ECB`, an `Intent.parseUri`, an empty
   `checkServerTrusted`, an absent `FLAG_SECURE`). Decoy / misleading comments are
   allowed; helpful ones are not.
3. **Noise + decoys — precision counts.** Each tree ships a `smali/com/common/lib/`
   noise pack: benign components **and at least two genuinely-strong controls**
   (e.g. AES/GCM + KeyStore + random IV; a correctly-applied OkHttp
   `CertificatePinner`). A run that flags a strong control is a real **false
   positive** — precision is reported and a flagged strong control is a methodology
   bug to fix, not bonus.
4. **Score both recall and precision honestly.** A drop below 100% under this
   protocol is the point: it reveals a genuine detection or precision gap to fix in
   the plugin (methodology/knowledge), distinct from the classification gaps the
   easy mode surfaced.

> What this still does **not** prove: detection in a real, large, obfuscated,
> comment-stripped APK (e.g. the actual `bradesco-novo.apk`, 4.5k files). These
> trees are small; treat 100% here as "names what it surfaces + picks the right
> areas + ignores strong controls", not "would find it in the wild".

### Hard-mode re-validation (the numbers that count)

All six labs were re-run under the protocol above — generic prompt, every
signposting comment stripped from smali/manifest/resources, and a
`com/common/lib/` noise pack (benign helpers + a correct AES/GCM+KeyStore crypto
box + a correctly-applied OkHttp pinner) injected into each tree:

| Lab | Recall | FP on strong controls | Note |
|-----|:------:|:---------------------:|------|
| M01 | 5/5 | none | emergent bonus: flagged that the pinner targets the wrong host |
| M02 | 4/4 | none | distinguished the weak `CryptoUtils` from the strong `CryptoBox` |
| M03 | 3/3 | none | self-corrected a "no pinning" claim once it saw the real pinner |
| M04 | 3/3 | none | inferred the exported account-screen leak from code (no comment) |
| M05 | 3/3 | none | inferred missing `FLAG_SECURE` without the hint |
| M06 | 3/3 | none | found the `qa_disable_checks` backdoor from control-flow alone |

**21/21 vulns, and the two strong-control decoys were judged STRONG and not
reported in all six runs.** Lower precision elsewhere is per-evidence granularity
(one finding per secret/flag), not false positives. The one lab-quality bug this
flushed out — M04's `DashboardActivity` "auth bypass" that lived only in a comment
— was fixed so the leak is substantiated in the smali itself.
