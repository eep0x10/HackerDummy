# M01 — LeakyVault — Results

The first **mobile (Android)** lab — and the first rung of the mobile ladder.
A wide-open decompiled app: no obfuscation, no RASP, pure static-analysis fruit.

## Result: 5/5 (100% recall) — the gap was vocabulary, not detection

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline (no mobile classes) | — | — | the blind agent found everything; the classifier had no mobile vocabulary, so the findings fell to `other` |
| After taxonomy | **5/5 (100%)** | 28% | precision <100% = bonus (the agent reports per-file instances; dedup collapses them) |

The blind static specialist analyzed the `app/` tree (manifest, `res/`, `assets/`,
`smali/`) **without the answer key** and produced **18 findings** — every planted
class plus genuine bonus: it caught all three exported components individually,
flagged the **user-CA trust-anchor** in the network-security-config, the **Bearer
token leaked to `Log.d`**, the duplicated secret across three extraction paths,
the over-broad `WRITE_EXTERNAL_STORAGE`, and the outdated `targetSdkVersion 22`.

Just like the web campaign: **the agent detects nearly everything blind; the gap
is the report engine naming it.**

## The gap this lab exposed

The classifier had **zero Android vocabulary**. Added four mobile classes (to both
`harness/classify.py` and the plugin's `finding_model.py`, kept in sync, plus
`TAXONOMY.md`):

| class | CWE | signal |
|-------|-----|--------|
| `debuggable` | 489 | `android:debuggable="true"` |
| `backup-allowed` | 530 | `android:allowBackup="true"` |
| `exported-component` | 926 | exported Activity/Service/Receiver/Provider, no permission |
| `cleartext-traffic` | 319 | `usesCleartextTraffic` / network-security-config cleartext |

They are placed **before** the web `backup` / `admin-panel` / `headers` classes so
the specific mobile class wins natural collisions (e.g. "adb **backup file**",
"exported **Admin**Activity"). Two fixes fell out of the regression check:

- the `cleartext-traffic` regex originally led with a bare `cleartext`, which would
  steal web findings like "**cleartext** credentials" → tightened to Android
  cleartext-traffic idioms only;
- `creds` didn't recognize **hardcoded-secret-in-APK** phrasing (api key / signing
  secret in `strings.xml` / `smali` / `assets`) and was out of sync between the two
  classifiers → unified and broadened in both.

## Bonus findings → the ladder ahead

The agent's extra findings preview later rungs: the **user-CA trust anchor** is the
`improper-tls` class M03 introduces; the **`Log.d` token leak** is `sensitive-log`
in M02. Built as designed.

## Run it

```bash
# blind static analysis of the tree, then:
python harness/score_lab.py \
  --gabarito labs/mobile/M01-leakyvault/gabarito.json \
  --findings your_agent_findings.json
```
