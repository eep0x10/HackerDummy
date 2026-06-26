# M05 — RootLite (Android)

Rung 5: the **RASP entry point**. The app *looks* hardened — it has root,
emulator and anti-debug detection — but every check is naive and trivially
bypassable. Security theatre, plus the controls it does have are undermined.

## Artifact

Decompiled **apktool tree** at [`app/`](app/). See [`../MOBILE.md`](../MOBILE.md).

```
app/
  AndroidManifest.xml                      # debuggable=true (undermines its own anti-debug)
  smali/com/rootlite/app/
    TamperCheck.smali                        # isRooted/isEmulator/isDebugged — single naive checks
    PinActivity.smali                        # sensitive PIN screen, no FLAG_SECURE
```

> Intentionally vulnerable, training only.

## Planted vulnerabilities (3)

| id | class | severity | evidence |
|----|-------|:--------:|----------|
| R1 | `weak-anti-tampering` | medium | root/emulator/anti-debug are single naive checks, no native/attestation — Frida/patch defeats them |
| R2 | `screenshot-allowed` | low | `PinActivity` (PIN screen) never sets `FLAG_SECURE` → screenshots/recording/recents capture |
| R3 | `debuggable` | medium | `android:debuggable="true"` in release — also defeats the app's own anti-debug |

Details in [`gabarito.json`](gabarito.json).

## Analyze & score

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M05-rootlite/gabarito.json \
  --findings your_agent_findings.json
```
