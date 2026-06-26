# M02 — StorageCrypt (Android)

Rung 2 of the mobile ladder: **insecure local storage + broken cryptography** —
the data-at-rest layer of a mobile wallet app done wrong.

## Artifact

Decompiled **apktool tree** at [`app/`](app/). See [`../MOBILE.md`](../MOBILE.md).

```
app/
  AndroidManifest.xml                       # allowBackup=true
  res/values/strings.xml
  assets/db_schema.sql                      # plaintext SQLite: CPF, name, full PAN, MD5 PIN
  smali/com/storagecrypt/app/
    CryptoUtils.smali                        # AES/ECB + hardcoded key + zero IV + MD5
    StorageManager.smali                     # world-readable plaintext prefs + Log.d leak
```

> Intentionally vulnerable, training only. Seed values (test CPF/PAN) are
> non-functional placeholders.

## Planted vulnerabilities (4)

| id | class | severity | evidence |
|----|-------|:--------:|----------|
| S1 | `insecure-storage` | high | `MODE_WORLD_READABLE` plaintext prefs (token, PAN) + unencrypted SQLite PII |
| S2 | `weak-crypto` | high | `AES/ECB/NoPadding` + hardcoded key + all-zero static IV + unsalted MD5 |
| S3 | `sensitive-log` | medium | `Log.d` leaks the session token and full card PAN |
| S4 | `backup-allowed` | medium | `android:allowBackup="true"` → `adb backup` exfiltration |

Details in [`gabarito.json`](gabarito.json).

## Analyze & score

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M02-storagecrypt/gabarito.json \
  --findings your_agent_findings.json
```
