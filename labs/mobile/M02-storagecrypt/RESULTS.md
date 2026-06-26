# M02 — StorageCrypt — Results

Rung 2: insecure local storage + broken crypto. The blind static specialist read
the `app/` tree (manifest, two smali classes, `assets/db_schema.sql`) and produced
**10 findings** — covering all four planted classes plus bonus (hardcoded AES key,
static IV, MD5 PIN). Notably it **correctly did NOT raise a cleartext-network
finding** (targetSdk 31 disables cleartext by default and there's no permissive
network-security-config) — good false-positive discipline.

## Score

| Pass | Recall | Notes |
|------|--------|-------|
| After taxonomy | 3/4 (75%) | the `allowBackup` finding was stolen by `insecure-storage` (it names the prefs/DB it exposes) |
| After reorder | **4/4 (100%)** | `backup-allowed` moved before `insecure-storage`; precision 40% (rest = bonus) |

## The gaps this lab exposed

**Two new classes + one extension** (synced in `classify.py` and `finding_model.py`,
documented in `TAXONOMY.md`):

| class | CWE | signal |
|-------|-----|--------|
| `insecure-storage` | 312 | world-readable/plaintext SharedPreferences, unencrypted SQLite/PII |
| `sensitive-log` | 532 | token/PII/PAN written to logcat (`Log.d`/`Log.v`) |
| `weak-crypto` (extended) | 327 | + AES-ECB, static/zero IV, hardcoded crypto key (kept MD5/SHA1/unsalted) |

**Three ordering/regression fixes** the sweep forced:

1. **`backup-allowed` before `insecure-storage`** — a real `allowBackup` finding
   describes the data it exposes ("...extract the SharedPreferences and plaintext
   `wallet.db`..."), so the storage class stole it. Root-cause class wins.
2. **`insecure-storage` before `weak-crypto`** — so "plaintext token in
   SharedPreferences" is a storage finding, while "MD5 hashing" stays crypto.
3. **`sqli` → `\bsqli\b`** — the bare literal matched "**SQLi**te", mis-classing any
   "unencrypted SQLite database" finding as SQL injection. Word-boundary keeps the
   `SQLi` abbreviation while freeing `SQLite`.

`sensitive-log` is anchored on real logging idioms (`logcat`, `Log.d/v`, "written
to log") so it does **not** steal web findings like "login **token** in the URL".

## Run it

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M02-storagecrypt/gabarito.json \
  --findings your_agent_findings.json
```
