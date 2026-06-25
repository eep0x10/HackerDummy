# Lab 09 — InjectArena — Results

Scoring the DroidAgent plugin against InjectArena's 5 beyond-SQL injection vulns.
The exploitation agents ran **blind** (live target + plugin knowledge base, never
the answer key).

## Method

Blind injection specialists tested each endpoint and confirmed all five with live
payloads: NoSQL operator injection (`$ne` auth bypass) on `/login`, LDAP injection
on `/directory`, XPath injection on `/employee`, SSI injection on `/greet`, and CSV
/ formula injection on `/export`. `score_lab.py` matched by class + route.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **0/5 (0%)** | — | the plugin **detected all five** but had no class to name them → all fell to `sqli`/`other` |
| After fix | **5/5 (100%)** | — | five dedicated injection classes added |

## The gap this lab exposed

The plugin *knew* these techniques (the knowledge base documents NoSQL/LDAP/XPath/
SSI/CSV injection) but the report engine had **no canonical class** for any of them,
so it could not name what it found. Added 5 classes to `finding_model.py` **and** the
benchmark's `classify.py`:

| Class | CWE | Note |
|-------|-----|------|
| `nosqli` | 943 | **must precede `sqli`** — "NoSQL Injection" contains "sql inj" |
| `ldap-injection` | 90 | |
| `xpath-injection` | 643 | |
| `ssi-injection` | 97 | server-side includes / ESI |
| `csv-injection` | 1236 | formula / spreadsheet injection |

Ordering matters: `nosqli` is placed **before** `sqli` so the more specific class
wins. Re-score: **5/5**, no regression across the other labs. Same pattern as every
other lab — **detection was complete; the gap was classification vocabulary.**
