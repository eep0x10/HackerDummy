# pentest-labs

A campaign of **deliberately vulnerable applications** built to stress-test and
refine an automated pentest pipeline. Each lab ships with an **answer key**
(`gabarito.json`) listing every planted vulnerability, so a scan can be scored
objectively: *did the process find the N planted bugs — or even more than
planned?*

> ⚠️ **Every app here is intentionally vulnerable.** They bind to `127.0.0.1`
> and are for **localhost security training only**. Never expose them to a
> network, never run them on a shared/public host, and never reuse any seed
> credential.

## Why this exists

Reviewing a pentest tool by eyeballing its reports doesn't tell you what it
*misses*. This repo turns that into a measurement: plant a known set of
vulnerabilities, run the pipeline **blind** (the attacker never sees the answer
key), and compute **recall** (planted bugs found ÷ planted) and **precision**
(findings that map to a planted bug ÷ total findings). Misses become a concrete
backlog of improvements; extras are either false positives to kill or genuine
bonus findings.

The loop is:

```
build lab + answer key  →  run pipeline BLIND  →  score recall/precision
        ↑                                                    │
        └──────────  fix the gaps the misses reveal  ◀───────┘
```

## Layout

```
labs/<NN-name>/
  app.py          # single-file, stdlib-only vulnerable app (no pip installs)
  gabarito.json   # answer key: every planted vuln (id, class, severity, route, exploit)
  README.md       # what the lab is, how to run it, the planted-vuln table
  RESULTS.md      # how the pipeline scored against it + gaps found/fixed
harness/
  score_lab.py    # compares gabarito.json vs a scan's findings → recall/precision
```

### Answer-key schema (`gabarito.json`)

```json
{
  "lab": "01-vulnshop",
  "base_url": "http://127.0.0.1:18801",
  "vulns": [
    {"id": "V01", "class": "sqli", "severity": "critical",
     "route": "/login", "desc": "...", "exploit": "...", "points": 1}
  ]
}
```

`class` uses canonical vulnerability keys (`sqli`, `xss`, `stored-xss`, `idor`,
`ssrf`, `open-redirect`, `creds`, `scm`, `backup`, `dir-listing`,
`admin-panel`, `cookie`, `headers`, `info-disc`, …). `route` is the vulnerable
path; `route: "*"` or `"/"` means "host-level, match any finding of that class".

### Scoring a run

```bash
python harness/score_lab.py \
  --gabarito labs/01-vulnshop/gabarito.json \
  --engagement <path-to-scan-output>
```

It matches by **class + route** and prints `ENCONTRADAS` (matched),
`MISSED` (planted but not found → gaps), and `EXTRA` (found but not in the key
→ false positive *or* bonus).

## Labs

| #  | Lab        | Stack                  | Planted | Focus                                                            |
|----|------------|------------------------|---------|-----------------------------------------------------------------|
| 01 | [VulnShop](labs/01-vulnshop/) | Python stdlib + sqlite3 | 15 | Classic OWASP web set: SQLi, XSS (reflected+stored), IDOR, SSRF, open redirect, exposed `.git`/`.env`/backup, dir-listing, headers, cookie, info-disclosure, unauth admin. |
| 02 | [VaultAuth](labs/02-vaultauth/) | Python stdlib + hand-rolled JWT | 12 | Auth/identity API: JWT `alg:none` + weak secret + no-`exp`, user enumeration, no rate-limiting, OTP/2FA bypass, mass-assignment priv-esc, unsalted-MD5 storage, IDOR, broken session (logout/remember-me). |
| 03 | [RelayKit](labs/03-relaykit/) | Python stdlib | 7 | Server-side exploitation: SSRF (+ filter bypass), XXE (file read/SSRF), insecure deserialization, OS command injection, path traversal/LFI, SSTI. Dangerous primitives are confirmable but execution-blocked by design. |
| 04 | [ShopAPI](labs/04-shopapi/) | Python stdlib JSON API + JWT | 9 | OWASP API Top 10: BOLA (object), BFLA (function), mass-assignment, excessive data exposure, JWT alg:none/weak-secret, missing rate-limiting, SSRF, verbose errors. |
| 05 | [SpringVault](labs/05-springvault/) | Java/Spring Boot (stdlib mock) | 7 | Spring Boot Actuator exposed: `/env` + `/heapdump` secret mining, Jolokia (JMX→RCE), H2 console (RCE), cleartext creds, Whitelabel/stack-trace disclosure. Tests stack-detection → signal → mining on a non-Python stack. |
| 06 | [OpenServices](labs/06-openservices/) | Infra — exposed network services | 8 | Unauthenticated Redis, Elasticsearch, MongoDB, CouchDB, Docker API (no TLS), Memcached, MySQL (EOL), + an admin panel with default `admin/admin`. Tests the infra `service_scan` port/banner/signal pipeline. |
| 07 | [GraphVault](labs/07-graphvault/) | GraphQL API (stdlib) | 8 | GraphQL: introspection enabled, BOLA, excessive data exposure, BFLA mutation, batching (no rate-limit), query-depth DoS, SQLi via argument, field-suggestion disclosure. |

## Results so far

| Lab | Planted | Baseline recall | Final recall | Precision | Gaps fixed |
|-----|---------|-----------------|--------------|-----------|------------|
| 01  | 15      | 12/15 (80%)     | **15/15 (100%)** | 93% (1 bonus, 0 FP) | 3 classifier bugs ([RESULTS](labs/01-vulnshop/RESULTS.md)) |
| 02  | 12      | 1/12 (8%)       | **12/12 (100%)** | 100%      | +8 auth/JWT/session classes ([RESULTS](labs/02-vaultauth/RESULTS.md)) |
| 03  | 7       | 4/7 (57%)       | **7/7 (100%)**   | 100%      | +3 server-side classes (xxe/deser/ssti) ([RESULTS](labs/03-relaykit/RESULTS.md)) |
| 04  | 9       | 6/9 (67%)       | **9/9 (100%)**   | 100%      | +2 API classes (bfla/excessive-data) ([RESULTS](labs/04-shopapi/RESULTS.md)) |
| 05  | 7       | 5/7 (71%)       | **7/7 (100%)**   | 100%      | actuator class broadened + reprioritized over rce ([RESULTS](labs/05-springvault/RESULTS.md)) |
| 06  | 8       | 0/8 (0%)        | **8/8 (100%)**   | 100%      | +2 infra classes (exposed-service/default-creds) ([RESULTS](labs/06-openservices/RESULTS.md)) |
| 07  | 8       | 6/8 (75%)       | **8/8 (100%)**   | 100%      | +2 classes (graphql/dos); regression sweep caught a NameError ([RESULTS](labs/07-graphvault/RESULTS.md)) |

Across all labs the **blind pentest found every planted bug on the first
pass** — the misses were always the *report engine* failing to classify a
real finding, which is precisely the weakness the answer-key loop is designed
to expose. **21 engine classes/fixes + a directory-discovery upgrade** shipped
so far (source-reference mining + redirect-following, so wordlist-blind
SPA/JSON apps still get fully mapped). The labs also validated the recon
pipeline beyond plain web: **Java/Spring stack-detection → actuator mining**
(Lab 05) and the **infra `service_scan` port/banner/signal** chain (Lab 06).

### Engine classes added by this campaign

`jwt` · `2fa-bypass` · `user-enum` · `no-rate-limit` · `mass-assignment` ·
`weak-crypto` · `session` · `auth` · `xxe` · `deserialization` · `ssti` ·
`open-redirect` · `bfla` · `excessive-data` · `exposed-service` · `default-creds` ·
`graphql` · `dos` — plus classifier fixes (title-first classification; tightened
`aspnet-leak`; `actuator` broadened + reprioritized over `rce`).

Each lab's `RESULTS.md` documents exactly what the pipeline found, what it
missed on the first pass, and what was fixed as a result.

## License

The lab code is provided for educational/defensive security training. Use only
against systems you own or are explicitly authorized to test.
