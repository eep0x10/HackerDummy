# Lab 06 — OpenServices — Results

Scoring the pipeline against a host exposing 8 misconfigured network services
(infra, not web). The agent ran **blind**, scoped strictly to the 8 in-scope lab
ports (the host's real SMB/445 was explicitly out of scope and untouched).

## What this lab validated (infra recon)

`service_scan.py` against `127.0.0.1` connected to the standard service ports and
emitted the right per-service signals — `redis-exposed`, `elastic-exposed`,
`mongodb-exposed`, `couchdb-exposed`, `docker-exposed`, `memcached-exposed`,
`mysql-exposed`, `http-alt-port` (and correctly also flagged the host's real
`smb-exposed` on 445, which we kept out of scope). The infra port-scan + banner +
signal step works.

## Score

| Pass        | Recall        | Precision | Notes |
|-------------|---------------|-----------|-------|
| Baseline    | **0/8 (0%)**  | 0%        | NO infra vocabulary at all |
| After fix   | **8/8 (100%)**| 100%      | +2 infra classes |

The blind agent confirmed all 8 (Redis 2.8.0 no-auth, Elasticsearch 1.4.2
no-auth, MongoDB no-auth, CouchDB admin-party, Docker API 19.03.5 no-TLS,
Memcached 1.4.15, MySQL 5.5.62 EOL, and the admin panel's `admin/admin`). Zero
false positives, all RCE vectors documented as theoretical (not detonated).

## The gap this lab exposed — the largest yet

Baseline recall was **0%**. The engine had **no class for exposed network
services or default credentials**, so the eight findings scattered into the
wrong buckets — "Exposed Redis" → `rce` (its body mentions cron-RCE), "Exposed
MySQL" → `sqli`/`other`, "Default credentials" → `creds`. Detection was perfect;
classification was absent.

Fix (engine):

| Class | CWE | Catches |
|-------|-----|---------|
| `exposed-service` | 306 | Redis/Elastic/Mongo/CouchDB/Docker/Memcached/MySQL/… reachable without authentication (missing auth on a critical function) |
| `default-creds` | 1392 | default/unchanged credentials (`admin/admin`, root-no-password, …) |

`default-creds` was placed **before** `creds` in the classifier, because
"Default **credential**s" would otherwise be grabbed by the generic credential-
exposure class. Both ship CVSS + ≥3 hardening references (OWASP/CIS/CWE).

Re-score: **8/8, 100% precision**. Regression: Labs 01-05 all unchanged.

## Strong points confirmed

- The infra subsystem (`service_scan`) fingerprinted every service and emitted
  correct signals on a multi-service host.
- The blind agent grabbed every version, confirmed every no-auth/default-cred
  condition, and respected scope (never touched the real SMB service) — a clean
  demonstration of authorized, scoped infra testing.
