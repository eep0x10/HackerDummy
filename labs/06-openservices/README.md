# Lab 06 — OpenServices

> ⚠️ **INTENTIONALLY VULNERABLE — LOCALHOST ONLY.** Every listener binds to
> `127.0.0.1`. Never expose this on a real interface.

## What it is

**OpenServices** is a single host that carelessly exposes a fleet of data /
infrastructure services on their **standard ports**, each with **no
authentication** (or trivial **default credentials**) — the classic "internal
service left open to the network" misconfiguration that turns one foothold into
total compromise.

It is a **single stdlib-only Python file** (`app.py`): no Redis, Mongo,
Elasticsearch, Docker, etc. are installed. Each service is a small threaded
listener that speaks just enough of its protocol that a **banner-grabber** and a
**curious client** can confirm the exposure — `PING`→`+PONG`, version strings,
RESP/text framing, a MySQL handshake whose readable portion carries the EOL
version, real-shaped JSON for the HTTP APIs, etc.

Exposed services (all unauthenticated unless noted):

- **Redis** 2.8.0 — no auth
- **Elasticsearch** 1.4.2 — no auth, EOL/outdated (Groovy RCE era)
- **MongoDB** — no auth
- **CouchDB** 1.6.0 — "admin party" (empty admins → everyone is admin)
- **Docker Engine API** 19.03.5 — no TLS, no auth
- **Memcached** 1.4.15 — no auth
- **MySQL** 5.5.62 — EOL, reachable on the network
- **HTTP admin panel** — accepts default creds `admin:admin`

## How to run

```bash
python app.py
```

Each listener first checks the port is free, sets `SO_REUSEADDR`, and runs in its
own daemon thread. A **bind failure prints a warning and is skipped** (the lab
never crashes). On startup it prints a summary of which ports bound, e.g.:

```
=== Startup summary ===
  [BOUND ] I1  6379   Redis (no auth)
  [BOUND ] I2  9200   Elasticsearch 1.4.2 (no auth)
  ...
8/8 services listening. Ctrl+C to stop.
```

If a port is already taken on your machine (e.g. you actually run Redis), that
one line shows `[SKIP ]` and the rest still come up.

## Exposed services

Answer key: [`gabarito.json`](gabarito.json). 8 issues, 1 point each.

| ID  | Port  | Service | Why it's dangerous | How to confirm |
|-----|-------|---------|--------------------|----------------|
| I1  | 6379  | **Redis** (no auth) | Unauthenticated read/write of all keys; RCE via writing cron jobs, modules, or an SSH `authorized_keys` through `CONFIG SET dir` + `SAVE`. | `redis-cli -h 127.0.0.1 PING` → `PONG`; `INFO` → `redis_version:2.8.0` with **no AUTH required**. Raw: `printf 'PING\r\n' \| nc 127.0.0.1 6379` → `+PONG`. |
| I2  | 9200  | **Elasticsearch** 1.4.2 (no auth) | Full index dump with no auth; the 1.4.x line is the **CVE-2015-1427** Groovy sandbox-bypass RCE era. | `curl 127.0.0.1:9200/` → `"number":"1.4.2"`; `curl 127.0.0.1:9200/_cat/indices` lists a **`secrets`** index. |
| I3  | 27017 | **MongoDB** (no auth) | Unauthenticated database — dump/modify every collection. | `mongo 127.0.0.1:27017` → `show dbs`. Lab: connecting prints `MongoDB server (no auth)` so the open port is unmistakable. |
| I4  | 5984  | **CouchDB** 1.6.0 (admin party) | Empty `admins` config → **every request is admin**; create an admin / **CVE-2017-12635** priv-esc → RCE. | `curl 127.0.0.1:5984/` → `"couchdb":"Welcome"`; `curl 127.0.0.1:5984/_all_dbs` → `["_users","_replicator","secrets"]`. |
| I5  | 2375  | **Docker Engine API** (no TLS) | Unauthenticated daemon socket over TCP = **trivial host RCE**: run a container that bind-mounts the host root (`-v /:/host`). | `curl 127.0.0.1:2375/version` → `"Version":"19.03.5"`; `curl 127.0.0.1:2375/info` → `prod-docker-01`. |
| I6  | 11211 | **Memcached** 1.4.15 (no auth) | Read cached secrets (session tokens, query results); historically abused for UDP reflection/amplification. | `printf 'stats\r\n' \| nc 127.0.0.1 11211` → `STAT version 1.4.15`; `printf 'version\r\n'` → `VERSION 1.4.15`. |
| I7  | 3306  | **MySQL** 5.5.62 (EOL) | Network-reachable DB on an **end-of-life** version → brute-force `root`, `INTO OUTFILE` webshell, known CVEs. | Banner-grab: `recv(160)` on connect contains `5.5.62`; `mysql -h 127.0.0.1 -u root`. |
| I8  | 8080  | **Admin panel** (default creds) | HTTP admin dashboard protected only by **default credentials** `admin:admin`. | `curl 127.0.0.1:8080/admin` → `401` + `WWW-Authenticate: Basic`; `curl -u admin:admin ...` → `200` admin dashboard. Server header `Apache/2.2.15` (old). |

## Suggested attack walk-through

1. **Scan / banner-grab** the host → eight standard service ports answer.
2. **Redis (I1):** `INFO`, `CONFIG GET dir`, `KEYS *` with no AUTH → key dump,
   then the classic write-primitive RCE.
3. **Elasticsearch (I2):** `_cat/indices` → `secrets`; `_search` dumps data; the
   1.4.2 version is the Groovy-RCE window.
4. **MongoDB (I3) / CouchDB (I4):** open DB / admin party → dump or create-admin.
5. **Docker (I5):** the crown jewel — `2375` over plain HTTP is **host RCE**.
6. **Memcached (I6):** `stats`/`get` → cached tokens.
7. **MySQL (I7):** EOL `5.5.62` banner → brute / `INTO OUTFILE`.
8. **Admin panel (I8):** try `admin:admin` → in.

## Notes / design

- This mock exists to exercise **infra service detection + open-service /
  default-creds signal emission** without installing any of the real daemons.
- The MongoDB listener emits a readable lab banner instead of the real binary
  wire protocol, on purpose, so the open port is trivially identifiable.
- Secret-shaped values (passwords, `flag{...}`) are intentionally fake
  placeholders for training only.
