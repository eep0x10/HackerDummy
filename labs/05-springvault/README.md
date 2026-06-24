# Lab 05 — SpringVault

> ⚠️ **INTENTIONALLY VULNERABLE — LOCALHOST TRAINING ONLY.** Binds to `127.0.0.1`.

## What it is

**SpringVault** is a **faithful stdlib mock of a Java/Spring Boot app** with its
**Actuator** endpoints exposed — the classic real-world misconfiguration
(`management.endpoints.web.exposure.include=*`). No JVM required: it reproduces
the Spring fingerprints (Whitelabel Error Page, `X-Application-Context` header,
Java stack traces) and the dangerous management endpoints, so a pipeline's
**stack detection → actuator signal emission → secret mining** can be exercised
end to end against a "non-Python" stack. Runs on `127.0.0.1:18805`.

## How to run

```bash
python app.py        # -> http://127.0.0.1:18805
```

`GET /` returns a Spring Whitelabel Error Page (the fingerprint). `GET /actuator`
lists the exposed management endpoints.

## Planted vulnerabilities

Answer key: [`gabarito.json`](gabarito.json). 7 issues, 1 point each.

| ID  | Class     | Sev      | Route                | What |
|-----|-----------|----------|----------------------|------|
| SP1 | actuator  | high     | `/actuator`          | Management endpoint listing exposed, no auth. |
| SP2 | actuator  | critical | `/actuator/env`      | Config secrets in cleartext: datasource password, JWT secret, Stripe/AWS keys. |
| SP3 | actuator  | critical | `/actuator/heapdump` | Downloadable `.hprof` → mine memory for runtime secrets (DB pwd, JWT, **admin Bearer session token**). |
| SP4 | actuator  | critical | `/jolokia`           | JMX-over-HTTP exposed → MBean read/invoke (logback `reloadByURL` → JNDI/deser RCE surface). |
| SP5 | actuator  | high     | `/h2-console`        | H2 web console reachable → controllable JDBC URL → `CREATE ALIAS`/`RUNSCRIPT` RCE. |
| SP6 | creds     | critical | `/actuator/env`      | The actual loot: production credentials reusable elsewhere. |
| SP7 | info-disc | medium   | `*`                  | Whitelabel page + Java stack traces leak Spring Boot **2.6.6** and internal packages. |

## Suggested attack walk-through

1. **Fingerprint:** `GET /` → "Whitelabel Error Page" + "Spring Boot 2.6.6" ⇒ Java/Spring.
2. **Enumerate management:** `GET /actuator` → env, heapdump, mappings, …
3. **Steal config:** `GET /actuator/env` → DB password, JWT secret, API keys.
4. **Mine memory:** `GET /actuator/heapdump` → grep the bytes → admin session token.
5. **RCE surfaces:** `/jolokia` (JMX→reloadByURL) and `/h2-console` (JDBC URL).

## Notes / design

- This mock exists to test **stack detection + actuator mining** on a non-Python
  stack without a JVM. The pipeline detects `stack=java` from the Whitelabel body
  and auto-probes the `/actuator/*` + `/jolokia` paths.
- Secret-shaped values (Stripe/AWS) are intentionally non-functional placeholders.
