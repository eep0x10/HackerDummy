# Lab 05 — SpringVault — Results

Scoring the pipeline against a **Java/Spring Boot** target (a non-Python stack) —
7 planted actuator/management-interface issues. This lab specifically exercises
**stack detection → signal emission → secret mining**, not just classification.

## What this lab validated (recon pipeline)

Running the real `content_discovery.py` against the mock:
- **Stack detection:** `stack=java` correctly inferred from the Whitelabel Error
  Page body (no JVM, no server-header giveaway).
- **Path discovery:** all `/actuator/*` + `/jolokia` + `/h2-console` endpoints
  found via the java STACK_PATHS.
- **Signal emission:** **11 signals** fired — `actuator-env-exposed`,
  `actuator-heapdump-exposed`, `jolokia-exposed`, `h2-console-exposed`,
  `spring-actuator-exposed` — which route to `specialist-actuator-mine` /
  `specialist-jolokia-rce` / `specialist-h2-rce` in the registry.

So the **detect → signal → dispatch** chain for a Java/Spring stack works
end-to-end. That part needed no fix.

## Score

| Pass        | Recall        | Precision | Notes |
|-------------|---------------|-----------|-------|
| Baseline    | **5/7 (71%)** | 75%       | actuator/creds/info-disc classified |
| After fix   | **7/7 (100%)**| 100%      | actuator class broadened + reprioritized |

The blind agent mined everything (env secrets, heapdump → **live admin Bearer
session token** + flag, confirmed jolokia/h2 RCE surfaces). Zero false positives.

## The gap this lab exposed

The two RCE-surface findings — Jolokia and H2 console — were titled
"…(RCE surface)" by the agent and classified as generic **`rce`** instead of the
management-interface class, because: (1) the `actuator` regex required the
slash-prefixed forms `/jolokia` / `/h2-console`, and (2) `rce` was checked
*before* `actuator`, so the word "RCE" in the title won.

Fix (engine):
- **Broadened `actuator`** to match `jolokia`, `h2[-/space]console`, `jmx`, and
  `heapdump` as bare words (not only slash-prefixed paths), and relabeled it
  "Java/Spring management interface (Actuator/Jolokia/H2)".
- **Reordered** `actuator` *above* `rce` in the classifier, so the **specific**
  management-interface class wins over the generic RCE class for these findings
  (RCE is the *impact*; the exposed interface is the *class*).

Re-score: **7/7, 100% precision**. Regression: Labs 01-04 all unchanged
(15/15, 12/12, 7/7, 9/9) — `rce` still classifies plain "OS Command Injection".

## Strong points confirmed

- Java/Spring stack handled with no Python-specific assumptions: fingerprint
  detection, actuator path discovery, signal emission, and heap-dump secret
  mining all worked.
- The agent recovered a live admin session token from the heap dump — the
  highest-impact loot — and correctly scoped the jolokia/h2 RCE as
  *exposure-confirmed, not detonated* (zero-FP discipline).
