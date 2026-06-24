# Lab 03 — RelayKit — Results

Scoring the pipeline against RelayKit's 7 planted server-side vulns. The
exploitation agent ran **blind** (recon endpoint list only, never the key).

## Method

Recon: the upgraded `content_discovery.py` **source-mined** the endpoint list
straight out of the JSON home page (none of RelayKit's routes are in any
wordlist) — including the server-only `/internal/secrets`. Then a blind
server-side agent tested SSRF (incl. filter bypass), XXE, insecure
deserialization, OS command injection, path traversal, and SSTI, confirming each
with live requests. `score_lab.py` matched by class + route.

## Score

| Pass        | Recall        | Precision | Notes |
|-------------|---------------|-----------|-------|
| Baseline    | **4/7 (57%)** | 100%      | ssrf/rce/lfi classified; xxe/deser/ssti had no class |
| After fix   | **7/7 (100%)**| 100%      | +3 server-side classes |

The agent confirmed all 7 on the first pass (bonus: noted `/fetch` also accepts
`file://`, and that the `/preview` embedded-credential bypass is correctly
blocked while case-variation works). The 3 misses were, again, **missing
classes** — the engine could not name XXE, deserialization, or SSTI.

## The gap this lab exposed

`finding_model.py` had `ssrf`, `rce`, and `lfi` but no vocabulary for the other
three core server-side classes. Added:

| Class | CWE | Catches |
|-------|-----|---------|
| `xxe` | 611 | XML external entities → file read / SSRF |
| `deserialization` | 502 | unsafe pickle/unserialize/yaml.load → RCE gadgets |
| `ssti` | 1336 | server-side template / expression-language injection |

Each with CVSS + ≥3 remediation references (OWASP/PortSwigger/CWE). Re-score:
**7/7, 100% precision**, and **no regression** (Lab 01 still 15/15, Lab 02 still
12/12).

## Recon win (the crawling upgrade)

This lab doubled as a test of the directory-crawling improvement. RelayKit's home
is JSON, and its endpoints (`/fetch`, `/render`, `/internal/secrets`, …) appear
in **no** wordlist. Before the upgrade, `content_discovery` found nothing; after
adding **source-reference mining** (HTML + JS/JSON `fetch`/`axios`/XHR/path
strings) and **redirect-following**, it surfaced the live endpoints — including
the SSRF target `/internal/secrets` — directly from source. This is the
"see 100% of the surface" rule in action: wordlist-only recon would have missed
the entire application.

## Strong points confirmed

- The blind agent's server-side tradecraft was complete and chained well (SSRF →
  internal secrets, filter-bypass reasoning, XXE+LFI+file-SSRF all reaching the
  same file, gadget-resolution proof for deserialization).
- Safety-by-design held: command injection and deserialization were confirmed
  without any real code execution on the host.
