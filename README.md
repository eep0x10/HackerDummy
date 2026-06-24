# PentestBench

**A benchmark for evaluating AI/LLM agents at penetration testing.**

PentestBench is a set of **deliberately-vulnerable apps**, each shipped with an
**answer key** (`gabarito.json`) listing every planted vulnerability. You point
*your* AI agent at a lab **blind** (it never sees the answer key), collect what it
found, and score it — objectively — for **recall** (did it catch every vuln?) and
**precision** (were its findings real?).

It is **provider-agnostic**: run it against Claude, GPT/Codex, Cursor/Composer, a
local LLM, or your own custom pentest plugin. The findings format is plain JSON
and free-text labels are normalized automatically, so your agent just reports
what it found *in its own words*.

> ⚠️ Every app here is **intentionally vulnerable** and binds to `127.0.0.1`.
> Localhost training only. Never expose them; never reuse a seed credential.
> Secret-shaped strings are non-functional placeholders.

## Why it exists

You can't improve what you can't measure. Eyeballing a pentest report tells you
nothing about what the agent **missed**. PentestBench turns that into a number:

```
   build lab + answer key  →  run YOUR agent BLIND  →  score recall / precision
            ↑                                                      │
            └──────────────  fix the gaps the misses reveal  ◀─────┘
```

Use it to:
- **Evaluate** any AI's pentest quality on a known target.
- **Compare** agents/models/prompts head-to-head on the same labs.
- **Catch regressions** when you change a model, prompt, or tool.
- **Fine-tune**: the answer keys are ground-truth labels. An agent's *misses* and
  *false positives* are exactly the supervision signal you train on.
- **Track evolution**: re-run after each change and watch recall climb.

## Quick start (any agent, 3 steps)

```bash
git clone https://github.com/eep0x10/PentestBench
cd PentestBench

# 1. start a lab (stdlib Python, no dependencies)
python labs/01-vulnshop/app.py        # -> http://127.0.0.1:18801

# 2. point YOUR agent at the target URL, BLIND. Tell it to pentest the app and
#    output each finding it confirms. Save them as JSON (see format below).

# 3. score what it found against the answer key
python harness/score_lab.py \
  --gabarito labs/01-vulnshop/gabarito.json \
  --findings your_agent_findings.json
```

You get recall, precision, the exact vulns it **MISSED** (its blind spots), and
any **EXTRA** findings (false positives or genuine bonus). See a worked example:
[`examples/example-findings-vulnshop.json`](examples/example-findings-vulnshop.json).

## The findings format

A JSON list (or `{"findings": [...]}`). Each finding needs a **label** and a
**location** — keys are flexible so most agents' output drops in with little
massaging:

| | accepted keys |
|---|---|
| **label** | `class` (a canonical key) **or** free text in `title` / `vuln` / `vulnerability` / `name` / `type` / `description` |
| **location** | `route` / `url` / `endpoint` / `path` / `location` / `host` / `target` / `port` |

```json
[
  {"title": "SQL Injection (auth bypass)", "url": "http://127.0.0.1:18801/login"},
  {"vuln": "Exposed Redis without authentication", "port": 6379},
  {"class": "idor", "route": "/api/order"}
]
```

Free-text labels are mapped to canonical classes by
[`harness/classify.py`](harness/classify.py) — your agent does **not** need to
learn our class names. The canonical taxonomy is documented in
[`TAXONOMY.md`](TAXONOMY.md); matching is by **class + route** (a gabarito
`route` of `"*"` means host-level: any finding of that class counts).

## The labs

Each lab targets a different slice of the attack surface. Counts are the planted
vulns in that lab's answer key.

| # | Lab | Surface | Vulns |
|---|-----|---------|-------|
| 01 | [VulnShop](labs/01-vulnshop/) | Classic web injection (SQLi, XSS, IDOR, SSRF, open-redirect, exposed `.git`/`.env`/backup, dir-listing, headers, cookie, info-disc, admin) | 15 |
| 02 | [VaultAuth](labs/02-vaultauth/) | Auth / JWT / session (alg:none, weak secret, user-enum, no-rate-limit, OTP bypass, mass-assignment, MD5 storage, broken session) | 12 |
| 03 | [RelayKit](labs/03-relaykit/) | Server-side (SSRF + filter bypass, XXE, insecure deserialization, command injection, LFI, SSTI) | 7 |
| 04 | [ShopAPI](labs/04-shopapi/) | OWASP API Top 10 (BOLA, BFLA, mass-assignment, excessive data, JWT, rate-limit, SSRF, verbose errors) | 9 |
| 05 | [SpringVault](labs/05-springvault/) | Java/Spring Boot Actuator (`/env`+`/heapdump` mining, Jolokia, H2 console, cleartext creds) | 7 |
| 06 | [OpenServices](labs/06-openservices/) | Infra — unauth Redis/Elastic/Mongo/CouchDB/Docker/Memcached/MySQL + default creds | 8 |
| 07 | [GraphVault](labs/07-graphvault/) | GraphQL (introspection, BOLA, excessive data, BFLA, batching, depth DoS, SQLi, field suggestions) | 8 |
| 08 | [TrustEdge](labs/08-trustedge/) | Trust-boundary / header misconfig (CORS reflection, Host-header injection, X-Forwarded-Host, CRLF response splitting, cache poisoning) | 7 |

**73 planted vulnerabilities across 8 labs.** More on the way (cloud-metadata
SSRF, native deserialization, request smuggling).

## Using it for fine-tuning

The answer keys make every lab a **labeled dataset**:
- **Ground truth** = `gabarito.json` (each vuln's class + route + how to exploit).
- **Supervision** = run your agent, diff against the key. Its **misses** are
  hard negatives (it should have found these); its **false positives** are noise
  to penalize. Build SFT/DPO/RL signal from the gap.
- **Curriculum** = the labs span easy (file exposure) to subtle (JWT alg
  confusion, GraphQL depth DoS); order them to grow capability.
- **Regression gate** = require recall ≥ target on all labs before shipping a new
  model/prompt.

## Reference run — evolving one agent on PentestBench

As a worked case study, the benchmark's author ran their own pentest agent
through every lab and used the misses to drive improvements. The pattern held in
all 7 labs: **the agent detected nearly everything on the first pass; the gap was
its report engine failing to *name/classify* what it found.** Closing those gaps
took the agent from the baselines below to 100% recall:

| Lab | Baseline recall | After fixes | What the miss taught |
|-----|-----------------|-------------|----------------------|
| 01 VulnShop | 80% | **100%** | 3 classifier bugs |
| 02 VaultAuth | 8% | **100%** | no auth/JWT vocabulary at all |
| 03 RelayKit | 57% | **100%** | missing XXE / deserialization / SSTI classes |
| 04 ShopAPI | 67% | **100%** | missing BFLA / excessive-data classes |
| 05 SpringVault | 71% | **100%** | management-interface vs RCE classification |
| 06 OpenServices | 0% | **100%** | no infra (exposed-service / default-creds) vocabulary |
| 07 GraphVault | 75% | **100%** | missing GraphQL-introspection / DoS classes |
| 08 TrustEdge | 14% | **100%** | no header-trust vocabulary (CORS / Host / CRLF / cache) |

That loop — *measure → find the blind spot → fix → re-measure* — is exactly what
PentestBench is for, whatever agent you bring.

## Repo layout

```
labs/<NN-name>/
  app.py          # single-file, stdlib-only vulnerable app (no installs)
  gabarito.json   # answer key: every planted vuln (id, class, route, exploit)
  README.md       # what it is, how to run, the planted-vuln table
  RESULTS.md      # the reference run's score + what it exposed
harness/
  score_lab.py    # score any agent's findings vs an answer key
  classify.py     # standalone canonical taxonomy (free text -> class key)
examples/         # example findings files
TAXONOMY.md       # the canonical vulnerability class keys
```

## License

Educational / defensive-security use. Run only against systems you own or are
explicitly authorized to test.
