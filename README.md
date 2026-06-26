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
| 09 | [InjectArena](labs/09-injectarena/) | Beyond-SQL injection (NoSQL operator, LDAP, XPath, SSI, CSV/formula) | 5 |
| 10 | [UploadForge](labs/10-uploadforge/) | File-upload surface — unrestricted upload → webshell → RCE, default-creds chain, traversal read, SVG stored-XSS, IDOR | 7 |
| 11 | [LegacyPortal](labs/11-legacyportal/) | PHP LFI-wrapper machinery — `php://filter` source disclosure, path traversal, upload→LFI→RCE polyglot, phpinfo, PHP type-juggling auth bypass | 6 |
| 12 | [CloudPivot](labs/12-cloudpivot/) | **Chaining** — SSRF → cloud IMDS instance-role credential theft → token reuse → RCE (each step gates the next), + verbose errors | 5 |
| 13 | [AspNetVault](labs/13-aspnetvault/) | .NET / IIS — exposed `web.config` (connectionStrings + machineKey), ViewState deserialization, ASP.NET trace viewer, version banners | 5 |
| 14 | [ClientForge](labs/14-clientforge/) | Client-side — DOM XSS (`location.hash`→`innerHTML`), prototype pollution, DOM open-redirect, hardcoded secret in JS, missing CSP | 5 |
| 15 | [RaceVault](labs/15-racevault/) | Business logic — genuine **race condition** (TOCTOU voucher double-spend via concurrent requests), IDOR, mass-assignment, no-rate-limit | 5 |
| 16 | [SamlForge](labs/16-samlforge/) | SSO / SAML — assertion signature not verified (auth bypass), XXE via SAMLResponse, RelayState open-redirect, verbose errors | 5 |
| 17 | [OAuthForge](labs/17-oauthforge/) | OAuth 2.0 / OIDC — unvalidated `redirect_uri` (code theft), missing `state` (CSRF), auth-code reuse + PKCE downgrade + no client auth | 5 |
| 18 | [JavaForge](labs/18-javaforge/) | Native **Java deserialization** (`rO0AB` session/`/api/restore` → ysoserial gadget → RCE), Tomcat default creds, Java stack traces, EOL stack | 5 |

**126 planted vulnerabilities across 18 labs.** More on the way (native
deserialization, request smuggling, GraphQL-advanced).

> Labs 01–10 are single-file stdlib **Python** (`python labs/NN/app.py`). Lab 11 is
> **PHP** (`labs/11-legacyportal/serve.sh` / `serve.ps1`) and needs PHP on PATH.

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
| 09 InjectArena | 0% | **100%** | no NoSQL/LDAP/XPath/SSI/CSV-injection classes |
| 10 UploadForge | 86% | **100%** | upload→RCE detected but classified `rce`; `upload` must beat generic `rce` |
| 11 LegacyPortal | 67% | **100%** | PHP type-juggling auth had no class vocab; LFI `?page=` had no recon signal |
| 12 CloudPivot | 60% | **100%** | plugin chained SSRF→IMDS→RCE; IMDS cred-theft mis-classed as `ssrf`; error-fuzzing missed malformed URL ports |
| 13 AspNetVault | 60% | **100%** | full .NET recon worked blind; `rce` had to move last so "ViewState deser→RCE" keeps its root cause |
| 14 ClientForge | 60% | **100%** | new `prototype-pollution` class; `xss` didn't recognise DOM XSS (no `\bxss\b`/DOM vocab) |
| 15 RaceVault | 80% | **100%** | plugin fired concurrent requests + found the TOCTOU race; needed a new `race-condition` class |
| 16 SamlForge | 80% | **100%** | blind agent did the full SAML tamper/strip/XXE chain; SAML sig-bypass mis-classed as `jwt` (regex too greedy) |
| 17 OAuthForge | 40% | **100%** | blind agent did the full OAuth chain; needed a new `csrf` class + OAuth token-flaw vocab in `auth` |
| 18 JavaForge | 60% | **100%** | recognised `rO0AB` Java deser blind; `rce` had to become the last impact class (default-creds→RCE kept root) |

That loop — *measure → find the blind spot → fix → re-measure* — is exactly what
PentestBench is for, whatever agent you bring. The pattern held in all ten labs:
**the agent detects nearly everything on the first pass; the gap is its report
engine failing to *name/classify* what it found.**

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
