# Lab 19 — SmuggleForge — Results

The first **HTTP request smuggling** lab — and a *genuine* front-end/back-end desync,
not a mock. Two stdlib raw-socket tiers that deliberately disagree on body framing:
the front-end (target, :18819) delimits by `Content-Length` and blocks `/admin`; the
back-end (:18820, internal) honours `Transfer-Encoding: chunked` and serves `/admin`.
A CL.TE payload smuggles a request to the internal `/admin` past the front-end block.

## Result: the plugin performed a real desync attack

Given a methodology-driven prompt (no exploit handed over), the blind smuggling
specialist read the `Server` banners, inferred the two-tier architecture, diagnosed
**CL.TE**, wrote a byte-exact raw-socket request (Content-Length covering a smuggled
`GET /admin` after the `0\r\n\r\n` chunk terminator), and **recovered the internal
admin secret** that a direct `/admin` request 403s on. This is the deepest protocol
attack in the suite — genuine HTTP desync, done blind.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **2/3 (67%)** | 50% | the smuggling finding had no class (fell to `other`/`ssrf`) |
| After fix | **3/3 (100%)** | — | banner + missing-headers are the other two; zero false positives |

## The gap this lab exposed

**New class: `smuggling` (CWE-444).** The agent confirmed the CL.TE desync but neither
classifier had a request-smuggling class, so it fell through. Added `smuggling`
(request/response smuggling, CL.TE / TE.CL / TE.TE, HTTP desync, chunked-vs-CL
conflict) to both classifiers + `TAXONOMY.md`, placed next to `crlf` (and verified it
does NOT collide with CRLF/response-splitting). The other two planted findings
(`version` banner, missing `headers`) classified correctly out of the box.

## Lab note

The desync is real (two raw-socket servers with genuinely different body-framing
logic), so it reproduces only with byte-exact requests — exactly like the real bug.
The only "secret" is a lab flag; nothing executes code. The back-end 404s unknown
paths so a content scan doesn't see the whole wordlist as 200.

## Run it

```bash
python labs/19-smuggleforge/app.py     # front-end (target) -> http://127.0.0.1:18819
#                                        (back-end runs internally on 18820)
```
