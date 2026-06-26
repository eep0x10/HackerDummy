# Lab 14 — ClientForge — Results

The first **client-side** lab — the entire browser-side attack surface that the
previous 13 (server-focused) labs never touched. Every bug lives in the HTML/JS the
server hands out and executes in the victim's browser, so it's found by **source →
sink analysis of the served code**, exactly how DOM XSS, prototype pollution, DOM
open-redirect and secrets-in-JS are discovered in a real engagement.

## Method

The plugin ran the full pipeline; the exploitation agent ran **blind** and (since
these vulns don't surface over plain HTTP responses) found them by fetching every
page + `<script>` and statically tracing data flow. It read `/search.html`,
`/profile.html`, `/go.html`, and `/static/app.js` and identified each source→sink.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **3/5 (60%)** | 50% | DOM XSS classified `other`; prototype pollution had no class (fell to `2fa-bypass` via body text) |
| After fix | **5/5 (100%)** | 83% | extra (clickjacking) is real bonus, zero false positives |

The blind agent **detected all five client-side bugs** by reading the JS. Both
misses were classification — including one brand-new class.

## The gaps this lab exposed

**1. New class: `prototype-pollution` (CWE-1321).** The agent found the unguarded
recursive `merge()` and the `?prefs={"__proto__":...}` flow, but neither
`finding_model.py` nor the benchmark `classify.py` had a prototype-pollution class,
so it fell through to `other` and then to `2fa-bypass` (its impact text mentioned
"2FA bypass" via the gadget, and body-fallback matched). Added the class to both,
with CWE-1321 + OWASP/PortSwigger references.

**2. `xss` didn't recognise DOM XSS (finding_model ↔ classify.py divergence).**
`finding_model`'s `xss` regex was `reflect.*xss | cross-site script | reflected.*script`
— it had **no `\bxss\b` and no DOM vocabulary**, so "DOM-Based XSS" classified as
`other` (while the benchmark `classify.py` already matched it via `\bxss\b`). Added
`dom.?based.?xss | dom.?xss` to `finding_model`.

**A trap avoided:** the obvious fix (add bare `\bxss\b`) *regressed* the open-redirect
finding — its title was "DOM-Based Open Redirect (escalation to **XSS** via
`javascript:`)", and a greedy `\bxss\b` stole it into the `xss` bucket. So the XSS
match is intentionally restricted to DOM/reflected/cross-site qualifiers, never a
bare "XSS" substring — the open-redirect (root cause) keeps its class while the DOM
XSS finding still matches. Verified across all 14 labs; no regression.

## Lab note

Static, stdlib-Python-served HTML/JS. The bugs are real client-side sinks
(`location.hash`→`innerHTML`, unguarded `merge()` of `?prefs=`, `location.href`←
`?next=`, hardcoded key in `app.js`); they execute in a browser, which is why
detection is source-review based. Secret-shaped strings are non-functional placeholders.

## Run it

```bash
python labs/14-clientforge/app.py        # -> http://127.0.0.1:18814
```
