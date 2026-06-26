# Lab 13 — AspNetVault — Results

The first **.NET / IIS** lab — a faithful stdlib-Python *mock* of a legacy ASP.NET
Web Forms site, exercising classes and recon the previous 12 labs never touched:
an exposed **web.config** (connectionStrings + `<machineKey>`), **ViewState
deserialization**, the ASP.NET **trace viewer**, and ASP.NET version banners. It
finally drives the entire .NET wordlist (web.config, trace.axd, elmah.axd,
Default.aspx) that already lived in the recon engine.

## Method

The plugin ran the full pipeline; exploitation agents **blind**. Recon was the best
of the campaign: `content_discovery` detected `stack=aspnet` and emitted
`web-config-exposed` (→ specialist-config-secrets P0), `trace-axd-enabled` (→
specialist-aspnet-trace), `aspnet-version-disclosure`, `iis-legacy`,
`elmah-exposed`, and `login-form-detected` — 9 specialists, 0 unmapped. The blind
.NET specialist then extracted everything from web.config, proved ViewState MAC was
not enforced (tampered `__VIEWSTATE` accepted), reasoned the machineKey→ViewState
forge / ysoserial.net ObjectStateFormatter RCE path, and read trace.axd's server
variables (physical paths, `PORTAL\svc_web` service account).

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **3/5 (60%)** | 38% | ViewState deser classified `rce`; trace.axd classified as the niche `aspnet-leak` |
| After fix | **5/5 (100%)** | 62% | extras (elmah, eol, clickjacking) are real bonus, zero false positives |

The plugin **detected the whole .NET surface blind**. Both misses were
classification, and one of them forced a long-deferred structural fix.

## The gaps this lab exposed

**1. `rce` must be LAST among the code-exec classes (the big one).** The ViewState
finding was titled "ViewState Deserialization → RCE", so it hit the generic `rce`
class before `deserialization`. This is the same root-cause-vs-impact pattern as
upload-before-rce — but it had been latent since Lab 11 (whose LFI finding simply
didn't say "RCE" in its title). AspNetVault forced it. Fix: moved `rce` to **after**
upload/lfi/ssrf/xxe/deserialization/ssti, so a finding titled "`<X>` → RCE" keeps
its root cause and only a pure command-injection finding lands on `rce`. Verified:
"OS Command Injection" → `rce`, "ViewState Deserialization → RCE" → `deserialization`,
"LFI → RCE" → `lfi`, "Upload → RCE" → `upload`, "SSTI → RCE" → `ssti`. No regression
across all 13 labs (and Lab 11's precision improved — its LFI→RCE finding is now
`lfi`, not a stray `rce` extra).

**2. Plugin/benchmark taxonomy had diverged (`aspnet-leak`).** trace.axd disclosure
was classified by a plugin-only `aspnet-leak` class that the benchmark taxonomy
(`classify.py`) didn't have. The canonical, provider-agnostic class for it is
`info-disc`. Re-pointed the ASP.NET-diagnostic class key to `info-disc` (keeping the
descriptive label) and taught `classify.py` to map `trace.axd` / `asp.net trace` /
`elmah` → `info-disc`, restoring finding_model ↔ classify.py sync.

Re-score: **5/5**, all 13 labs still 100%.

## Lab note

This is a *mock* (stdlib Python, no .NET runtime) that reproduces the ASP.NET/IIS
attack **surface** so an agent's .NET recon + knowledge can be measured. Exploitation
primitives are gated for safety: a tampered/gadget `__VIEWSTATE` is recognised and
reported as RCE-capable (MAC not enforced) but never deserialized/executed;
machineKey and SQL password are non-functional placeholders.

## Run it

```bash
python labs/13-aspnetvault/app.py        # -> http://127.0.0.1:18813
```
