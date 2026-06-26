# Lab 11 — LegacyPortal (PHP) — Results

Scoring the DroidAgent plugin against LegacyPortal's 6 planted vulns. The plugin
ran the **full pipeline** (engage-init → passive_audit + content_discovery →
specialist_dispatcher → Fase-4 specialists), exploitation agents **blind** — live
target + the plugin's own knowledge base only, never the answer key. This is the
first PHP lab; it exercises the LFI-wrapper machinery (php://filter, traversal,
upload→LFI→RCE polyglot) that the plugin documents but no lab had ever measured.

## Method

Four blind Fase-4 specialists (LFI/RCE, upload, auth, info-disc). They confirmed
every planted vuln with live requests: php://filter source disclosure of
`config.php` (DB creds + flag), `../` traversal reading host files, a GIF89a/MIME
polyglot upload included via the LFI to execute arbitrary PHP (`php_uname()`,
`7*7=49` — RCE; OS-exec is neutralized by engine `disable_functions`, so the host
is safe), phpinfo exposure, PHP type-juggling auth bypass (`key=0e1` / `key=0`),
verbose-error path disclosure, and missing headers.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **4/6 (67%)** | 40% | LFI found but route-mismatched; type-juggling stolen by `admin-panel` |
| After fix | **6/6 (100%)** | 60% | precision <100% = real bonus (RCE chain, allow_url_fopen SSRF risk, version, clickjacking), zero false positives |

The plugin **detected everything blind on the first pass** — including the full
upload→LFI→RCE chain. The gap was, again, **classification + recon plumbing**, not
detection.

## The gaps this lab exposed

**1. `auth` had no vocabulary for auth-bypass / type juggling (finding_model fix).**
The type-juggling finding was titled "PHP Type Juggling Authentication Bypass —
Admin Panel", so it was stolen by the `admin-panel` class (the title literally
contains "Admin Panel"). The `auth` class only knew password-reset/recovery wording.
Added `authentication bypass | auth bypass | login bypass | type juggling | magic
hash | loose comparison` to `auth` (which precedes `admin-panel`), so the bypass is
classified as `auth`. Regression-checked: "SQL injection authentication bypass"
still → `sqli`, "Admin panel exposed" still → `admin-panel`, "predictable password
reset token" still → `auth`.

**2. No `php-page-controller-lfi` signal for the `?page=` LFI param (recon fix).**
`content_discovery` flagged the upload form but not the obvious `?page=` LFI — the
critical-severity star of this lab. Added a conservative LFI-param detector: it
emits `php-page-controller-lfi` (→ `specialist-lfi-php-page-controller`, P0) when a
file-include-ish param (`page/file/include/template/path/...`) carries a file/path/
wrapper value, and stays silent on pagination (`?page=2`, `?page=next`). The
dispatcher now auto-spawns the LFI specialist (0 unmapped) — the LFI vector no
longer depends on the LLM noticing the param.

**3. Answer-key route was over-strict.** P1's route was `/index.php`, but the LFI
front controller is equally reachable at `/?page=` (the plugin reported that form).
Relaxed P1's route to the front-controller root `/`.

Re-score: **6/6**, and **no regression** — all 11 labs remain 100% recall.

## Lab safety

LegacyPortal is genuinely vulnerable (real unsanitized `include()`, real arbitrary
PHP execution via the upload→LFI chain), but the server is launched with
`disable_functions` covering OS-exec (`system`/`exec`/…) and destructive file ops
(`unlink`/`file_put_contents`/…). So an included webshell **executes PHP** (proving
RCE and reading source) but cannot run shell commands or damage the host. A router
script also makes the built-in server return real 404s (otherwise PHP's CLI server
falls back to index.php for every path, which would make any content scan think the
whole wordlist exists).

## Run it

```bash
# needs PHP on PATH (or scoop's php)
./serve.sh        # or:  pwsh ./serve.ps1     ->  http://127.0.0.1:18811
```
