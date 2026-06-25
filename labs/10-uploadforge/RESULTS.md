# Lab 10 — UploadForge — Results

Scoring the DroidAgent plugin against UploadForge's 7 planted vulns. The plugin
ran the **full pipeline** (engage-init → passive_audit + content_discovery →
specialist_dispatcher → Fase-4 specialists), with the exploitation agents **blind**
— live target + the plugin's own knowledge base only, never the answer key.

## Method

Four blind Fase-4 specialists ran in parallel (RCE-hunter, ATO/auth-hunter,
IDOR/BFLA, injection/client-side). The RCE-hunter — which the web methodology
mandates always chase upload→webshell→RCE — logged in with the default
`operator:operator`, uploaded a `{{exec:…}}` template (no validation accepted it),
and rendered it for live command execution (`whoami`→`eep0x10`, `id`→uid…). All 7
planted vulns were confirmed with live requests, plus 6 genuine bonus findings
(BFLA on `/render`, predictable sequential session tokens, no rate-limit, insecure
cookies, internal-token leak, clickjacking). `score_lab.py` matched by class+route.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **6/7 (86%)** | 43% | upload→RCE detected but **classified `rce`**, not `upload`; one bonus finding fell to `other` |
| After fix | **7/7 (100%)** | 54% | upload class restored; bonus findings get canonical classes. Precision <100% = 6 real bonus findings, **zero false positives** |

The plugin **detected everything on the first pass — including the full
upload→webshell→RCE chain.** The gap was, once again, **classification**, not
detection.

## The gaps this lab exposed (3 real `finding_model` fixes)

1. **`upload` must beat `rce`.** The crown-jewel finding — "Unrestricted File
   Upload leading to Remote Code Execution (webshell)" — hit the generic `rce`
   regex (`remote code`) first, because `rce` preceded `upload` in the class list.
   So the plugin's #1 RCE priority was *found but mis-categorized* (and scored as a
   miss). Fix: moved `upload` **before** `rce` and broadened its regex to keep the
   canonical class `upload` even when the title states the RCE *impact*. A pure
   command-injection RCE ("OS Command Injection") has no upload words and still
   classifies as `rce` (Lab 03 unchanged). *Same specific-before-generic rule as
   nosqli-before-sqli.*

2. **Broken-access-control vocabulary.** A bonus finding ("Unauthenticated Access
   to Uploaded Files", "Missing Object-Level Authorization") matched no class →
   `other`. Added a **late** catch (after the specific access-control and
   exposed-service classes, so it can't steal Lab 06) routing
   missing-auth / unauthenticated-access / broken-access-control leftovers to the
   `idor` object-access bucket.

3. **Session vocabulary too narrow.** "Session Tokens **Without Expiry** and **No
   Logout** Endpoint" required the regex to say "never expir"/"not invalidated" →
   fell to `other`. Broadened `session` to also catch "without expiry / no expiry /
   no logout endpoint". (Care taken: not over-broadening `predictable.*token`,
   which would steal Lab 02's "predictable password reset token" — an `auth`
   finding — verified by regression.)

Re-score: **7/7, no `other`-bucket findings, and no regression** — all 10 labs
remain 100% recall (Lab 02 back to 12/12 after the session-regex was tightened).

## The recon/dispatch gap this lab exposed (noted, not yet closed)

The deterministic front-end did **not** point at the upload vector on its own:
`content_discovery` surfaced only the GET-reachable `/myfiles` + `/render` (the
POST-only `/upload`, `/login` were filtered), and there is **no signal type** for
"file-upload endpoint" or "login form" — so the dispatcher emitted only the passive
clickjacking/headers specialists. The upload→RCE chain was carried entirely by the
blind RCE-hunter discovering `/upload` from the `/` index, exactly as the web
methodology mandates. That worked here, but a more robust pipeline would emit a
`file-upload-detected` / `auth-endpoint-detected` signal and auto-dispatch a
specialist rather than relying on the LLM specialist to find the vector. Logged as
the top follow-up improvement.

## Strong points confirmed

- The blind agents' tradecraft was complete and **chained**: default-creds → auth
  → unrestricted upload → server-side render → RCE, proven live.
- Safety-by-design held: the webshell executed only the read-only canary
  allow-list; non-canary commands were confirmed RCE-capable without running.
- Over-delivery, not noise: every "extra" finding was a real additional weakness
  (BFLA, predictable sessions, no-rate-limit, insecure cookies, token leak,
  clickjacking) — zero false positives.
