# Lab 01 — VulnShop — Results

Scoring the automated pentest pipeline against VulnShop's 15 planted vulns.
The pipeline ran **blind**: the exploitation agent received only the
recon-discovered endpoints, never the answer key.

## Method

1. **Recon (deterministic scripts)** — `passive_audit.py` (security headers,
   cookies, banners) + `content_discovery.py` (path/file discovery + signal
   emission) against `http://127.0.0.1:18801`.
2. **Exploitation (blind agent)** — a web-pentest agent actively tested every
   discovered endpoint/parameter for injection, access-control, redirect/SSRF,
   and info-disclosure bugs, confirming each with a live request (zero
   false-positive discipline) and writing one finding per confirmed vuln.
3. **Score** — `harness/score_lab.py` matched the findings against
   `gabarito.json` by class + route.

## Score

| Pass            | Recall        | Precision           | Notes |
|-----------------|---------------|---------------------|-------|
| First run       | 12/15 (80%)   | 85%                 | 3 misses — all **classifier** bugs, not detection failures |
| After fixes     | **15/15 (100%)** | **93% (1 bonus, 0 FP)** | all planted vulns matched + 1 bonus |

The single "extra" finding is **clickjacking** — a real issue the pipeline
surfaced beyond the answer key (bonus, not a false positive). Effective
precision is 100%.

## What the first pass missed — and why

The blind agent actually **found all 15 vulns** and wrote findings for them. The
three "misses" were the reporting engine **mis-classifying** correct findings,
which is exactly the kind of gap this campaign is meant to surface:

| Planted | Root cause | Fix |
|---------|-----------|-----|
| **V03 backup** (`/backup.sql`) | The finding's evidence (a SQL dump) contained `password`, and `classify()` read title **+ evidence**; the `creds` regex precedes `backup`, so it was relabeled `creds` and merged into the `.env` finding. | **Title-first classification**: classify on the specialist's title first, fall back to body only when the title is generic. |
| **V07 info-disc** (`/product?id=abc`) | The verbose-error finding's evidence showed a SQL error, so full-text classify hit `sqli` and merged it away. Its title alone hit `aspnet-leak` (regex too greedy: matched generic "verbose error" / "stack trace"). | Title-first classify **+** tightened `aspnet-leak` to ASP.NET-specific markers **+** broadened `info-disc` to catch `verbose error` / `traceback` / `stack trace`. |
| **V14 open-redirect** (`/redirect?url=`) | There was **no open-redirect class** at all — it fell through to `other`. | Added an `open-redirect` class (CWE-601) with its own CVSS vector and ≥3 remediation references. |

All fixes landed in the shared engine `finding_model.py`
(`tools/templates/deliverable/dashboard/`) — so they benefit every future
engagement, not just this lab.

## Secondary observations (logged, not recall-affecting)

- **Passive cookie check is root-only.** `passive_audit.py` flags insecure
  cookies on the landing response, but VulnShop only sets its session cookie on
  a successful `POST /login`. The exploitation agent caught V06 (it inspected
  `Set-Cookie` after authenticating), so recall was unaffected — but passive
  recon alone would miss cookies set only on authenticated responses.
- **Engagements snapshot the engine.** Engagement scaffolding copies the
  dashboard engine (`finding_model.py`, `generate_manifest.py`) into the
  engagement folder for reproducibility, so engine fixes must be re-synced into
  an in-flight engagement before re-scoring.

## Strong points confirmed

- Recon reliably surfaced every file/path exposure (`.git`, `.env`,
  `backup.sql`, dir-listing, admin panel) and emitted the right signals.
- The blind exploitation agent confirmed injection, access-control,
  redirect/SSRF, and info-disclosure bugs with live evidence and **no false
  positives** — it even correctly ruled out SQLi on `/search` (reflection only)
  and noted the session cookie value was *predictable/forgeable*
  (`user-<id>-<role>`), a bonus depth beyond the planted bug.
- Severity calibration + per-class remediation references rendered correctly
  for all classes, including the newly added `open-redirect`.
