# M04 — DeepLinkForge — Results

Rung 4: the IPC / deep-link surface. Run **blind through the DroidAgent
`droidagent-mobile` methodology** (Agent A + Agent B), reading the plugin's
`Android Components.md` / `Common Vulns.md` knowledge.

## Result: 3/3 (100%), precision 100%

| Pass | Recall | Notes |
|------|--------|-------|
| baseline | 2/3 | the provider-traversal finding was stolen by `upload` ("arbitrary file"); D3 needed the consolidation |
| after fixes | **3/3 (100%)** | precision 100% — a perfectly clean run |

The specialist returned exactly 3 findings, one per pattern: intent redirection
(`Intent.parseUri`→`startActivity`), content-provider path traversal, and the
exported authenticated `DashboardActivity` (login bypass).

## The gaps this lab exposed

**One new class** — `deeplink` (CWE-939) — plus the two structural fixes the sweep forced:

1. **Mobile classes consolidated into one block before `auth` / `open-redirect` /
   `weak-crypto`.** A mobile "exported activity → **auth bypass**" finding was being
   stolen by the web `auth` class; `deeplink` must beat `exported-component` for a
   redirection finding; both must beat `open-redirect`. One ordered block fixes all
   of it (root cause beats impact, specific beats generic).
2. **`deeplink` scoped to redirection/forwarding semantics** (`Intent.parseUri`,
   "forwards an untrusted intent", "deep-link redirect/hijack") — not a bare
   "deep link" / "browsable", which was wrongly stealing M03's exported BROWSABLE
   WebView (that stays `exported-component`).
3. **`upload`'s `arbitrary file` → `arbitrary file (upload|write|creat)`** so the
   provider's "read **arbitrary files** via `../`" classifies as `lfi`, not `upload`.

After each fix, the full mobile + web regression was re-run: M01 5/5, M02 4/4,
M03 3/3, M04 3/3; web upload labs (10: 7/7, 11: 6/6) unchanged.

## Run it

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M04-deeplinkforge/gabarito.json \
  --findings your_agent_findings.json
```
