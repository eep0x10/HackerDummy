# M03 — NetForge — Results

Rung 3: broken TLS trust + dangerous WebView. Run **blind through the DroidAgent
plugin's `droidagent-mobile` methodology** (Workflow C, Phase 2 — Agent A
Protection Mapper + Agent B Local Files Inspector), reading the plugin's own
mobile knowledge base (`SSL Pinning.md`, `Android Components.md`, `Common Vulns.md`).

## Result: 3/3 (100%) on the first pass

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| After taxonomy | **3/3 (100%)** | 33% | the 2 new classes landed clean; precision = bonus (per-evidence findings) |

The specialist produced **8 findings** and, beyond detection, **chained** them: a
BROWSABLE exported WebView whose `loadUrl` is taken from the intent + a JS bridge +
universal file access = a malicious web page fires `netforge://open?...`, loads
attacker JS, then calls `window.android.getToken()` / `readFile()` to steal the
session token and read arbitrary app files.

## The gap this lab exposed

**Two new classes** (synced `classify.py` + `finding_model.py` + `TAXONOMY.md`):

| class | CWE | signal |
|-------|-----|--------|
| `improper-tls` | 295 | trust-all `X509TrustManager` (empty `checkServerTrusted`), allow-all `HostnameVerifier`, missing pinning |
| `webview` | 749 | `addJavascriptInterface` bridge + `setAllowUniversalAccessFromFileURLs` + attacker-controlled `loadUrl` |

Both are anchored on TLS/WebView API names (`X509TrustManager`, `HostnameVerifier`,
`addJavascriptInterface`, `setAllowFileAccess…`) so they do **not** steal web
findings — "DOM XSS via JavaScript" stays `xss`, not `webview`. The exported WebView
host classified as `exported-component` (added at M01), which sits before `webview`
so the externally-reachable-activity finding keeps its root-cause class.

## Run it

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M03-netforge/gabarito.json \
  --findings your_agent_findings.json
```
