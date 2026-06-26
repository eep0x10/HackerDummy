# M03 — NetForge (Android)

Rung 3: the **network-trust + WebView** layer — how a mobile app talks to its
backend, and how it renders untrusted web content, done wrong.

## Artifact

Decompiled **apktool tree** at [`app/`](app/). See [`../MOBILE.md`](../MOBILE.md).

```
app/
  AndroidManifest.xml                         # exported, BROWSABLE WebViewActivity
  smali/com/netforge/app/
    InsecureTrust.smali                         # trust-all X509TrustManager + allow-all hostname
    WebViewActivity.smali                       # JS + file access + bridge + loadUrl(intent url)
    JsBridge.smali                              # @JavascriptInterface getToken()/readFile()
```

> Intentionally vulnerable, training only.

## Planted vulnerabilities (3)

| id | class | severity | evidence |
|----|-------|:--------:|----------|
| N1 | `improper-tls` | high | `X509TrustManager` with empty `checkServerTrusted` + allow-all `HostnameVerifier`, no pinning |
| N2 | `webview` | high | JS enabled + `addJavascriptInterface` + `setAllowUniversalAccessFromFileURLs` + `loadUrl(intent.url)` |
| N3 | `exported-component` | high | `WebViewActivity` exported + BROWSABLE deep-link, loads the URL from the intent |

Details in [`gabarito.json`](gabarito.json).

## Analyze & score

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M03-netforge/gabarito.json \
  --findings your_agent_findings.json
```
