# M04 — DeepLinkForge (Android)

Rung 4: the **IPC / deep-link** surface — how other apps and web pages reach into
this one. Three classic inter-component flaws.

## Artifact

Decompiled **apktool tree** at [`app/`](app/). See [`../MOBILE.md`](../MOBILE.md).

```
app/
  AndroidManifest.xml                       # exported DeepLink/Dashboard activities + provider
  smali/com/dlforge/app/
    DeepLinkActivity.smali                    # Intent.parseUri(link target) + startActivity
    FilesProvider.smali                       # openFile() path traversal, no ../ check
    DashboardActivity.smali                   # exported authenticated screen, no auth check
```

> Intentionally vulnerable, training only.

## Planted vulnerabilities (3)

| id | class | severity | evidence |
|----|-------|:--------:|----------|
| D1 | `deeplink` | high | exported BROWSABLE `DeepLinkActivity` → `Intent.parseUri(target)` + `startActivity` (intent redirection) |
| D2 | `lfi` | high | exported `FilesProvider.openFile` builds a path from the URI with no `../` check (sandbox traversal) |
| D3 | `exported-component` | high | `DashboardActivity` (authenticated screen) exported, no permission, no auth check → login bypass |

Details in [`gabarito.json`](gabarito.json).

## Analyze & score

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M04-deeplinkforge/gabarito.json \
  --findings your_agent_findings.json
```
