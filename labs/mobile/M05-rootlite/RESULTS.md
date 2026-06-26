# M05 — RootLite — Results

Rung 5: the RASP entry point. Run **blind through `droidagent-mobile`** (Agent A
Protection Mapper), reading the plugin's `Root Detection Bypass.md`,
`Anti-Debug Bypass.md`, `FLAG_SECURE Bypass.md`, and `Frida.md` knowledge.

## Result: 3/3 (100%) on the first pass

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| After taxonomy | **3/3 (100%)** | 50% | precision = bonus (per-control findings + a logic-flaw catch) |

This rung tests a different skill: not just *detecting* a control, but **judging
its strength**. The specialist mapped all three anti-tampering checks and correctly
called each one naive/bypassable (single Java check, no native, no attestation),
flagged `debuggable=true` as undermining the lot, caught the missing `FLAG_SECURE`
on the PIN screen — and, as a bonus, spotted that `verifyPin()` ignores the PIN and
returns `isRooted()`, collapsing auth to one bypassable check. It excluded nothing
as "strong" because nothing was.

## The gap this lab exposed

**Two new classes** (synced `classify.py` + `finding_model.py` + `TAXONOMY.md`):

| class | CWE | signal |
|-------|-----|--------|
| `weak-anti-tampering` | 693 | naive/bypassable root / emulator / anti-debug / anti-Frida, no native/attestation |
| `screenshot-allowed` | 200 | sensitive screen missing `FLAG_SECURE` (screenshot/recording/recents capture) |

Both are anchored on RASP/`FLAG_SECURE` idioms (`isRooted`, `/system/bin/su`,
`Build.FINGERPRINT`, `Debug.isDebuggerConnected`, `FLAG_SECURE`) so they sit in the
mobile block and don't disturb the web `auth`/`session` classes.

## Run it

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M05-rootlite/gabarito.json \
  --findings your_agent_findings.json
```
