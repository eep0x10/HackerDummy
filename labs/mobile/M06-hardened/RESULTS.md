# M06 — VaultSecure / Hardened — Results

The capstone. A banking-grade hardened app — correct OkHttp pinning, a native
anti-tamper lib, ProGuard/R8 obfuscation — hiding three real flaws. Run **blind
through `droidagent-mobile`** (Agent A Protection Mapper), reading the plugin's
`Reverse Engineering.md`, `SSL Pinning.md`, `Root Detection Bypass.md`,
`Crypto and Tokens.md` knowledge.

## Result: 3/3 (100%), precision 100% — full marks on the hardest rung

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| baseline | 2/3 | — | the RASP-backdoor finding was stolen by `exported-component` (it names the exported delivery) |
| after fix | **3/3 (100%)** | **100%** | every finding correct; **no strong control mis-reported** |

This rung tests two things at once — *find the flaws despite hardening*, and
*don't false-positive the strong controls*. The specialist:

- recovered the **base64 HMAC secret** from the **obfuscated** class `a/c` and
  **independently base64-decoded it** to confirm (didn't trust the comment);
- flagged the **exported QA/debug Activity** left in the release;
- found the **`qa_disable_checks` soft-toggle backdoor** that short-circuits the
  whole RASP, and **chained** it to the exported activity that flips the flag;
- and correctly judged the **OkHttp `CertificatePinner`** and the **native
  `libtamper.so`** as **STRONG — and did not report them.** Precision 100%.

## The gap this lab exposed

No new class (the capstone reuses `creds` / `exported-component` /
`weak-anti-tampering`). One ordering fix:

- **`weak-anti-tampering` moved before `exported-component`**, and given explicit
  `backdoor` / `short-circuit` / `soft-toggle` / `disable` vocab. The RASP-backdoor
  finding named the exported component that flips it, so the IPC class stole it; the
  root cause is the **protection-mechanism failure**, which now wins. A pure
  exported-activity finding (no RASP terms) still classifies `exported-component`.

Full regression after the fix: **all 6 mobile labs 100%** (M01 5/5, M02 4/4, M03 3/3,
M04 3/3, M05 3/3, M06 3/3) and **all 30 web classes unchanged**.

## Run it

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M06-hardened/gabarito.json \
  --findings your_agent_findings.json
```
