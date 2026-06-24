# Lab 03 — RelayKit

> ⚠️ **INTENTIONALLY VULNERABLE — LOCALHOST TRAINING ONLY.**
> Real server-side exploitation bugs on purpose. Binds to `127.0.0.1`.

## What it is

**RelayKit** is a fake internal "integration gateway" for practicing
**server-side exploitation**: SSRF, XXE, insecure deserialization, OS command
injection, path traversal/LFI, and SSTI. Single self-contained Python file,
stdlib only. Runs on `127.0.0.1:18803`.

### Safety-by-design

So the lab can't damage the host while staying faithful, the two most dangerous
primitives are confirmable but neutered:

- **`/restore` (deserialization)** resolves the malicious pickle gadget — proving
  the bug — but **refuses to execute** it (`resolved_gadget` is reported instead).
- **`/ping` (command injection)** executes only a **read-only canary allow-list**
  (`whoami`/`hostname`/`id`/`ver`/`echo`); anything else is intercepted.
- **`/render` (SSTI)** leaks data via format-string injection; it does not exec.

The SSRF / XXE / LFI primitives are genuine (read-only disclosure).

## How to run

```bash
python app.py        # -> http://127.0.0.1:18803
```

No deps. `GET /` lists the endpoints. There's a server-only `/internal/secrets`
endpoint (refuses non-loopback callers) that the SSRF/XXE bugs are meant to reach.

## Planted vulnerabilities

Answer key: [`gabarito.json`](gabarito.json). 7 vulns, 1 point each.

| ID  | Class           | Sev      | Route          | How to exploit |
|-----|-----------------|----------|----------------|----------------|
| SS1 | ssrf            | high     | `/fetch?url=`  | Server fetches any URL → reach `/internal/secrets` (DB pwd, AWS key, token). Also accepts `file://` → local file read. |
| SS2 | ssrf            | high     | `/preview?url=`| Same, but behind a **case-sensitive** blocklist of `127.0.0.1`/`localhost` → bypass with `http://LocalHost:18803/internal/secrets`. |
| XX1 | xxe             | high     | `/import-xml`  | XML parsed with external entities enabled → `<!ENTITY x SYSTEM "file:///…/secret.txt">` reads local files (and SSRF via `http` SYSTEM entities). |
| DS1 | deserialization | critical | `/restore`     | base64 → `pickle.loads` of attacker input. A `__reduce__`→`os.system` gadget is resolved (RCE in a real deploy; exec blocked here for safety). |
| RC1 | rce             | critical | `/ping?host=`  | `host` concatenated into a shell command → `?host=x;whoami` runs the canary and returns its output. |
| LF1 | lfi             | high     | `/download?file=` | Path joined to `files/` without normalization → `?file=../secret.txt` (or `../../…`) reads arbitrary files. |
| ST1 | ssti            | high     | `/render?name=`| `name` concatenated into a `.format()` template → `?name={config[SECRET_KEY]}` leaks the app secret. |

## Suggested attack walk-through

1. **Map internal:** SSRF on `/fetch` → `/internal/secrets` dumps DB/AWS/token.
2. **Beat the filter:** `/preview` blocks `127.0.0.1`; send `LocalHost` (case)
   to reach the same internal endpoint.
3. **Read the disk:** XXE on `/import-xml` and traversal on `/download` both
   read `secret.txt`; `/fetch?url=file://…` does it via SSRF.
4. **Code execution:** command injection on `/ping`; insecure deserialization on
   `/restore` (gadget resolved).
5. **Leak config:** SSTI on `/render` prints `SECRET_KEY`.

## Notes / design

- `/internal/secrets` enforces a loopback-only check so the SSRF is meaningful
  (an external attacker can't hit it directly — only *through* the gateway).
- Lab files (`secret.txt`, `files/report.txt`) are created on first run.
- Classic web-injection lives in [Lab 01](../01-vulnshop/); auth/JWT in
  [Lab 02](../02-vaultauth/).
