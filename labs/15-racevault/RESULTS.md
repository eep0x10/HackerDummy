# Lab 15 — RaceVault — Results

The first **business-logic** lab. It tests a *capability*, not a surface: can the
agent find a flaw that is invisible to one-request-at-a-time testing? The crown jewel
is a genuine **race condition** — the redeem endpoint has a real check-then-act
(TOCTOU) window with no lock, so only an agent that fires **concurrent** requests
finds it. The SKILL lists a business-logic specialist (race conditions / workflow
skip); no prior lab had ever measured it.

## Result: the plugin sent concurrent requests and won

Given a methodology-driven prompt (no hint that a race existed), the blind
business-logic specialist captured the before-state, fired ~30 **parallel**
`POST /redeem` of a single-use voucher, and observed the wallet over-credited
(BONUS25 valued 25 → balance +75 = redeemed 3×). It correctly diagnosed the missing
lock between the `used` check and the credit. That is the headline: the breadth-first
business-logic methodology genuinely exercises concurrency, not just sequential probes.

## Score

| Pass | Recall | Precision | Notes |
|------|--------|-----------|-------|
| Baseline | **4/5 (80%)** | 67% | the race was detected but had no class (`other`) |
| After fix | **5/5 (100%)** | 83% | extra (clickjacking) is a real bonus, zero false positives |

## The gap this lab exposed

**New class: `race-condition` (CWE-362).** The agent confirmed the TOCTOU
double-spend, but neither `finding_model.py` nor the benchmark `classify.py` had a
class for it, so it fell to `other`. Added the class to both (+ `TAXONOMY.md`),
matching `race condition | TOCTOU | check-then-act | double-spend | concurrent
<action>` wording, with CWE-362 + OWASP/PortSwigger references. The other four
planted bugs classified correctly out of the box (idor, mass-assignment,
no-rate-limit, headers).

## A bug the blind run found in the lab itself

On the first pass the specialist reported a **null-comparison auth bypass** I had
accidentally written: `USERS.get(u) == p` returns `None == None` for a non-existent
user with `"password": null`, minting a session for any name (plus a `KeyError` DoS
on the resulting ghost user). That is a real type-confusion bug — but unintended, and
it trivialised the app's auth and blocked clean testing of the mass-assignment path.
Fixed the lab to `u in USERS and p is not None and USERS[u] == p` and re-ran. (A nice
demonstration that the harness catches the lab author's mistakes too.)

## Lab note

In-memory play-money; nothing real is at stake. The race is genuine — a threaded
server with a real (small) TOCTOU window — so it reproduces only under concurrency,
exactly like the real bug class.

## Run it

```bash
python labs/15-racevault/app.py        # -> http://127.0.0.1:18815
# test accounts: alice/alicepw, bob/bobpw
```
