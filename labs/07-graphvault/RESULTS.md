# Lab 07 — GraphVault — Results

Scoring the pipeline against a GraphQL API with 8 planted vulns. The agent ran
**blind** — given only the `/graphql` endpoint (which recon source-mined from the
JSON index), never the answer key.

## Score

| Pass        | Recall        | Precision | Notes |
|-------------|---------------|-----------|-------|
| Baseline    | **6/8 (75%)** | 86%       | idor/excessive-data/bfla/no-rate-limit/sqli/info-disc classified |
| After fix   | **8/8 (100%)**| 100%      | +2 classes (graphql, dos) |

The blind agent confirmed all 8 (introspection schema dump, BOLA, full-table
excessive exposure, BFLA `makeAdmin`, batched-alias brute force, depth-16 query →
3.6 MB response, SQLi via the `search` filter arg, field-suggestion leakage).
Zero false positives.

## The gap this lab exposed

The engine already covered the *transport-agnostic* bugs that show up in GraphQL
(BOLA→`idor`, BFLA→`bfla`, excessive data→`excessive-data`, batching→
`no-rate-limit`, arg→`sqli`, verbose errors→`info-disc`). The two **GraphQL-shaped**
issues had no home:

| Class | CWE | Catches |
|-------|-----|---------|
| `graphql` | 200 | introspection enabled, schema exposure, GraphQL-specific misconfig |
| `dos` | 400 | uncontrolled resource consumption — query depth/complexity, amplification, missing limits |

Both kept deliberately **narrow** so they wouldn't poach neighbours: the
`graphql` regex matches introspection/`__schema` only (not "batching", so the
batched-brute finding stays `no-rate-limit`), and neither touches the
field-suggestion finding (stays `info-disc`). Re-score: **8/8, 100%**.

## A regression the harness caught before it shipped

The first attempt at the `dos` class referenced the module-level `_CS` URL prefix
**inside the CLASSES list** — but `_CS` is defined later in the file, so importing
`finding_model` raised `NameError` and `build_findings` silently fell back to the
legacy parser. The full-campaign regression sweep flagged it instantly: **all
seven labs dropped to 0%** in one run. Fixed (literal URL in the inline ref) and
re-verified. A broken classifier engine would have degraded *every real
engagement* — the answer-key loop caught it in seconds. That safety net is a
large part of why this campaign exists.

## Regression

After the fix: Labs 01-06 all unchanged (15/15, 12/12, 7/7, 9/9, 7/7, 8/8).

## Strong points confirmed

- Recon source-mined `/graphql` from the JSON index (no wordlist hit needed).
- The blind agent demonstrated real GraphQL tradecraft: introspection-driven
  schema mapping, alias batching, exponential depth amplification, and
  injection through a typed argument.
