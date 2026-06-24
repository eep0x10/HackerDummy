#!/usr/bin/env python3
"""
score_lab.py — Mede o RECALL do DroidAgent contra o gabarito de um lab.

Compara as vulnerabilidades PLANTADAS (gabarito.json) com o que o plugin ACHOU
(dashboard/manifest.json do engagement), por classe canônica + rota. Reporta:
  - recall     = vulns do gabarito encontradas / total plantado
  - precision  = findings que casam o gabarito / total de findings
  - MISSED     = o que o gabarito tem e o plugin não achou (= gaps a melhorar)
  - EXTRA      = findings fora do gabarito (FP a investigar OU bônus achado a mais)

Uso:
  python score_lab.py --gabarito labs/01-vulnshop/gabarito.json --engagement <eng_dir>
  python score_lab.py --gabarito ... --engagement ... --json

Gabarito (schema): { "lab":..., "base_url":..., "vulns": [
   {"id":"V01","class":"sqli","severity":"critical","route":"/login","desc":"...","points":1}, ... ] }
`class` usa as CHAVES CANÔNICAS do finding_model (sqli, xss, stored-xss, idor, creds,
scm, backup, dir-listing, headers, clickjacking, cookie, trace, open-redirect, ssrf,
rce, lfi, info-disc, actuator, admin-panel, version, web-config, phpinfo, mod-status).
route="*" ou "/" = vuln a nível de host (casa qualquer finding da classe no host).
"""
import argparse
import json
import sys
from pathlib import Path


def _route_match(vuln_route, finding_routes, base_host):
    if vuln_route in ("*", "/", ""):
        return True  # host-level
    vr = vuln_route.split("?")[0].rstrip("/").lower()
    for r in finding_routes:
        rr = r.split("?")[0].rstrip("/").lower()
        if vr and (vr in rr or rr.endswith(vr)):
            return True
    return False


def score(gabarito_path, eng_dir):
    gab = json.loads(Path(gabarito_path).read_text(encoding="utf-8"))
    vulns = gab.get("vulns", [])
    man_path = Path(eng_dir) / "dashboard" / "manifest.json"
    findings = []
    if man_path.exists():
        try:
            findings = json.loads(man_path.read_text(encoding="utf-8", errors="ignore")).get("findings", [])
        except Exception:
            findings = []

    base_host = (gab.get("base_url", "") or "").split("//")[-1].split("/")[0]
    matched_vulns, missed = [], []
    used_findings = set()
    for v in vulns:
        hit = None
        for i, f in enumerate(findings):
            if f.get("class") == v["class"] and _route_match(v.get("route", "*"),
                                                             f.get("routes", []) or [f.get("host", "")], base_host):
                hit = f; used_findings.add(i); break
        (matched_vulns if hit else missed).append((v, hit))

    extras = [f for i, f in enumerate(findings) if i not in used_findings]
    total = len(vulns)
    found = len(matched_vulns)
    recall = (found / total) if total else 0.0
    precision = (len(used_findings) / len(findings)) if findings else 0.0
    return {
        "lab": gab.get("lab"), "total_planted": total, "found": found,
        "recall": round(recall, 3), "precision": round(precision, 3),
        "findings_total": len(findings),
        "matched": [{"id": v["id"], "class": v["class"], "route": v.get("route"),
                     "finding": f.get("id")} for v, f in matched_vulns],
        "missed": [{"id": v["id"], "class": v["class"], "route": v.get("route"),
                    "severity": v.get("severity"), "desc": v.get("desc")} for v, _ in missed],
        "extra_findings": [{"id": f.get("id"), "class": f.get("class"),
                            "title": f.get("title"), "routes": f.get("routes")} for f in extras],
    }


def main():
    ap = argparse.ArgumentParser(description="Score recall do DroidAgent vs gabarito do lab.")
    ap.add_argument("--gabarito", required=True)
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    r = score(args.gabarito, args.engagement)
    if args.json:
        print(json.dumps(r, indent=2, ensure_ascii=False)); return 0
    print(f"# Lab {r['lab']} — RECALL {r['found']}/{r['total_planted']} "
          f"({r['recall']*100:.0f}%) · precision {r['precision']*100:.0f}% "
          f"({r['findings_total']} findings)")
    print(f"\n## ENCONTRADAS ({len(r['matched'])})")
    for m in r["matched"]:
        print(f"  [OK]   {m['id']:<4} {m['class']:<14} {m['route'] or '*':<22} -> {m['finding']}")
    print(f"\n## MISSED ({len(r['missed'])}) — gaps a melhorar")
    for m in r["missed"]:
        print(f"  [MISS] {m['id']:<4} {m['class']:<14} {m['route'] or '*':<22} [{m['severity']}] {m['desc']}")
    if r["extra_findings"]:
        print(f"\n## EXTRA ({len(r['extra_findings'])}) — fora do gabarito (FP ou bônus)")
        for e in r["extra_findings"]:
            print(f"  [?]    {e['class']:<14} {(e['title'] or '')[:46]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
