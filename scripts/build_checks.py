#!/usr/bin/env python3
"""
Render the human/LLM-readable reference files from the structured check library.

Source of truth: scripts/checks.data.json (one object per check). This script renders:
  - references/checks.md            full library, grouped by category, with a TOC
  - references/readme-redflags.md   fast readme-mode lookup, grouped by hole
  - references/ultra-categories.json machine-readable category list for the ultra workflow:
                                    per category, appliesTo + the trace/adversarial finder digest

To add or change checks: edit checks.data.json (or drop new findings in via a hardening
workflow), then run `python scripts/build_checks.py`. Do not hand-edit the two .md files;
they are generated and will be overwritten.

Usage: python scripts/build_checks.py
"""
import io
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "checks.data.json")
REFS = os.path.normpath(os.path.join(HERE, "..", "references"))

SEVMARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
SEVWORD = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
GENERATED = "<!-- generated from scripts/checks.data.json by scripts/build_checks.py — do not hand-edit -->\n\n"


def esc(s):
    return (s or "").replace("\n", " ").strip()


def build_checks_md(cats):
    total = sum(len(c["checks"]) for c in cats)
    o = io.StringIO()
    w = o.write
    w("# Git Gud Security — check library\n\n")
    w(GENERATED)
    w("The master list of holes this skill knows. Source of truth for `quick`, `full`, and "
      "`ultra` scans. Read the categories relevant to what you're scanning before you start; for "
      "a README-only pass use `readme-redflags.md` instead (it's the fast lookup).\n\n")
    w(f"**{total} checks across {len(cats)} categories.** `scripts/patterns.json` (the scanner's "
      "grep/config subset) links back here by `id`.\n\n")
    w("## How to read an entry\n\n")
    w("Each check carries a **severity** and a **detectability** tier. Detectability drives the "
      "modes — a mode runs the tiers it can afford:\n\n")
    w("- `readme` — inferable from README/marketing claims alone (every mode).\n")
    w("- `config` — visible in a config/manifest file (quick+).\n")
    w("- `grep` — single-file pattern match (quick+). Most are in `patterns.json`.\n")
    w("- `trace` — needs cross-file dataflow: is a sink reachable from user input (full+).\n")
    w("- `adversarial` — needs an attacker-mindset reviewer to confirm reachability (ultra).\n\n")
    w("**Severity:** `critical` = exploitable now by anyone. `high` = serious, needs a condition. "
      "`medium` = real but limited. `low` = hardening.\n\n")
    w("Always confirm a candidate at its `file:line` before reporting it. A signal is a lead, not "
      "a verdict.\n\n---\n\n## Categories\n\n")
    for i, c in enumerate(cats, 1):
        crit = sum(1 for x in c["checks"] if x["severity"] == "critical")
        w(f"{i}. [{c['title']}](#{c['key']}) — {len(c['checks'])} checks ({crit} critical)\n")
    w("\n---\n")
    for c in cats:
        checks = sorted(c["checks"], key=lambda x: SEV_ORDER.get(x["severity"], 9))
        w(f"\n<a id=\"{c['key']}\"></a>\n## {c['title']}\n\n")
        for x in checks:
            applies = ", ".join(x.get("appliesTo", []))
            w(f"**{esc(x['title'])}**  `{x['id']}`  \n")
            w(f"`{SEVMARK[x['severity']]}` · `{x['detectability']}` · {applies}  \n")
            sigs = x.get("signals", [])
            if sigs:
                w("- signals: " + " · ".join(esc(s) for s in sigs[:6]) + "\n")
            rfs = x.get("readmeRedFlags", [])
            if rfs:
                w("- readme red flags: " + " · ".join('"' + esc(r) + '"' for r in rfs[:4]) + "\n")
            if x.get("example"):
                w("- example: " + esc(x["example"])[:220] + "\n")
            if x.get("fix"):
                w("- fix: " + esc(x["fix"]) + "\n")
            w("\n")
    return o.getvalue()


def build_redflags_md(cats):
    o = io.StringIO()
    w = o.write
    holes = phrases = 0
    w("# README red flags — fast lookup for `readme` mode\n\n")
    w(GENERATED)
    w("Phrases and claims in a README / landing page / docs that betray a specific hole, grouped "
      "by hole. Seeing one makes the hole *likely* (mark it inferred, not confirmed, unless the "
      "README literally shows the vulnerable thing). Full detail is in `checks.md` under the `id`.\n\n")
    w("Scan the target's prose against these. Up to 3 most diagnostic phrasings per hole; the "
      "model generalizes from the pattern, so an inexact match still counts.\n\n")
    for c in cats:
        flagged = [x for x in sorted(c["checks"], key=lambda y: SEV_ORDER.get(y["severity"], 9))
                   if x.get("readmeRedFlags")]
        if not flagged:
            continue
        w(f"## {c['title']}\n\n")
        for x in flagged:
            seen = set(); clean = []
            for r in x["readmeRedFlags"]:
                k = esc(r).lower()
                if k and k not in seen:
                    seen.add(k); clean.append(esc(r))
            clean = clean[:3]
            holes += 1; phrases += len(clean)
            line = " · ".join(f'"{p}"' for p in clean)
            w(f"- **{esc(x['title'])}** `{x['id']}` · {SEVWORD[x['severity']]}\n  {line}\n")
        w("\n")
    return o.getvalue(), holes, phrases


# The tiers a live-repo finder agent should hunt. grep/config/readme-tier checks come pre-seeded
# from scan.py's deterministic sweep, so the LLM finders don't re-discover what the regex already
# found — they spend their budget on reachability the regex can't reason about.
FINDER_TIERS = ("trace", "adversarial")


def build_ultra_categories(cats):
    """Machine-readable category list the ultra workflow's launching agent selects from.

    Per category: the union of appliesTo signals (for repo-type gating) and a finderDigest of
    only the trace/adversarial-tier checks (what an LLM finder should hunt). A category whose
    finderDigest is empty (e.g. cicd, config-trust) is seed-only: covered by the deterministic
    scan, no finder agent spent on it.
    """
    out = []
    for c in cats:
        applies = sorted({s for x in c["checks"] for s in x.get("appliesTo", [])})
        digest = [
            {
                "id": x["id"],
                "title": esc(x["title"]),
                "severity": x["severity"],
                "detectability": x["detectability"],
                "signals": [esc(s) for s in x.get("signals", [])][:6],
            }
            for x in sorted(c["checks"], key=lambda y: SEV_ORDER.get(y["severity"], 9))
            if x["detectability"] in FINDER_TIERS
        ]
        out.append({
            "key": c["key"],
            "title": c["title"],
            "appliesTo": applies,
            "checkCount": len(c["checks"]),
            "finderTierCount": len(digest),
            "finderDigest": digest,
        })
    return {
        "generated_from": "scripts/checks.data.json",
        "note": "Generated by scripts/build_checks.py. The ultra workflow's launching agent reads "
                "this, selects categories by repo type (appliesTo) + the always-on set, and passes "
                "the selection into the workflow via args.categories. Do not hand-edit.",
        "finderTiers": list(FINDER_TIERS),
        "categories": out,
    }


def main():
    data = json.load(open(DATA, encoding="utf-8"))
    cats = data["categories"]
    cmd = build_checks_md(cats)
    open(os.path.join(REFS, "checks.md"), "w", encoding="utf-8").write(cmd)
    rmd, holes, phrases = build_redflags_md(cats)
    open(os.path.join(REFS, "readme-redflags.md"), "w", encoding="utf-8").write(rmd)
    uc = build_ultra_categories(cats)
    open(os.path.join(REFS, "ultra-categories.json"), "w", encoding="utf-8").write(
        json.dumps(uc, indent=1, ensure_ascii=False) + "\n")
    total = sum(len(c["checks"]) for c in cats)
    finder_total = sum(c["finderTierCount"] for c in uc["categories"])
    print(f"checks.md: {len(cmd.splitlines())} lines, {total} checks, {len(cats)} categories")
    print(f"readme-redflags.md: {len(rmd.splitlines())} lines, {holes} holes, {phrases} phrases")
    print(f"ultra-categories.json: {len(cats)} categories, {finder_total} finder-tier checks")


if __name__ == "__main__":
    main()
