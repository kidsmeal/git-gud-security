#!/usr/bin/env python3
"""
Git Gud Security - enumerated baseline.

A baseline is the adoption mechanism: snapshot the findings a repo has today, then a later scan
fails only on findings that are NEW relative to the snapshot. This is deliberately an *enumerated*
list of exact findings, not an open-ended ignore-glob:

  - A glob ("ignore **/*.js secrets") suppresses an unbounded, unknowable future space — including
    a payload that hasn't been written yet. A baseline can't: a new finding isn't in the snapshot,
    so it still fails. To hide one, you have to regenerate the baseline, and the new entry then
    shows up in the baseline's own diff. Enumerated == tamper-evident; glob == silent.
  - So GGS ships no in-repo ignore file. The baseline is an explicit operator/CI artifact passed on
    the command line, and the pre-install gate never honors one (a hostile target must not get to
    grandfather its own findings).

Each entry is keyed by a fingerprint of (check id + file + evidence), independent of line number so
an edit elsewhere in the file doesn't silently un-suppress or re-fire it. Suppression is always
reported (count + the entries), never silent, and the baseline is audited for entries that
grandfather a critical or install-time finding.

No third-party deps. Python 3.8+. scan.py imports this for --baseline / --update-baseline.
"""
import hashlib
import json
import os


class BaselineError(Exception):
    """A baseline file that couldn't be read/parsed in a way the caller should report."""


def _evidence(finding):
    """The text a fingerprint is built from: the redacted snippet if present, else the title.
    Never the raw secret (snippets are already redacted upstream) and never the line number
    (which drifts as the file is edited)."""
    return (finding.get("snippet") or finding.get("title") or "").strip()


def fingerprint(finding):
    """Stable, line-independent key for a finding: sha1(id | file | evidence), short hex.

    Line is deliberately excluded so editing unrelated lines doesn't move the fingerprint. Two
    distinct findings only collide if they share id, file, and identical redacted evidence — rare,
    and the safe direction (a real new finding that collides with a baselined one stays suppressed
    only if it is genuinely the same check + file + evidence)."""
    key = "|".join([finding.get("id", ""), finding.get("file", ""), _evidence(finding)])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def record(finding):
    """A human-reviewable baseline entry. Enumerated and readable so a baseline diff in a PR shows
    exactly what is being grandfathered."""
    return {
        "fingerprint": fingerprint(finding),
        "id": finding.get("id"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "severity": finding.get("severity"),
        "install_time": bool(finding.get("install_time")),
        "snippet": finding.get("snippet"),
    }


def write_baseline(path, findings, version="unknown"):
    """Write an enumerated baseline. Records are sorted for a stable, reviewable diff. Returns the
    number of entries written. Regenerating is a conscious act (scan.py --update-baseline), so a
    newly-grandfathered finding lands as a visible line in this file's diff."""
    records = sorted((record(f) for f in findings),
                     key=lambda r: (r["severity"] or "", r["file"] or "", r["fingerprint"]))
    doc = {
        "tool": "git-gud-security",
        "baseline_version": version,
        "note": "Enumerated baseline. Findings listed here are grandfathered: a scan with "
                "--baseline fails only on findings NOT in this list. Review changes to this file "
                "like any privileged config — a new entry grandfathers a real finding.",
        "count": len(records),
        "findings": records,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    return len(records)


class Loaded:
    """A parsed baseline: the fingerprint set (for fast membership) and the raw records (for audit
    and reporting)."""
    def __init__(self, records):
        self.records = records
        self.fingerprints = {r.get("fingerprint") for r in records if r.get("fingerprint")}


def load(path):
    """Parse a baseline file into a Loaded. Raises BaselineError on a missing/garbled file or a
    shape that isn't ours, so a typo'd path fails loud instead of silently suppressing nothing."""
    if not os.path.isfile(path):
        raise BaselineError(f"baseline not found: {path} (create it with --update-baseline)")
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise BaselineError(f"baseline unreadable: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise BaselineError(f"{path} is not a git-gud-security baseline (no findings list)")
    return Loaded(doc["findings"])


def partition(findings, loaded):
    """Split findings into (new, suppressed) by baseline membership. `new` is what a scan reports
    and gates on; `suppressed` is reported as a visible count, never dropped silently."""
    new, suppressed = [], []
    for f in findings:
        (suppressed if fingerprint(f) in loaded.fingerprints else new).append(f)
    return new, suppressed


def audit(loaded):
    """Flag baseline entries that grandfather something that should never be quietly ignored: a
    critical, or an install-time finding. Returns a list of human-readable warnings (loud, per the
    no-silent-suppression policy). An attacker broadening the baseline to bury a critical trips
    this."""
    warnings = []
    crits = [r for r in loaded.records if r.get("severity") == "critical"]
    insts = [r for r in loaded.records if r.get("install_time")]
    if crits:
        warnings.append(
            f"{len(crits)} CRITICAL finding(s) grandfathered by the baseline — these are hidden "
            f"from --fail-on until removed: "
            + ", ".join(f"{r.get('id')} @ {r.get('file')}" for r in crits[:5])
            + (" ..." if len(crits) > 5 else ""))
    if insts:
        warnings.append(
            f"{len(insts)} install-time finding(s) grandfathered by the baseline: "
            + ", ".join(f"{r.get('id')} @ {r.get('file')}" for r in insts[:5])
            + (" ..." if len(insts) > 5 else ""))
    return warnings
