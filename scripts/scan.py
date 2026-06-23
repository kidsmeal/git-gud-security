#!/usr/bin/env python3
"""
Git Gud Security - deterministic sweep.

Walks a repo, applies the pattern library in patterns.json (secrets, known-dangerous
code patterns, config red flags), and emits findings as JSON for the skill to confirm,
score, and grade. This is the cheap grep/config tier; dataflow (trace tier) is the LLM's
job in full/ultra mode.

Usage:
    python scan.py <repo-path> [--mode quick|full|readme] [--json] [--out FILE]

Output: JSON {findings: [...], scanned: {...}} to stdout (and --out if given).
Each finding: id, category, severity, title, file, line, snippet (secrets redacted),
fix, detectability.

No third-party deps. Python 3.8+. The skill falls back to running patterns.json with
Grep if Python is unavailable.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Directories never worth scanning. .env detection still works because we list the tree
# separately; these are just skipped for content scanning.
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", "out", ".nuxt", ".svelte-kit",
    "vendor", "target", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    "coverage", ".turbo", ".cache", "bower_components", ".gradle", ".idea", ".vscode",
    "Pods", "DerivedData", ".terraform",
}

# Binary / generated extensions to skip for content scanning.
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".tar", ".bz2", ".7z", ".rar", ".mp4", ".mp3", ".wav", ".mov", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".class", ".jar", ".pyc", ".so", ".dll", ".dylib", ".bin",
    ".wasm", ".lock",  # lockfile contents don't matter; presence is checked elsewhere
}

MAX_FILE_BYTES = 2_000_000  # skip files larger than 2MB for content scanning


def load_patterns():
    with open(os.path.join(HERE, "patterns.json"), encoding="utf-8") as f:
        data = json.load(f)
    compiled = []
    for p in data.get("patterns", []):
        entry = dict(p)
        entry["_any"] = [re.compile(r, re.IGNORECASE) for r in p.get("any", [])]
        entry["_not"] = [re.compile(r, re.IGNORECASE) for r in p.get("not", [])]
        compiled.append(entry)
    return compiled, data.get("secret_redaction", True)


def ext_of(path):
    return os.path.splitext(path)[1].lower()


def matches_include(path, pat):
    """Decide whether this file is in scope for this pattern."""
    name = os.path.basename(path).lower()
    inc = pat.get("include")  # list of extensions like [".ts",".tsx"] or ["*"] or filenames
    if not inc or inc == ["*"]:
        base_ok = True
    else:
        base_ok = False
        e = ext_of(path)
        for token in inc:
            t = token.lower()
            if t.startswith("."):
                if e == t:
                    base_ok = True
                    break
            elif t == name or name.endswith(t):
                base_ok = True
                break
    if not base_ok:
        return False
    for token in pat.get("exclude", []):
        t = token.lower()
        if t.startswith(".") and ext_of(path) == t:
            return False
        if t == name:
            return False
    return True


def redact(s):
    s = s.strip()
    if len(s) <= 12:
        return s[:4] + "***"
    return s[:6] + "***" + s[-3:]


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def rel(root, path):
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def scan_content(root, patterns, do_redact):
    findings = []
    files_scanned = 0
    for path in iter_files(root):
        if ext_of(path) in SKIP_EXTS:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        applicable = [p for p in patterns if p.get("kind", "content") == "content"
                      and matches_include(path, p)]
        if not applicable:
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, UnicodeError):
            continue
        files_scanned += 1
        for pat in applicable:
            for i, line in enumerate(lines, 1):
                hit = None
                for rx in pat["_any"]:
                    m = rx.search(line)
                    if m:
                        hit = m
                        break
                if not hit:
                    continue
                if any(rx.search(line) for rx in pat["_not"]):
                    continue
                snippet = line.rstrip()[:200]
                if pat.get("secret") and do_redact:
                    snippet = snippet.replace(hit.group(0), redact(hit.group(0)))
                findings.append({
                    "id": pat["id"],
                    "category": pat.get("category", ""),
                    "severity": pat["severity"],
                    "title": pat["title"],
                    "file": rel(root, path),
                    "line": i,
                    "snippet": snippet,
                    "fix": pat.get("fix", ""),
                    "detectability": pat.get("detectability", "grep"),
                })
    return findings, files_scanned


def scan_filenames(root, patterns):
    """File-presence checks: flag if a file matching a name/glob exists in the tree."""
    findings = []
    present = []
    for path in iter_files(root):
        present.append((os.path.basename(path).lower(), rel(root, path)))
    for pat in patterns:
        if pat.get("kind") != "filename":
            continue
        wanted = [w.lower() for w in pat.get("filenames", [])]
        rx_list = [re.compile(r, re.IGNORECASE) for r in pat.get("filename_regex", [])]
        for base, relpath in present:
            ok = base in wanted or any(rx.search(relpath) for rx in rx_list)
            if not ok:
                continue
            if any(x.lower() in base for x in pat.get("filename_exclude", [])):
                continue
            findings.append({
                "id": pat["id"],
                "category": pat.get("category", ""),
                "severity": pat["severity"],
                "title": pat["title"],
                "file": relpath,
                "line": 0,
                "snippet": "(file present in repo)",
                "fix": pat.get("fix", ""),
                "detectability": pat.get("detectability", "config"),
            })
    return findings


def check_env_hygiene(root):
    """Light .env-tracking check independent of patterns.json. A real .env (not an
    example) present in the tree is reported; the skill confirms it's git-tracked and
    holds real values."""
    findings = []
    example_markers = ("example", "sample", "template", "dist")
    gitignore = os.path.join(root, ".gitignore")
    ignored_env = False
    if os.path.isfile(gitignore):
        try:
            txt = open(gitignore, encoding="utf-8", errors="ignore").read()
            ignored_env = bool(re.search(r"^\s*\.env", txt, re.MULTILINE))
        except OSError:
            pass
    for path in iter_files(root):
        base = os.path.basename(path).lower()
        if base.startswith(".env") and not any(m in base for m in example_markers):
            findings.append({
                "id": "committed-dotenv-or-cred-file",
                "category": "secrets-and-credentials",
                "severity": "critical" if not ignored_env else "medium",
                "title": "Real .env present in repo tree",
                "file": rel(root, path),
                "line": 0,
                "snippet": "(.env not gitignored)" if not ignored_env else "(.env gitignored, confirm not tracked)",
                "fix": "Add .env* (except .env.example) to .gitignore, git rm --cached it, rotate every value, purge from history.",
                "detectability": "config",
            })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--mode", default="quick", choices=["readme", "quick", "full"])
    ap.add_argument("--json", action="store_true", help="(default) emit JSON")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    root = os.path.abspath(args.repo)
    if not os.path.isdir(root):
        print(json.dumps({"error": f"not a directory: {root}"}))
        sys.exit(1)

    patterns, do_redact = load_patterns()
    content_findings, files_scanned = scan_content(root, patterns, do_redact)
    name_findings = scan_filenames(root, patterns)
    env_findings = check_env_hygiene(root)

    findings = content_findings + name_findings + env_findings
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["file"], f["line"]))

    out = {
        "tool": "git-gud-security",
        "mode": args.mode,
        "repo": root.replace("\\", "/"),
        "scanned": {"files": files_scanned, "pattern_count": len(patterns)},
        "counts": {
            s: sum(1 for f in findings if f["severity"] == s)
            for s in ("critical", "high", "medium", "low")
        },
        "findings": findings,
        "note": "Scanner output is candidate findings. Confirm each at file:line before "
                "reporting; drop false positives (comments, tests, docs, safe public keys).",
    }
    payload = json.dumps(out, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
    print(payload)


if __name__ == "__main__":
    main()
