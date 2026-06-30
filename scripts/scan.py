#!/usr/bin/env python3
"""
Git Gud Security - deterministic sweep.

Walks a repo, applies the pattern library in patterns.json (secrets, known-dangerous
code patterns, config red flags), and emits findings as JSON for the skill to confirm,
score, and grade. This is the cheap grep/config tier; dataflow (trace tier) is the LLM's
job in full/ultra mode.

Usage:
    python scan.py <repo-path> [--mode readme|quick] [--staged] [--format json|sarif|text]
                   [--fail-on critical|high|medium|low] [--out FILE]

readme = prose red-flag scan + config/filename checks. quick = readme + full pattern sweep
+ a secret/sourcemap sweep of build output. full/ultra need the skill (they require an LLM
for dataflow tracing and adversarial verification) and exit with a pointer if invoked here.

--staged scans only files staged for commit (git diff --cached) — the fast path for a
pre-commit hook. --fail-on exits nonzero when a finding at or above that severity is present,
so the hook can block the commit. --format sarif emits SARIF 2.1.0 for GitHub code scanning;
--format text emits a terse human summary.

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
import subprocess
import sys

__version__ = "0.2.0"

HERE = os.path.dirname(os.path.abspath(__file__))

# Dependency / cache / IDE dirs: never scanned at all.
ALWAYS_SKIP = {
    "node_modules", ".git", "vendor", "target", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", "coverage", ".turbo", ".cache", "bower_components",
    ".gradle", ".idea", "Pods", "DerivedData", ".terraform",
}
# Build output: skipped for the general pattern sweep, but still swept for inlined secrets
# and sourcemaps — that is exactly where a leaked key or a .map file ends up, and the
# secret-in-bundle / sourcemap checks would otherwise be dead code.
BUILD_OUTPUT = {"dist", "build", ".next", "out", ".nuxt", ".svelte-kit"}
SKIP_DIRS = ALWAYS_SKIP | BUILD_OUTPUT

# Binary / generated extensions to skip for content scanning.
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".tar", ".bz2", ".7z", ".rar", ".mp4", ".mp3", ".wav", ".mov", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".class", ".jar", ".pyc", ".so", ".dll", ".dylib", ".bin",
    ".wasm", ".lock",  # lockfile contents don't matter; presence is checked elsewhere
}

MAX_FILE_BYTES = 2_000_000  # skip files larger than 2MB for content scanning
MAX_LINE_LEN = 5_000  # bound the slice any one regex runs against, so a minified/one-line blob
# in a hostile repo can't drive catastrophic backtracking and hang the scan. Long lines are
# scanned in overlapping windows of this size (see match_in_line) rather than truncated, so a
# secret past byte 5000 in a one-line bundle is still found while each match stays bounded.
LINE_WINDOW_OVERLAP = 256  # window overlap, larger than any token so none is split across a seam


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


# High-precision secret formats scrubbed from EVERY emitted snippet, whatever pattern matched.
# Without this, a real secret sitting on a line that matched a non-secret pattern (a JWT inside a
# localStorage.setItem, say) would be printed verbatim into stdout and SECURITY_AUDIT.md.
_SECRET_RE = re.compile(
    r"sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}"
    r"|AKIA[0-9A-Z]{16}|gh[opsur]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}"
    r"|sk_live_[0-9A-Za-z]{20,}|rk_live_[0-9A-Za-z]{20,}|shpat_[a-fA-F0-9]{32}"
    r"|sb_secret_[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}"
    r"|r8_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|pplx-[A-Za-z0-9]{32,}"
    r"|npm_[A-Za-z0-9]{36}|sk-svcacct-[A-Za-z0-9_-]{20,}"
    # SendGrid / Twilio / DigitalOcean: detected by patterns.json but were missing here, so a
    # token on a line that also matched a non-secret pattern leaked in full. Keep this regex a
    # superset of every token format the patterns detect (test_scrub_covers_token_formats).
    r"|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|AC[A-Za-z0-9]{32}|dop_v1_[a-f0-9]{64}"
    r"|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"
    r"|[a-zA-Z][a-zA-Z0-9+.-]*://[^:@/\s\"']+:[^@/\s\"']+@",
    re.IGNORECASE,
)


def scrub(s):
    """Redact any secret-format substring anywhere in a snippet, regardless of pattern."""
    return _SECRET_RE.sub(lambda m: redact(m.group(0)), s)


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def staged_files(root):
    """Absolute paths of files staged for commit (added/copied/modified), via git. This is
    the pre-commit fast path: scan what's about to land, not the whole tree. Returns None if
    git isn't available or `root` isn't a work tree (caller falls back to a full-tree scan);
    an empty list means a clean stage. Dependency/cache dirs are pruned the same as a walk."""
    try:
        r = subprocess.run(
            ["git", "-C", root, "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
            capture_output=True, text=True)
    except (OSError, ValueError):
        return None
    if r.returncode != 0:
        return None
    out = []
    for name in r.stdout.split("\0"):
        name = name.strip()
        if not name:
            continue
        if set(name.replace("\\", "/").split("/")) & ALWAYS_SKIP:
            continue
        p = os.path.join(root, name)
        if os.path.isfile(p):
            out.append(p)
    return out


def iter_build_files(root, build_dirs, skip=ALWAYS_SKIP):
    """Yield files living under a build-output dir (incl. nested, e.g. packages/*/dist).
    Prunes `skip` (always-skip + any user --exclude dirs) so excluded parents like tests/
    are not entered. Used for the secret/sourcemap sweep of build output."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        segments = set(rel(root, dirpath).split("/"))
        if segments & build_dirs:
            for fn in filenames:
                yield os.path.join(dirpath, fn)


def rel(root, path):
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def match_in_line(line, pat):
    """First `_any` hit not suppressed by a `_not` in the same window. Long lines are scanned
    in overlapping windows so a hit past MAX_LINE_LEN (a key in a one-line minified bundle) is
    still found, while each regex runs against a bounded window. Returns (match, window) or
    (None, None)."""
    if len(line) <= MAX_LINE_LEN:
        windows = ((0, line),)
    else:
        step = MAX_LINE_LEN - LINE_WINDOW_OVERLAP
        windows = ((s, line[s:s + MAX_LINE_LEN]) for s in range(0, len(line), step))
    for _, win in windows:
        for rx in pat["_any"]:
            m = rx.search(win)
            if m and not any(nrx.search(win) for nrx in pat["_not"]):
                return m, win
    return None, None


def scan_content(root, patterns, do_redact, files=None):
    findings = []
    files_scanned = 0
    for path in (iter_files(root) if files is None else files):
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
                hit, win = match_in_line(line, pat)
                if not hit:
                    continue
                if len(line) <= MAX_LINE_LEN:
                    snippet = line.rstrip()[:200]
                else:
                    s = max(0, hit.start() - 60)
                    e = min(len(win), hit.end() + 60)
                    snippet = ("..." + win[s:e].strip())[:200]
                if pat.get("secret") and do_redact:
                    snippet = snippet.replace(hit.group(0), redact(hit.group(0)))
                if do_redact:
                    snippet = scrub(snippet)
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


def scan_filenames(root, patterns, files=None):
    """File-presence checks: flag if a file matching a name/glob exists in the tree."""
    findings = []
    present = []
    for path in (iter_files(root) if files is None else files):
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


def check_env_hygiene(root, files=None):
    """Light .env-tracking check independent of patterns.json. A real .env (not an
    example) present in the tree is reported; the skill confirms it's git-tracked and
    holds real values. With `files`, only those paths are considered (staged-mode)."""
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
    for path in (iter_files(root) if files is None else files):
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


def scan_build_output(root, patterns, do_redact, build_dirs, skip=ALWAYS_SKIP):
    """Sweep build-output dirs for inlined secrets and committed sourcemaps only. These
    dirs are skipped by the general walk, but a key compiled into a bundle or a leaked
    .map lives here and nowhere else."""
    build_files = list(iter_build_files(root, build_dirs, skip))
    if not build_files:
        return []
    secret_content = [p for p in patterns
                      if p.get("kind", "content") == "content" and p.get("secret")]
    filename_pats = [p for p in patterns if p.get("kind") == "filename"]
    content_findings, _ = scan_content(root, secret_content, do_redact, files=build_files)
    name_findings = scan_filenames(root, filename_pats, files=build_files)
    return content_findings + name_findings


PROSE_EXTS = {".md", ".mdx", ".markdown", ".txt", ".rst"}


def load_readme_phrases():
    """Pull the README red-flag phrases out of checks.data.json (the structured source the
    readme-redflags.md doc is generated from). Returns (normalized_phrase, id, title,
    severity, category) tuples."""
    path = os.path.join(HERE, "checks.data.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for cat in data.get("categories", []):
        cat_id = cat.get("key") or cat.get("title", "")
        for c in cat.get("checks", []):
            for phrase in (c.get("readmeRedFlags") or []):
                norm = " ".join(str(phrase).lower().split())
                if len(norm) >= 12:  # skip short generic phrases that would over-match
                    out.append((norm, c["id"], c.get("title", ""),
                                c.get("severity", "medium"), cat_id))
    return out


def scan_prose_redflags(root, phrases, files=None):
    """readme-tier: match doc/landing prose against the red-flag phrase list. These are
    low-confidence INFERRED leads (marked inferred=true), not confirmed holes — a literal
    case-insensitive phrase pass. The skill/LLM does the semantic version."""
    findings = []
    for path in (iter_files(root) if files is None else files):
        if ext_of(path) not in PROSE_EXTS:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, UnicodeError):
            continue
        norm_lines = [(" ".join(l.lower().split()), idx) for idx, l in enumerate(lines, 1)]
        for norm, cid, title, sev, cat in phrases:
            for nl, idx in norm_lines:
                if norm and norm in nl:
                    findings.append({
                        "id": cid,
                        "category": cat,
                        "severity": sev,
                        "title": title,
                        "file": rel(root, path),
                        "line": idx,
                        "snippet": "README claim matches red flag: " + lines[idx - 1].rstrip()[:160],
                        "fix": "",
                        "detectability": "readme",
                        "inferred": True,
                    })
                    break  # one hit per phrase per file
    return findings


SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# GitHub code scanning reads SARIF `level` for pass/fail and the `security-severity` property
# (a 0-10 string) to bucket findings into its own critical/high/medium/low in the UI.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}

# Which engine produced a finding — set by the producer, not inferred from the check. This
# script IS the deterministic engine, so everything it emits is `deterministic`, even for a
# check whose library detectability is `trace` (a couple of trace-tier checks have a sound grep
# proxy). The skill stamps its dataflow/adversarial findings `llm`. The distinction drives CI
# policy: deterministic and adversarial findings are high-precision and can hard-fail a build,
# a single-pass LLM finding is a warning until escalated.
ENGINE_ORDER = ("deterministic", "llm")
# Fallback only: classify by detectability tier when a finding arrives without an explicit
# engine stamp (e.g. findings fed in from elsewhere). The producer's stamp always wins.
DETERMINISTIC_TIERS = {"readme", "config", "grep"}


def engine_of(finding):
    eng = finding.get("engine")
    if eng:
        return eng
    return "deterministic" if finding.get("detectability") in DETERMINISTIC_TIERS else "llm"


def _sarif_run(engine, findings, version):
    """One SARIF run for a single engine: its own tool.driver, its own rules, and an
    automationDetails.id so GitHub renders it as a distinct analysis the consumer can gate
    separately (fail on deterministic, warn on llm)."""
    rules = {}
    results = []
    for f in findings:
        rid = f["id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.get("title") or rid},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f["severity"], "warning")},
                "properties": {
                    "category": f.get("category", ""),
                    "detectability": f.get("detectability", ""),
                    "engine": engine,
                    "security-severity": _SECURITY_SEVERITY.get(f["severity"], "5.0"),
                },
            }
        msg = f.get("title") or rid
        if f.get("fix"):
            msg = f"{msg}. Fix: {f['fix']}"
        line = f.get("line") or 0
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    # SARIF regions are 1-based; config/filename findings (line 0) anchor to 1.
                    "region": {"startLine": line if line and line > 0 else 1},
                }
            }],
            "properties": {
                "severity": f["severity"],
                "detectability": f.get("detectability", ""),
                "engine": engine,
                "inferred": bool(f.get("inferred")),
            },
        })
    return {
        "tool": {"driver": {
            "name": "git-gud-security",
            "informationUri": "https://github.com/kidsmeal/git-gud-security",
            "version": version,
            "rules": list(rules.values()),
        }},
        # GitHub keys analyses off this id, so the two engines show up as separate categories.
        "automationDetails": {"id": f"git-gud-security/{engine}"},
        "properties": {"engine": engine},
        "results": results,
    }


def to_sarif(out):
    """Render SARIF 2.1.0 for GitHub code scanning, one run per engine (deterministic vs llm).
    Keeping them as separate runs lets CI gate them independently instead of parsing a property
    off every result. The standalone script only ever produces deterministic findings, so today
    that's a single run; the skill's trace/adversarial findings slot in as the llm run."""
    findings = out["findings"]
    version = out.get("version", "")
    runs = []
    for engine in ENGINE_ORDER:
        eng_findings = [f for f in findings if engine_of(f) == engine]
        if eng_findings:
            runs.append(_sarif_run(engine, eng_findings, version))
    if not runs:
        # No findings at all: still emit one valid, empty deterministic run.
        runs.append(_sarif_run("deterministic", [], version))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def to_text(out):
    """Terse human summary — the format a pre-commit hook prints. One line per finding,
    severity-sorted (the dict is already sorted by main)."""
    findings = out["findings"]
    c = out["counts"]
    lines = [f"git-gud-security — {out['mode']} scan · {out['scanned']['files']} files scanned",
             f"  {c['critical']} critical · {c['high']} high · {c['medium']} medium · {c['low']} low"]
    if not findings:
        lines.append("  clean (no candidate findings in this mode)")
        return "\n".join(lines) + "\n"
    lines.append("")
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        inferred = "  (inferred)" if f.get("inferred") else ""
        lines.append(f"  {f['severity'].upper():<8} {f['id']:<44} {loc}{inferred}")
    lines.append("")
    lines.append("candidate findings — confirm each at file:line before trusting.")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(
        description="Git Gud Security deterministic sweep. Output is CANDIDATE findings "
                    "that need confirmation at file:line before reporting.")
    ap.add_argument("repo")
    ap.add_argument("--version", action="version", version=f"git-gud-security {__version__}")
    ap.add_argument("--mode", default="quick", choices=["readme", "quick", "full", "ultra"])
    ap.add_argument("--json", action="store_true", help="(deprecated alias for --format json)")
    ap.add_argument("--format", default="json", choices=["json", "sarif", "text"],
                    help="json (default, for the skill), sarif (GitHub code scanning), "
                         "text (terse summary, for a pre-commit hook)")
    ap.add_argument("--staged", action="store_true",
                    help="scan only files staged for commit (git diff --cached) — pre-commit fast path")
    ap.add_argument("--fail-on", default=None, choices=["critical", "high", "medium", "low"],
                    help="exit nonzero if a finding at or above this severity is present "
                         "(use in a pre-commit hook / CI to block on findings)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--exclude", nargs="*", default=[], metavar="DIR",
                    help="additional directories to skip (e.g. --exclude references tests)")
    args = ap.parse_args()
    if args.json:
        args.format = "json"

    # full/ultra do dataflow tracing and adversarial verification — that needs an LLM, so
    # they live in the Claude Code skill, not this script. Don't fake them by aliasing quick.
    if args.mode in ("full", "ultra"):
        needs = "dataflow tracing" if args.mode == "full" else \
                "dataflow tracing and adversarial multi-agent verification"
        print(f"git-gud-security: '{args.mode}' mode needs the Claude Code skill. It requires "
              f"an LLM for {needs}. The standalone script runs the deterministic tiers only: "
              f"--mode readme or --mode quick.", file=sys.stderr)
        sys.exit(2)

    root = os.path.abspath(args.repo)
    if not os.path.isdir(root):
        print(json.dumps({"error": f"not a directory: {root}"}))
        sys.exit(1)

    if args.exclude:
        SKIP_DIRS.update(args.exclude)

    patterns, do_redact = load_patterns()

    # --staged: restrict every tier to the files staged for commit. None means whole-tree
    # (no --staged, or git unavailable); [] means a clean stage (nothing to scan).
    scan_files = None
    if args.staged:
        scan_files = staged_files(root)
        if scan_files is None:
            print("git-gud-security: --staged needs a git work tree; scanning the whole repo "
                  "instead.", file=sys.stderr)

    print(f"git-gud-security: {len(patterns)} patterns, mode={args.mode}"
          f"{', staged only' if scan_files is not None else ''}. "
          f"Output is candidate findings, not confirmed vulnerabilities.",
          file=sys.stderr)

    # Shared across modes (quick is a strict superset of readme): prose red-flag scan,
    # filename checks, .env hygiene.
    prose_findings = scan_prose_redflags(root, load_readme_phrases(), files=scan_files)
    name_findings = scan_filenames(root, patterns, files=scan_files)
    env_findings = check_env_hygiene(root, files=scan_files)

    if args.mode == "readme":
        # readme: config-tier content only, no grep tier.
        content_pats = [p for p in patterns if p.get("detectability") == "config"
                        and p.get("kind", "content") == "content"]
        content_findings, files_scanned = scan_content(root, content_pats, do_redact, files=scan_files)
    else:
        # quick: every grep + config pattern, plus a secret/sourcemap sweep of build output.
        content_findings, files_scanned = scan_content(root, patterns, do_redact, files=scan_files)
        # Build-output sweep walks dirs the normal pass skips; in staged mode the staged file
        # list already includes any staged bundle, so only run it on a whole-tree scan.
        if scan_files is None:
            build_dirs = BUILD_OUTPUT - set(args.exclude)
            build_skip = ALWAYS_SKIP | set(args.exclude)
            content_findings += scan_build_output(root, patterns, do_redact, build_dirs, build_skip)

    content_findings += prose_findings

    findings = content_findings + name_findings + env_findings
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["file"], f["line"]))
    # This script is the deterministic engine, so stamp every finding it produces accordingly
    # (the skill stamps its trace/adversarial findings `llm`). Exposed in JSON and split into
    # per-engine runs in SARIF. Note: a finding can be deterministic-engine yet carry a
    # `trace` detectability — the tier describes the check, the engine describes who fired it.
    for f in findings:
        f["engine"] = "deterministic"

    out = {
        "tool": "git-gud-security",
        "version": __version__,
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
    if args.format == "sarif":
        payload = json.dumps(to_sarif(out), indent=2)
    elif args.format == "text":
        payload = to_text(out)
    else:
        payload = json.dumps(out, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
    print(payload)

    # --fail-on: exit nonzero when a finding meets the threshold, so a pre-commit hook or CI
    # step blocks. Candidate findings are unconfirmed, so this is opt-in, not the default.
    if args.fail_on:
        threshold = SEV_RANK[args.fail_on]
        if any(SEV_RANK.get(f["severity"], 0) >= threshold for f in findings):
            sys.exit(1)


if __name__ == "__main__":
    main()
