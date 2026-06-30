#!/usr/bin/env python3
"""Test runner for git-gud-security scanner.

Runs scan.py against fixture directories and asserts the exact set of findings
(id, file, line, severity) against hand-owned golden files. Exits 0 on pass, 1 on fail.

Usage:
    python tests/run_tests.py            # assert
    python tests/run_tests.py --update   # regenerate the golden files (deliberate)

The goldens (tests/expected/{quick,readme}.json) are normalized finding lists, not raw
scanner dumps. Regenerating is a conscious act so a regex that drifts to a new line/file
shows up as a reviewable golden diff instead of being laundered through the test.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_PY = os.path.join(ROOT, "scripts", "scan.py")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
EXPECTED = os.path.join(ROOT, "tests", "expected")
PATTERNS_JSON = os.path.join(ROOT, "scripts", "patterns.json")

sys.path.insert(0, os.path.join(ROOT, "scripts"))
import scan  # noqa: E402  (reuse the real scanner for per-pattern coverage)

UPDATE = "--update" in sys.argv
failed = False


def run_scan(target, mode):
    """Return (raw_stdout, parsed_dict) or (None, None) on failure."""
    result = subprocess.run(
        [sys.executable, SCAN_PY, target, "--mode", mode],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  FAIL: scan.py exited {result.returncode}")
        print(f"  stderr: {result.stderr.strip()}")
        return None, None
    return result.stdout, json.loads(result.stdout)


def finding_rows(findings):
    """Normalize findings to sorted [id, file, line, severity] rows: the stable, machine-
    independent shape the goldens assert on (no absolute paths, no volatile snippet text)."""
    return sorted([f["id"], f["file"], f["line"], f["severity"]] for f in findings)


def test_findings_exact(mode):
    """Assert the scanner's findings match the golden EXACTLY: every expected (id, file,
    line, severity) row present, and no extras. Missing catches a broken pattern; extra
    catches a regex that broadened onto a line it shouldn't touch."""
    global failed
    target = os.path.join(FIXTURES, "true-positives")
    golden_file = os.path.join(EXPECTED, f"{mode}.json")

    print(f"\n--- true-positives ({mode} mode, exact) ---")
    raw, actual = run_scan(target, mode)
    if actual is None:
        failed = True
        return
    actual_rows = finding_rows(actual["findings"])

    if UPDATE:
        with open(golden_file, "w", encoding="utf-8") as f:
            json.dump(actual_rows, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"  UPDATED: wrote {len(actual_rows)} rows to expected/{mode}.json")
        return

    with open(golden_file, encoding="utf-8") as f:
        golden_rows = [list(r) for r in json.load(f)]

    actual_set = {tuple(r) for r in actual_rows}
    golden_set = {tuple(r) for r in golden_rows}
    missing = sorted(golden_set - actual_set)
    extra = sorted(actual_set - golden_set)

    if missing or extra:
        failed = True
        print(f"  FAIL: {len(missing)} missing, {len(extra)} extra")
        for r in missing:
            print(f"    - missing: {r[0]} {r[1]}:{r[2]} ({r[3]})")
        for r in extra:
            print(f"    + extra:   {r[0]} {r[1]}:{r[2]} ({r[3]})")
    else:
        print(f"  PASS: {len(actual_rows)} findings match exactly")


def test_secrets_redacted():
    """A scanner that prints the secrets it finds is itself a leak (SECURITY.md scopes this as
    a vuln). Discover every secret-format token present in the fixtures, then assert NONE
    appears verbatim in output. Auto-covers new fixtures, and catches the same-line
    double-finding leak (one finding redacts, a second prints raw via an incomplete scrub)."""
    global failed
    print("\n--- secret redaction (no token in cleartext) ---")
    tp = os.path.join(FIXTURES, "true-positives")
    all_files = list(scan.iter_files(tp)) + list(scan.iter_build_files(tp, scan.BUILD_OUTPUT))
    tokens = set()
    for path in all_files:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        for m in scan._SECRET_RE.finditer(text):
            tokens.add(m.group(0))
    raw, actual = run_scan(tp, "quick")
    if raw is None:
        failed = True
        return
    leaked = sorted(t for t in tokens if t in raw)
    if leaked:
        failed = True
        print(f"  FAIL: {len(leaked)} fixture secret(s) printed in cleartext:")
        for t in leaked:
            print(f"    - {t[:12]}...")
    elif "***" not in raw:
        failed = True
        print("  FAIL: no redaction marker in output (redaction may not have run)")
    else:
        print(f"  PASS: {len(tokens)} fixture secrets, none in cleartext")


def test_severity_synced():
    """patterns.json must not silently downgrade a check's severity. The finding's severity
    drives the grade, so it has to match the source-of-truth library."""
    global failed
    print("\n--- severity sync (patterns vs checks) ---")
    with open(PATTERNS_JSON, encoding="utf-8") as f:
        pats = json.load(f)["patterns"]
    with open(os.path.join(ROOT, "scripts", "checks.data.json"), encoding="utf-8") as f:
        checks = {c["id"]: c["severity"] for cat in json.load(f)["categories"]
                  for c in cat["checks"]}
    bad = [(p["id"], p.get("severity"), checks[p["id"]]) for p in pats
           if p["id"] in checks and p.get("severity") != checks[p["id"]]]
    if bad:
        failed = True
        print(f"  FAIL: {len(bad)} patterns disagree with the library on severity:")
        for pid, ps, cs in bad:
            print(f"    - {pid}: pattern={ps} check={cs}")
    else:
        print(f"  PASS: all {len(pats)} pattern severities match the library")


def test_scrub_covers_token_formats():
    """The global scrub regex must be a superset of every standalone token format the patterns
    detect; otherwise a token on a line matched by a non-secret pattern prints in cleartext.
    Samples are built by concatenation so no contiguous high-entropy token sits in this file."""
    global failed
    print("\n--- scrub covers detected token formats ---")
    samples = {
        "anthropic":    "sk-ant-" + "A" * 24,
        "openai-proj":  "sk-proj-" + "A" * 24,
        "aws":          "AKIA" + "ABCDEFGHIJKLMNOP",
        "github":       "ghp_" + "A" * 32,
        "google":       "AIza" + "A" * 35,
        "stripe":       "sk_live_" + "A" * 24,
        "slack":        "xoxb-1-" + "A" * 12,
        "sendgrid":     "SG." + "a" * 22 + "." + "b" * 43,
        "twilio":       "AC" + "0" * 32,
        "digitalocean": "dop_v1_" + "a" * 64,
    }
    leaks = [name for name, tok in samples.items() if not scan._SECRET_RE.search(tok)]
    if leaks:
        failed = True
        print(f"  FAIL: {len(leaks)} detected format(s) not covered by scrub: {', '.join(leaks)}")
    else:
        print(f"  PASS: all {len(samples)} token formats are scrubbed")


def test_long_line_bundle():
    """A secret past MAX_LINE_LEN in a one-line minified bundle must still be found (the build
    sweep's whole point); the line cap windows, it doesn't truncate."""
    global failed
    print("\n--- long-line bundle coverage ---")
    tp = os.path.join(FIXTURES, "true-positives")
    raw, actual = run_scan(tp, "quick")
    if actual is None:
        failed = True
        return
    hits = [f for f in actual["findings"] if f["file"].endswith("min.bundle.js")]
    if hits:
        print(f"  PASS: secret past byte 5000 found ({len(hits)} finding)")
    else:
        failed = True
        print("  FAIL: secret in one-line bundle past byte 5000 was missed")


def test_version_in_sync():
    """scan.py __version__ must match the top entry in CHANGELOG.md."""
    global failed
    print("\n--- version sync ---")
    import re
    changelog = os.path.join(ROOT, "CHANGELOG.md")
    with open(changelog, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"##\s*\[(\d+\.\d+\.\d+)\]", text)
    top = m.group(1) if m else None
    if top == scan.__version__:
        print(f"  PASS: scan.py and CHANGELOG agree on {top}")
    else:
        print(f"  FAIL: scan.py={scan.__version__}, CHANGELOG top={top}")
        failed = True


def test_every_pattern_has_fixture():
    """Rigorous coverage: every individual pattern ENTRY must fire on a fixture, not just
    every unique id. Six ids map to two patterns each, so an id-only check could let a
    broken duplicate hide behind its sibling. This runs each pattern object on its own."""
    global failed
    print("\n--- per-pattern fixture coverage ---")
    patterns, do_redact = scan.load_patterns()
    tp = os.path.join(FIXTURES, "true-positives")
    # Include build-output dirs so build-only fixtures (inlined dist secret) count.
    all_files = list(scan.iter_files(tp)) + list(scan.iter_build_files(tp, scan.BUILD_OUTPUT))
    missing = []
    for pat in patterns:
        if pat.get("kind") == "filename":
            f = scan.scan_filenames(tp, [pat], files=all_files)
        else:
            f, _ = scan.scan_content(tp, [pat], do_redact, files=all_files)
        if not f:
            missing.append((pat["id"], pat.get("title", "")))
    if missing:
        print(f"  FAIL: {len(missing)} pattern entries have no fixture:")
        for pid, title in missing:
            print(f"    - {pid}: {title}")
        failed = True
    else:
        print(f"  PASS: all {len(patterns)} pattern entries fire on a fixture")


def test_full_ultra_route_to_skill():
    """full/ultra can't run standalone (need an LLM); they must exit with a pointer, not
    silently alias quick."""
    global failed
    print("\n--- full/ultra route to skill ---")
    tp = os.path.join(FIXTURES, "true-positives")
    for mode in ("full", "ultra"):
        r = subprocess.run([sys.executable, SCAN_PY, tp, "--mode", mode],
                           capture_output=True, text=True)
        if r.returncode == 2 and "needs the Claude Code skill" in r.stderr:
            print(f"  PASS: --mode {mode} exits 2 with skill pointer")
        else:
            print(f"  FAIL: --mode {mode} rc={r.returncode}, stderr={r.stderr.strip()[:80]}")
            failed = True


def test_sarif_output():
    """--format sarif must emit valid SARIF 2.1.0 with one run PER ENGINE (deterministic vs
    llm), each tagged with an automationDetails.id so GitHub gates them separately. Results
    summed across runs must equal the finding count; every result carries a ruleId, a 1-based
    location, and an engine that matches the run it's in."""
    global failed
    print("\n--- SARIF output (per-engine runs) ---")
    tp = os.path.join(FIXTURES, "true-positives")
    r = subprocess.run([sys.executable, SCAN_PY, tp, "--mode", "quick", "--format", "sarif"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        failed = True
        print(f"  FAIL: exited {r.returncode}: {r.stderr.strip()[:120]}")
        return
    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        failed = True
        print(f"  FAIL: not valid JSON: {e}")
        return
    _, jdoc = run_scan(tp, "quick")
    n_findings = len(jdoc["findings"])
    runs = doc.get("runs", [])
    problems = []
    if doc.get("version") != "2.1.0":
        problems.append(f"version={doc.get('version')} (want 2.1.0)")
    total_results = sum(len(run.get("results", [])) for run in runs)
    if total_results != n_findings:
        problems.append(f"{total_results} results across runs vs {n_findings} findings")
    seen_engines = set()
    for run in runs:
        engine = run.get("properties", {}).get("engine")
        seen_engines.add(engine)
        if run.get("automationDetails", {}).get("id") != f"git-gud-security/{engine}":
            problems.append(f"run automationDetails.id wrong for engine {engine}")
        if run.get("results") and not run.get("tool", {}).get("driver", {}).get("rules"):
            problems.append(f"engine {engine}: results but no rules")
        for res in run.get("results", []):
            if not res.get("ruleId"):
                problems.append(f"engine {engine}: a result has no ruleId"); break
            if res.get("properties", {}).get("engine") != engine:
                problems.append(f"engine {engine}: result tagged a different engine"); break
            line = res["locations"][0]["physicalLocation"]["region"]["startLine"]
            if line < 1:
                problems.append(f"engine {engine}: startLine {line} < 1"); break
    # The standalone script only produces deterministic findings, so only that run should exist.
    if seen_engines - {"deterministic"}:
        problems.append(f"unexpected engine run(s) from the script: {seen_engines}")
    if problems:
        failed = True
        print(f"  FAIL: {'; '.join(problems)}")
    else:
        print(f"  PASS: valid SARIF, {len(runs)} run(s) {sorted(seen_engines)}, "
              f"{total_results} results total")


def test_fail_on_exit_code():
    """--fail-on must exit nonzero when a finding meets the threshold and zero otherwise —
    this is what lets a pre-commit hook block a commit. Default (no --fail-on) stays 0."""
    global failed
    print("\n--- --fail-on exit code ---")
    tp = os.path.join(FIXTURES, "true-positives")
    fp = os.path.join(FIXTURES, "false-positives")
    cases = [
        (tp, ["--fail-on", "critical"], "ne0", "dirty repo, fail-on critical"),
        (fp, ["--fail-on", "low"], "eq0", "clean repo, fail-on low"),
        (tp, [], "eq0", "dirty repo, no --fail-on (must not block)"),
    ]
    for target, extra, want, label in cases:
        r = subprocess.run([sys.executable, SCAN_PY, target, "--mode", "quick",
                            "--format", "text"] + extra, capture_output=True, text=True)
        ok = (r.returncode != 0) if want == "ne0" else (r.returncode == 0)
        if ok:
            print(f"  PASS: {label} -> rc={r.returncode}")
        else:
            failed = True
            print(f"  FAIL: {label} -> rc={r.returncode} (wanted {want})")


def test_staged_scope():
    """--staged must scan only files staged for commit, not committed or unstaged ones —
    the pre-commit fast path. Builds a throwaway git repo so the test owns the index state."""
    global failed
    print("\n--- --staged scope ---")
    import tempfile, shutil
    tmp = tempfile.mkdtemp(prefix="ggs-staged-")
    try:
        def git(*a):
            return subprocess.run(["git", "-C", tmp, *a], capture_output=True, text=True)
        if git("init", "-q").returncode != 0:
            print("  SKIP: git unavailable")
            return
        git("config", "user.email", "t@t.co"); git("config", "user.name", "t")
        # secret in a committed file (must be ignored by --staged)
        with open(os.path.join(tmp, "committed.js"), "w") as f:
            f.write('const k = "AKIA' + "ABCDEFGHIJKLMNOP" + '";\n')
        git("add", "committed.js"); git("commit", "-q", "-m", "init")
        # secret in a staged file (must be found) and an unstaged file (must be ignored)
        with open(os.path.join(tmp, "staged.js"), "w") as f:
            f.write('const t = "ghp_' + "A" * 32 + '";\n')
        with open(os.path.join(tmp, "unstaged.js"), "w") as f:
            f.write('const u = "AKIA' + "ZZZZZZZZZZZZZZZZ" + '";\n')
        git("add", "staged.js")
        r = subprocess.run([sys.executable, SCAN_PY, tmp, "--mode", "quick", "--staged"],
                           capture_output=True, text=True)
        doc = json.loads(r.stdout)
        files = {f["file"] for f in doc["findings"]}
        if files == {"staged.js"}:
            print("  PASS: only the staged file was scanned")
        else:
            failed = True
            print(f"  FAIL: scanned files = {sorted(files)} (wanted just staged.js)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_action_manifest():
    """The composite action must be wired correctly: a scan step that runs the bundled
    scan.py, a SARIF upload step, and — critically for a security tool — inputs passed via
    `env`, never interpolated as ${{ }} into a run script (the Actions injection hole this
    tool flags). Skips cleanly if PyYAML isn't installed."""
    global failed
    print("\n--- GitHub Action manifest ---")
    try:
        import yaml
    except ImportError:
        print("  SKIP: PyYAML not installed")
        return
    path = os.path.join(ROOT, "action.yml")
    if not os.path.isfile(path):
        failed = True
        print("  FAIL: action.yml missing")
        return
    with open(path, encoding="utf-8") as f:
        raw = f.read()
        doc = yaml.safe_load(raw)
    problems = []
    steps = doc.get("runs", {}).get("steps", [])
    run_blocks = "\n".join(s.get("run", "") for s in steps)
    if doc.get("runs", {}).get("using") != "composite":
        problems.append("not a composite action")
    if "scripts/scan.py" not in run_blocks:
        problems.append("no step runs scripts/scan.py")
    if not any("upload-sarif" in str(s.get("uses", "")) for s in steps):
        problems.append("no SARIF upload step")
    # Expression-injection guard: inputs must reach the shell via env, not be spliced into run:.
    import re
    for s in steps:
        body = s.get("run", "")
        if re.search(r"\$\{\{\s*inputs\.", body):
            problems.append(f"step '{s.get('name','?')}' interpolates inputs into run: "
                            f"(injection risk — pass via env instead)")
    if problems:
        failed = True
        print(f"  FAIL: {'; '.join(problems)}")
    else:
        print(f"  PASS: composite, runs scan.py, uploads SARIF, no inputs spliced into run:")


def test_false_positives(mode):
    global failed
    target = os.path.join(FIXTURES, "false-positives")

    print(f"\n--- false-positives ({mode} mode) ---")
    raw, actual = run_scan(target, mode)
    if actual is None:
        failed = True
        return

    if actual["findings"]:
        print(f"  FAIL: {len(actual['findings'])} false positives fired:")
        for f in actual["findings"]:
            print(f"    - {f['id']} in {f['file']}:{f['line']}")
        failed = True
    else:
        print("  PASS: 0 findings (correct)")


def test_json_valid():
    global failed
    print("\n--- JSON validity ---")
    for name in ["scripts/checks.data.json", "scripts/patterns.json"]:
        path = os.path.join(ROOT, name)
        try:
            with open(path, encoding="utf-8") as f:
                json.load(f)
            print(f"  PASS: {name}")
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"  FAIL: {name}: {e}")
            failed = True


def test_pattern_check_alignment():
    global failed
    print("\n--- pattern/check ID alignment ---")
    with open(PATTERNS_JSON, encoding="utf-8") as f:
        patterns = json.load(f)["patterns"]
    with open(os.path.join(ROOT, "scripts", "checks.data.json"), encoding="utf-8") as f:
        checks_data = json.load(f)

    check_ids = set()
    for cat in checks_data["categories"]:
        for check in cat["checks"]:
            check_ids.add(check["id"])

    pattern_ids = {p["id"] for p in patterns}
    orphans = sorted(pattern_ids - check_ids)
    if orphans:
        failed = True
        print(f"  FAIL: {len(orphans)} pattern IDs have no matching check (fix the id in "
              f"patterns.json or add the check):")
        for pid in orphans:
            print(f"    - {pid}")
    else:
        print(f"  PASS: all {len(pattern_ids)} pattern IDs exist in checks.data.json")


def test_counts_match():
    global failed
    print("\n--- documented counts ---")
    with open(os.path.join(ROOT, "scripts", "checks.data.json"), encoding="utf-8") as f:
        data = json.load(f)
    actual_count = sum(len(cat["checks"]) for cat in data["categories"])

    for doc in ["README.md", "SKILL.md"]:
        path = os.path.join(ROOT, doc)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        import re
        m = re.search(r"(\d{3})\s+checks", content)
        if m:
            stated = int(m.group(1))
            if stated != actual_count:
                print(f"  FAIL: {doc} says {stated} checks, actual is {actual_count}")
                failed = True
            else:
                print(f"  PASS: {doc} says {stated} checks (correct)")
        else:
            print(f"  WARN: couldn't find check count in {doc}")


import gate  # noqa: E402  (the pre-install gate's fetch + classify)
import baseline  # noqa: E402  (the enumerated baseline)


def test_exclude_glob():
    """--exclude must accept a path glob (not just a bare dir name) and drop matching files'
    findings — the self-scan corpus fix. A bare name still prunes the walk as before."""
    global failed
    print("\n--- --exclude path glob ---")
    import tempfile, shutil
    tmp = tempfile.mkdtemp(prefix="ggs-exg-")
    try:
        with open(os.path.join(tmp, "real.js"), "w") as f:
            f.write('const k = "ghp_' + "A" * 32 + '";\n')
        with open(os.path.join(tmp, "corpus.json"), "w") as f:
            f.write('{"example": "ghp_' + "B" * 32 + '"}\n')
        r = subprocess.run([sys.executable, SCAN_PY, tmp, "--mode", "quick",
                            "--exclude", "*.json"], capture_output=True, text=True)
        files = {f["file"] for f in json.loads(r.stdout)["findings"]}
        if files == {"real.js"}:
            print("  PASS: *.json glob excluded corpus.json, kept real.js")
        else:
            failed = True
            print(f"  FAIL: findings in {sorted(files)} (wanted just real.js)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_diff_scope():
    """--diff <ref> must scan only files changed against the ref, not the whole tree — the CI
    adoption path. Builds a throwaway repo so the test owns the history."""
    global failed
    print("\n--- --diff scope ---")
    import tempfile, shutil
    tmp = tempfile.mkdtemp(prefix="ggs-diff-")
    try:
        def git(*a):
            return subprocess.run(["git", "-C", tmp, *a], capture_output=True, text=True)
        if git("init", "-q").returncode != 0:
            print("  SKIP: git unavailable"); return
        git("config", "user.email", "t@t"); git("config", "user.name", "t")
        with open(os.path.join(tmp, "old.js"), "w") as f:
            f.write('const k = "ghp_' + "A" * 32 + '";\n')
        git("add", "-A"); git("commit", "-q", "-m", "base")
        with open(os.path.join(tmp, "new.js"), "w") as f:
            f.write('const t = "ghp_' + "B" * 32 + '";\n')
        # commit the change so it's a real diff against the base ref (the CI/PR shape); --diff,
        # like --staged, scans tracked changes, not untracked files.
        git("add", "new.js"); git("commit", "-q", "-m", "add new.js")
        r = subprocess.run([sys.executable, SCAN_PY, tmp, "--mode", "quick", "--diff", "HEAD~1"],
                           capture_output=True, text=True)
        files = {f["file"] for f in json.loads(r.stdout)["findings"]}
        if files == {"new.js"}:
            print("  PASS: only the changed file (new.js) was scanned")
        else:
            failed = True
            print(f"  FAIL: scanned {sorted(files)} (wanted just new.js)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_baseline_fingerprint_stable():
    """The fingerprint must be line-independent: the same finding at a different line is the same
    fingerprint, so editing unrelated lines doesn't silently un-suppress it."""
    global failed
    print("\n--- baseline: line-independent fingerprint ---")
    a = {"id": "x", "file": "a.js", "snippet": "ghp_REDACTED", "line": 1}
    b = {"id": "x", "file": "a.js", "snippet": "ghp_REDACTED", "line": 99}  # same finding, moved
    other = {"id": "x", "file": "b.js", "snippet": "ghp_REDACTED", "line": 1}  # different file
    ok = (baseline.fingerprint(a) == baseline.fingerprint(b)
          and baseline.fingerprint(a) != baseline.fingerprint(other))
    if ok:
        print("  PASS: line drift keeps the fingerprint; different file changes it")
    else:
        failed = True
        print("  FAIL: fingerprint not line-independent / not file-sensitive")


def test_baseline_roundtrip():
    """write -> load -> partition: a snapshotted finding is suppressed, a new one is reported."""
    global failed
    print("\n--- baseline: write/load/partition ---")
    import tempfile
    old = {"id": "hardcoded-api-key-literal", "file": "old.js", "line": 1,
           "severity": "critical", "snippet": "ghp_REDACTED", "install_time": False}
    new = {"id": "hardcoded-api-key-literal", "file": "new.js", "line": 1,
           "severity": "critical", "snippet": "sk_REDACTED", "install_time": False}
    fd, path = tempfile.mkstemp(prefix="ggs-bl-", suffix=".json"); os.close(fd)
    try:
        baseline.write_baseline(path, [old], "test")
        loaded = baseline.load(path)
        fresh, supp = baseline.partition([old, new], loaded)
        if [f["file"] for f in fresh] == ["new.js"] and [f["file"] for f in supp] == ["old.js"]:
            print("  PASS: old finding suppressed, new finding reported")
        else:
            failed = True
            print(f"  FAIL: fresh={[f['file'] for f in fresh]} supp={[f['file'] for f in supp]}")
    finally:
        os.remove(path)


def test_baseline_audit():
    """The audit must loudly flag a baseline that grandfathers a critical or install-time
    finding — the no-silent-suppression policy. An attacker burying a critical trips this."""
    global failed
    print("\n--- baseline: audit grandfathered criticals ---")
    import tempfile
    crit = {"id": "hook-exfiltrates-env-or-credentials", "file": "hooks/x.sh", "line": 1,
            "severity": "critical", "snippet": "cat ~/.aws", "install_time": True}
    fd, path = tempfile.mkstemp(prefix="ggs-bla-", suffix=".json"); os.close(fd)
    try:
        baseline.write_baseline(path, [crit], "test")
        warnings = baseline.audit(baseline.load(path))
        if warnings and any("CRITICAL" in w for w in warnings) and any("install-time" in w for w in warnings):
            print("  PASS: audit flagged the grandfathered critical + install-time entry")
        else:
            failed = True
            print(f"  FAIL: audit warnings = {warnings}")
    finally:
        os.remove(path)


def test_baseline_gate_refusal():
    """Policy 1: the --url gate must refuse --baseline (a hostile target can't grandfather its own
    findings). Rejected before any fetch, so no network."""
    global failed
    print("\n--- baseline: gate refuses --baseline ---")
    r = subprocess.run([sys.executable, SCAN_PY, "--url", "owner/repo", "--baseline", "x.json"],
                       capture_output=True, text=True)
    if r.returncode != 0 and "do not apply to a --url gate" in (r.stdout + r.stderr):
        print("  PASS: --url + --baseline refused before fetch")
    else:
        failed = True
        print(f"  FAIL: rc={r.returncode}, out={(r.stdout + r.stderr)[:120]!r}")


def test_gate_resolve_url():
    """resolve_url must accept https/git URLs and owner/repo shorthand, and refuse every
    transport that can run or read a local resource (ext::, file://, ssh, scp-style, bare path).
    The protocol allowlist is the gate's single most important fetch hardening."""
    global failed
    print("\n--- gate: URL resolution + protocol refusal ---")
    ok = [("kidsmeal/git-gud-security", "https://github.com/kidsmeal/git-gud-security"),
          ("https://github.com/a/b.git", "https://github.com/a/b.git")]
    bad = ["ext::sh -c whoami", "file:///etc/passwd", "git@github.com:a/b",
           "ssh://host/x", "../local/path", ""]
    problems = []
    for spec, want in ok:
        try:
            got = gate.resolve_url(spec)
            if got != want:
                problems.append(f"{spec!r} -> {got!r}, wanted {want!r}")
        except gate.GateError as e:
            problems.append(f"{spec!r} wrongly refused: {e}")
    for spec in bad:
        try:
            gate.resolve_url(spec)
            problems.append(f"LEAK: accepted dangerous target {spec!r}")
        except gate.GateError:
            pass
    if problems:
        failed = True
        print("  FAIL: " + "; ".join(problems))
    else:
        print(f"  PASS: {len(ok)} accepted, {len(bad)} dangerous targets refused")


def test_gate_classify():
    """classify must name the artifact from on-disk signals. Skill fixtures -> skill; a built
    temp mcp/plugin/app -> the matching kind. Wrong classification points the gate at the
    wrong check categories."""
    global failed
    print("\n--- gate: artifact classification ---")
    import tempfile, shutil
    cases = []
    cases.append((os.path.join(FIXTURES, "gate-malicious-skill"), "skill"))
    cases.append((os.path.join(FIXTURES, "gate-clean-skill"), "skill"))
    tmps = []
    try:
        d = tempfile.mkdtemp(prefix="ggs-cls-"); tmps.append(d)
        open(os.path.join(d, "mcp.json"), "w").write("{}")
        cases.append((d, "mcp"))
        d = tempfile.mkdtemp(prefix="ggs-cls-"); tmps.append(d)
        os.makedirs(os.path.join(d, ".claude-plugin"))
        cases.append((d, "plugin"))
        d = tempfile.mkdtemp(prefix="ggs-cls-"); tmps.append(d)
        open(os.path.join(d, "index.js"), "w").write("console.log(1)")
        cases.append((d, "app"))
        problems = []
        for path, want in cases:
            got = gate.classify(path)["primary"]
            if got != want:
                problems.append(f"{os.path.basename(path)} -> {got}, wanted {want}")
        if problems:
            failed = True
            print("  FAIL: " + "; ".join(problems))
        else:
            print(f"  PASS: {len(cases)} artifacts classified correctly")
    finally:
        for d in tmps:
            shutil.rmtree(d, ignore_errors=True)


def test_gate_safe_clone():
    """safe_clone must fetch a pinned checkout, return its SHA, leave no temp dir behind, and
    enforce the size ceiling. Uses a local fixture repo over file:// (test-only protocol
    widening); production callers never widen past https/git."""
    global failed
    print("\n--- gate: hardened clone (sha, size cap, cleanup) ---")
    import tempfile, shutil, glob
    src = tempfile.mkdtemp(prefix="ggs-src-")
    try:
        def git(*a):
            return subprocess.run(["git", "-C", src, *a], capture_output=True, text=True)
        if git("init", "-q").returncode != 0:
            print("  SKIP: git unavailable")
            shutil.rmtree(src, ignore_errors=True)
            return
        git("config", "user.email", "t@t.co"); git("config", "user.name", "t")
        open(os.path.join(src, "SKILL.md"), "w").write("---\nname: x\n---\n")
        git("add", "-A"); git("commit", "-q", "-m", "init")
        url = "file://" + src.replace("\\", "/")
        problems = []

        repo_dir, sha, work = gate.safe_clone(url, allow_protocols=("file",))
        if not (len(sha) == 40 and gate.classify(repo_dir)["primary"] == "skill"):
            problems.append(f"clone returned sha={sha!r}, classify off")
        gate.cleanup(work)
        if os.path.exists(work):
            problems.append("workdir not cleaned up after cleanup()")

        # size ceiling: a 1-byte cap must refuse and leave nothing behind.
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "ggs-gate-*")))
        try:
            gate.safe_clone(url, max_bytes=1, allow_protocols=("file",))
            problems.append("size cap not enforced")
        except gate.GateError:
            pass
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "ggs-gate-*")))
        if after - before:
            problems.append("size-cap refusal stranded a temp dir")

        # defense in depth: even if an ext:: URL reached safe_clone, the protocol allowlist
        # (https/git only) must make git refuse it rather than run the command.
        try:
            gate.safe_clone("ext::sh -c touch\\ pwned", allow_protocols=("https", "git"))
            problems.append("ext:: URL was not refused by the clone")
        except gate.GateError:
            pass

        if problems:
            failed = True
            print("  FAIL: " + "; ".join(problems))
        else:
            print("  PASS: pinned sha, size cap enforced, no temp dirs stranded, ext:: refused")
    finally:
        gate._rmtree(src)


def test_gate_verdict():
    """The three-level verdict keys on install-time risk: a critical/high that fires on load
    blocks; a non-install-time finding (their leaked key) is advisory; nothing is clean."""
    global failed
    print("\n--- gate: verdict thresholds ---")
    def mk(sev, it):
        return {"severity": sev, "install_time": it}
    cases = [
        ([mk("critical", True)], "DO NOT INSTALL"),
        ([mk("high", True)], "DO NOT INSTALL"),
        ([mk("critical", False)], "REVIEW FIRST"),   # real, but not install-time
        ([mk("medium", True)], "REVIEW FIRST"),       # install-time but below block threshold
        ([], "LOOKS CLEAN"),
    ]
    problems = []
    for findings, want in cases:
        got = scan.gate_verdict(findings)
        if got != want:
            problems.append(f"{findings} -> {got}, wanted {want}")
    if problems:
        failed = True
        print("  FAIL: " + "; ".join(problems))
    else:
        print(f"  PASS: all {len(cases)} verdict thresholds correct")


def test_gate_format():
    """End to end through the CLI: a malicious skill fixture must render DO NOT INSTALL with the
    exfil hook under INSTALL-TIME RISKS; a clean skill must render LOOKS CLEAN. Proves
    install_time stamping + the gate formatter wire together on real scanned findings."""
    global failed
    print("\n--- gate: --format gate end to end ---")
    problems = []
    mal = subprocess.run([sys.executable, SCAN_PY,
                          os.path.join(FIXTURES, "gate-malicious-skill"), "--format", "gate"],
                         capture_output=True, text=True)
    if "DO NOT INSTALL" not in mal.stdout:
        problems.append("malicious skill did not render DO NOT INSTALL")
    if "INSTALL-TIME RISKS" not in mal.stdout or "hook-exfiltrates-env-or-credentials" not in mal.stdout:
        problems.append("exfil hook not surfaced as an install-time risk")
    clean = subprocess.run([sys.executable, SCAN_PY,
                            os.path.join(FIXTURES, "gate-clean-skill"), "--format", "gate"],
                           capture_output=True, text=True)
    if "LOOKS CLEAN" not in clean.stdout:
        problems.append("clean skill did not render LOOKS CLEAN")
    if problems:
        failed = True
        print("  FAIL: " + "; ".join(problems))
    else:
        print("  PASS: malicious -> DO NOT INSTALL (install-time), clean -> LOOKS CLEAN")


if __name__ == "__main__":
    if UPDATE:
        # Only regenerate the goldens; skip assertions.
        test_findings_exact("quick")
        test_findings_exact("readme")
        print("\nGoldens updated. Review the diff before committing.")
        sys.exit(0)

    test_json_valid()
    test_pattern_check_alignment()
    test_severity_synced()
    test_counts_match()
    test_version_in_sync()
    test_every_pattern_has_fixture()
    test_full_ultra_route_to_skill()
    test_secrets_redacted()
    test_scrub_covers_token_formats()
    test_long_line_bundle()
    test_sarif_output()
    test_fail_on_exit_code()
    test_staged_scope()
    test_action_manifest()
    test_gate_resolve_url()
    test_gate_classify()
    test_gate_safe_clone()
    test_gate_verdict()
    test_gate_format()
    test_exclude_glob()
    test_diff_scope()
    test_baseline_fingerprint_stable()
    test_baseline_roundtrip()
    test_baseline_audit()
    test_baseline_gate_refusal()
    test_findings_exact("quick")
    test_findings_exact("readme")
    test_false_positives("quick")
    test_false_positives("readme")

    print()
    if failed:
        print("RESULT: FAIL")
        sys.exit(1)
    else:
        print("RESULT: PASS")
        sys.exit(0)
