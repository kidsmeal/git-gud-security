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
    """A scanner that prints the secrets it finds is itself a leak (SECURITY.md scopes this
    as a vuln). Assert known fixture secrets never appear verbatim in output, and that
    redaction actually fired (the redacted marker is present), so the test isn't vacuous."""
    global failed
    print("\n--- secret redaction ---")
    target = os.path.join(FIXTURES, "true-positives")
    raw, actual = run_scan(target, "quick")
    if raw is None:
        failed = True
        return
    # Raw secret strings planted in the fixtures, all on lines a pattern matches.
    raw_secrets = [
        "sk-ant-TESTFIXTURE1234567890abcdefghij",
        "sk-ant-BUNDLEFIXTURE1234567890abcdef",
        "AKIAIOSFODNN7FIXTURE",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
        "s3cretP4ssw0rd",
    ]
    leaked = [s for s in raw_secrets if s in raw]
    if leaked:
        failed = True
        print(f"  FAIL: {len(leaked)} secret(s) printed in cleartext:")
        for s in leaked:
            print(f"    - {s[:10]}...")
    elif "***" not in raw:
        failed = True
        print("  FAIL: no redaction marker in output (redaction may not have run)")
    else:
        print(f"  PASS: {len(raw_secrets)} known secrets redacted, none in cleartext")


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


if __name__ == "__main__":
    if UPDATE:
        # Only regenerate the goldens; skip assertions.
        test_findings_exact("quick")
        test_findings_exact("readme")
        print("\nGoldens updated. Review the diff before committing.")
        sys.exit(0)

    test_json_valid()
    test_pattern_check_alignment()
    test_counts_match()
    test_version_in_sync()
    test_every_pattern_has_fixture()
    test_full_ultra_route_to_skill()
    test_secrets_redacted()
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
