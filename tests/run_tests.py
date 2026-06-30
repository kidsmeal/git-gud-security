#!/usr/bin/env python3
"""Test runner for git-gud-security scanner.

Runs scan.py against fixture directories and compares the set of
pattern IDs that fire against the expected set. Exits 0 on pass, 1 on fail.

Usage:
    python tests/run_tests.py
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

failed = False


def run_scan(target, mode):
    result = subprocess.run(
        [sys.executable, SCAN_PY, target, "--mode", mode],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  FAIL: scan.py exited {result.returncode}")
        print(f"  stderr: {result.stderr.strip()}")
        return None
    return json.loads(result.stdout)


def test_true_positives(mode):
    global failed
    target = os.path.join(FIXTURES, "true-positives")
    expected_file = os.path.join(EXPECTED, f"{mode}.json")

    print(f"\n--- true-positives ({mode} mode) ---")
    actual = run_scan(target, mode)
    if actual is None:
        failed = True
        return

    actual_ids = sorted(set(f["id"] for f in actual["findings"]))

    with open(PATTERNS_JSON, encoding="utf-8") as f:
        all_patterns = json.load(f)["patterns"]
    all_ids = sorted(p["id"] for p in all_patterns)

    if mode == "quick":
        expected_ids = sorted(set(all_ids))
    else:
        with open(expected_file, encoding="utf-8") as f:
            expected = json.load(f)
        expected_ids = sorted(set(f["id"] for f in expected["findings"]))

    missing = sorted(set(expected_ids) - set(actual_ids))
    unexpected = sorted(set(actual_ids) - set(expected_ids))

    if missing:
        print(f"  FAIL: {len(missing)} patterns did not fire:")
        for pid in missing:
            print(f"    - {pid}")
        failed = True
    if unexpected and mode != "quick":
        print(f"  WARN: {len(unexpected)} unexpected patterns fired:")
        for pid in unexpected:
            print(f"    + {pid}")

    if not missing and not unexpected:
        print(f"  PASS: {len(actual_ids)} / {len(expected_ids)} patterns fired")
    elif not missing:
        print(f"  PASS: all {len(expected_ids)} expected patterns fired ({len(unexpected)} extra)")


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
    actual = run_scan(target, mode)
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
        print(f"  WARN: {len(orphans)} pattern IDs don't exactly match a check ID (naming drift)")
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
    test_json_valid()
    test_pattern_check_alignment()
    test_counts_match()
    test_every_pattern_has_fixture()
    test_full_ultra_route_to_skill()
    test_true_positives("quick")
    test_true_positives("readme")
    test_false_positives("quick")
    test_false_positives("readme")

    print()
    if failed:
        print("RESULT: FAIL")
        sys.exit(1)
    else:
        print("RESULT: PASS")
        sys.exit(0)
