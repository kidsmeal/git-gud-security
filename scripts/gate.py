#!/usr/bin/env python3
"""
Git Gud Security - pre-install gate (fetch + classify).

The gate vets an UNTRUSTED skill / MCP server / plugin from a URL *before* it's installed
into ~/.claude. This module does the two deterministic, no-LLM steps the gate needs:

  1. safe_clone  - fetch the URL into an isolated throwaway dir. The repo is written by
                   someone trying to attack the scanner, so the clone is hardened: pinned
                   shallow checkout, an explicit git protocol allowlist (no ext::/file://
                   local-exec or local-read tricks), an isolated HOME with system/global
                   git config off, no submodule recursion, no clone-time template hooks,
                   a wall-clock timeout, and a post-clone size ceiling. Static read only;
                   the target's code is never executed.
  2. classify    - decide what the artifact is (skill / plugin / mcp / agent-config / app)
                   from on-disk signals, so the scan can lead with the right check
                   categories and the verdict can name what it vetted.

No third-party deps. Python 3.8+. scan.py imports this for `scan.py --url`.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Only these git transports are ever allowed. https/git are real remote fetches; everything
# else (ext::, file://, ssh) is refused so a crafted URL can't run a local command or read a
# local path during the clone. This is the single most important hardening in the fetch.
ALLOWED_PROTOCOLS = ("https", "git")

# A gate target is small by nature (a skill, an MCP server, a plugin). Refuse anything that
# blows past this so a hostile repo can't fill the disk or stall the scan. Counts the working
# tree, not .git.
DEFAULT_MAX_BYTES = 80_000_000  # 80 MB
DEFAULT_TIMEOUT = 120  # seconds for the clone itself


class GateError(Exception):
    """Fetch/classify failed in a way the caller should report, not crash on."""


# owner/repo shorthand: letters, digits, dot, underscore, hyphen on each side.
_OWNER_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")


def resolve_url(spec):
    """Normalize a user-supplied target to a clone URL, or raise GateError.

    Accepts a full https:// or git:// URL, or `owner/repo` shorthand (assumed GitHub).
    Refuses every other transport (ssh, file, ext, scp-style host:path) so the clone can't
    be steered into a local-exec or local-read primitive.
    """
    spec = spec.strip()
    if not spec:
        raise GateError("empty URL")
    # Strip a trailing .git and trailing slashes for the shorthand check, but keep the
    # original for real URLs (git is fine with .git suffixes).
    if "://" in spec:
        proto = spec.split("://", 1)[0].lower()
        if proto not in ALLOWED_PROTOCOLS:
            raise GateError(
                f"refusing {proto}:// URL: the gate only fetches over https/git "
                f"(no ssh/file/ext, which can run or read local resources)")
        return spec
    # No scheme: must be owner/repo shorthand. Reject scp-style (git@host:path) and bare
    # paths outright — both are ways to point the clone at something local or non-https.
    if spec.startswith("git@") or spec.startswith("ssh:") or os.sep in spec or ":" in spec:
        raise GateError(f"unrecognized target {spec!r}: use a https URL or owner/repo")
    if not _OWNER_REPO.match(spec):
        raise GateError(f"unrecognized target {spec!r}: use a https URL or owner/repo")
    return f"https://github.com/{spec}"


def _isolated_git_env():
    """A git environment that ignores the caller's and the target's config.

    Points HOME at a throwaway dir and turns off system/global config so nothing the host
    user has set (or anything a malicious repo could plant) changes how the clone behaves.
    """
    env = dict(os.environ)
    home = tempfile.mkdtemp(prefix="ggs-gate-home-")
    env["HOME"] = home
    env["USERPROFILE"] = home  # Windows HOME equivalent
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"  # never block waiting for credentials
    env["GIT_ASKPASS"] = ""
    env["GCM_INTERACTIVE"] = "never"
    return env, home


def _dir_size(path):
    total = 0
    for root, dirs, files in os.walk(path):
        if ".git" in dirs:
            dirs.remove(".git")  # measure the working tree, not git internals
        for name in files:
            fp = os.path.join(root, name)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def safe_clone(url, ref=None, max_bytes=DEFAULT_MAX_BYTES, timeout=DEFAULT_TIMEOUT,
               allow_protocols=ALLOWED_PROTOCOLS):
    """Hardened shallow clone of an untrusted URL into a throwaway dir.

    Returns (repo_dir, sha, workdir). The caller owns `workdir` and must cleanup() it.
    Raises GateError on a refused protocol, clone failure, timeout, or size-cap breach.

    allow_protocols is overridable only so the test suite can clone a local fixture over
    file://; production callers must never widen it.
    """
    workdir = tempfile.mkdtemp(prefix="ggs-gate-")
    dest = os.path.join(workdir, "repo")
    env, home = _isolated_git_env()

    # protocol.allow=never + an explicit allowlist is what blocks ext:: (arbitrary command
    # exec) and file:// (local read). init.templateDir= disables clone-time template hooks.
    cfg = ["-c", "protocol.allow=never", "-c", "init.templateDir="]
    for proto in allow_protocols:
        cfg += ["-c", f"protocol.{proto}.allow=always"]

    cmd = ["git", *cfg, "clone", "--depth", "1", "--no-tags", "--single-branch",
           "--no-recurse-submodules", "--quiet"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, dest]

    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _rmtree(workdir); _rmtree(home)
        raise GateError(f"clone timed out after {timeout}s")
    except FileNotFoundError:
        _rmtree(workdir); _rmtree(home)
        raise GateError("git not found on PATH; the gate needs git to fetch the target")
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = msg[-1] if msg else f"exit {proc.returncode}"
        _rmtree(workdir); _rmtree(home)
        raise GateError(f"clone failed: {detail}")

    size = _dir_size(dest)
    if size > max_bytes:
        _rmtree(workdir); _rmtree(home)
        raise GateError(
            f"target is {size // 1_000_000} MB, over the {max_bytes // 1_000_000} MB gate "
            f"ceiling; fetch and review it yourself")

    sha = _rev_parse(dest, env)
    _rmtree(home)  # the isolated HOME is only needed during the clone
    return dest, sha, workdir


def _rev_parse(dest, env):
    try:
        proc = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"],
                              env=env, capture_output=True, text=True, timeout=15)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return "unknown"


def _on_rm_error(func, path, _exc):
    # git writes pack/object files read-only; on Windows rmtree can't unlink those until the
    # read-only bit is cleared. Clear it and retry, so a gate run never strands a temp clone.
    try:
        os.chmod(path, 0o700)
        func(path)
    except OSError:
        pass


def _rmtree(path):
    if not os.path.exists(path):
        return
    # onexc (3.12+) supersedes onerror; pass whichever this Python accepts.
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_on_rm_error)
    else:
        shutil.rmtree(path, onerror=_on_rm_error)


def cleanup(workdir):
    """Delete a workdir returned by safe_clone. Safe to call more than once."""
    if workdir:
        _rmtree(workdir)


# --- classification -------------------------------------------------------------------------
# Each artifact kind is decided by on-disk signals only (no prose trust). A repo can match
# more than one; `primary` is the highest-priority match, since that's the surface the gate
# should lead with. Priority: skill > plugin > mcp > agent-config > app.

def _exists(root, *rel):
    return os.path.exists(os.path.join(root, *rel))


def _find_shallow(root, name, max_depth=2):
    """True if a file named `name` exists within max_depth dirs of root."""
    root = os.path.abspath(root)
    for cur, dirs, files in os.walk(root):
        if ".git" in dirs:
            dirs.remove(".git")
        depth = cur[len(root):].count(os.sep)
        if depth >= max_depth:
            dirs[:] = []
        if name in files:
            return True
    return False


def classify(repo_dir):
    """Return {'primary': <kind>, 'signals': [<kind>...], 'evidence': {kind: path}}.

    Kinds: skill, plugin, mcp, agent-config, app. Deterministic, file-signal based.
    """
    evidence = {}

    if _find_shallow(repo_dir, "SKILL.md"):
        evidence["skill"] = "SKILL.md"

    if _exists(repo_dir, ".claude-plugin") or _find_shallow(repo_dir, "plugin.json"):
        evidence["plugin"] = ".claude-plugin/" if _exists(repo_dir, ".claude-plugin") else "plugin.json"

    for mcp_name in ("mcp.json", ".mcp.json"):
        if _find_shallow(repo_dir, mcp_name):
            evidence["mcp"] = mcp_name
            break
    if "mcp" not in evidence and _mentions_mcp_server(repo_dir):
        evidence["mcp"] = "package.json (mcp server deps)"

    for cfg_signal in (".claude", "hooks", "AGENTS.md", ".cursorrules",
                       ".github/copilot-instructions.md"):
        if _exists(repo_dir, *cfg_signal.split("/")):
            evidence["agent-config"] = cfg_signal
            break

    priority = ["skill", "plugin", "mcp", "agent-config"]
    signals = [k for k in priority if k in evidence]
    primary = signals[0] if signals else "app"
    if not signals:
        evidence["app"] = "(no skill/plugin/mcp/agent signals)"
    return {"primary": primary, "signals": signals or ["app"], "evidence": evidence}


def _mentions_mcp_server(repo_dir):
    """A package.json that depends on an MCP server SDK is an MCP artifact even without
    an mcp.json (the server is the thing being shipped)."""
    pkg = os.path.join(repo_dir, "package.json")
    if not os.path.isfile(pkg):
        return False
    try:
        with open(pkg, encoding="utf-8", errors="replace") as f:
            text = f.read(200_000)
    except OSError:
        return False
    return "@modelcontextprotocol/sdk" in text or "modelcontextprotocol" in text
