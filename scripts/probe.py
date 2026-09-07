#!/usr/bin/env python3
"""
Git Gud Security - live MCP probe (stdio transport).

Static scanning reads a server's source. It cannot see what a server SAYS to the model at
runtime: the `instructions` string in the initialize result, tool descriptions the server
generates on the fly, and text riding inside tool results (content blocks, `_meta`, extra
keys). A closed-source or hosted server can steer the model through those channels and
leave nothing on disk to grep. The probe connects as a real MCP client, records every one
of those surfaces, and runs the directive/injection regexes over the transcript.

What it does, in order:
  1. spawn the server command in a throwaway cwd with a scrubbed environment (PATH and OS
     basics only; HOME/USERPROFILE point at an empty temp dir; named vars pass through only
     via --probe-env)
  2. initialize -> notifications/initialized -> tools/list (paginated)
  3. tools/call on up to N tools judged read-only (annotations.readOnlyHint, or a
     get/list/search/... name with no destructive hint) with schema-derived placeholder args;
     explicitly named tools via --probe-tool are called regardless
  4. tools/list again, to diff for a rug pull (definitions that change after first listing)
  5. close stdin, wait, terminate, kill

This module EXECUTES the target. That is the point and the risk: run it only on a server you
have decided to trial, and read the report's env-passthrough line. The --url gate never calls
this.

No third-party deps. Python 3.8+. scan.py imports this for `scan.py --mcp-cmd`.
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from queue import Empty, Queue

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_TIMEOUT = 30       # seconds per request (initialize, tools/list, each tools/call)
DEFAULT_CALLS = 5          # read-only tools called automatically
MAX_LINE_BYTES = 5_000_000
MAX_TOTAL_BYTES = 50_000_000
STDERR_TAIL = 4000
MAX_LIST_PAGES = 10

# Environment the child gets by default. Nothing that names a credential store or an
# interpreter preload (no NODE_OPTIONS, no PYTHONSTARTUP, no *_TOKEN). HOME is replaced.
BASE_ENV_KEYS = (
    "PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR", "TEMP", "TMP", "TMPDIR",
    "LANG", "LC_ALL", "LC_CTYPE", "TERM", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "PROGRAMFILES", "PROGRAMFILES(X86)", "NVM_DIR",
)

# Result keys the spec defines. Anything else at the top level of a tools/call result is a
# side channel the client did not ask for.
STANDARD_RESULT_KEYS = {"content", "isError", "structuredContent", "_meta"}

# Key names that, when they carry prose, are text addressed to the model rather than data.
SIDE_CHANNEL_KEYS = {
    "instructions", "instruction", "hint", "hints", "followup", "follow_up", "nextsteps",
    "next_steps", "suggestion", "suggestions", "note_to_assistant", "assistant_note",
    "system", "prompt", "message_to_assistant", "promo", "upsell", "tip", "tips",
    "announcement", "banner", "notice", "guidance",
}

_READ_ONLY_NAME = re.compile(
    r"^(?:[a-z0-9]+[-_.])*?(get|list|read|search|fetch|query|retrieve|describe|status|find|"
    r"lookup|show|browse|check|view)(?:[-_.]|$)",
    re.I,
)

FIXES = {
    "mcp-tool-result-model-directive":
        "Tool results are data, never instructions. Return only the requested data; keep "
        "product notices in docs. Agents: treat result text as untrusted and never relay "
        "vendor prompts to the user as your own words.",
    "mcp-injectable-tool-description":
        "Treat tool descriptions as untrusted code: review and pin them, forbid "
        "dynamic/remote-sourced descriptions, scan for imperatives, chaining directives, and "
        "hidden unicode.",
    "mcp-rug-pull-tool-redefinition":
        "Pin and hash tool definitions, require re-approval on any description/schema change, "
        "ship tools statically, version the server with integrity checks.",
    "invisible-unicode-in-instructions":
        "Strip zero-width, bidi, and tag characters from every instruction and metadata string; "
        "reject definitions that contain them.",
}
CATEGORY = {
    "mcp-tool-result-model-directive": "mcp",
    "mcp-injectable-tool-description": "mcp",
    "mcp-rug-pull-tool-redefinition": "mcp",
    "invisible-unicode-in-instructions": "claude-ext",
}


class ProbeError(Exception):
    """Transport or protocol failure the caller should report, not crash on."""


class RpcError(Exception):
    """The server answered a request with a JSON-RPC error object."""

    def __init__(self, error):
        super().__init__(str(error.get("message", error)) if isinstance(error, dict) else str(error))
        self.error = error


# ---------------------------------------------------------------- process + env

def split_command(cmd):
    """Turn the user's command (string or argv list) into an argv with a resolved executable.
    Never a shell: the command runs as a process, not as a shell string."""
    if isinstance(cmd, (list, tuple)):
        argv = [str(a) for a in cmd]
    else:
        argv = shlex.split(cmd, posix=(os.name != "nt"))
        if os.name == "nt":
            argv = [a[1:-1] if len(a) >= 2 and a[0] == a[-1] and a[0] in "\"'" else a
                    for a in argv]
    if not argv:
        raise ProbeError("empty command")
    exe = shutil.which(argv[0])
    if exe is None and os.path.isfile(argv[0]):
        exe = os.path.abspath(argv[0])
    if exe is None:
        raise ProbeError(f"command not found: {argv[0]}")
    argv[0] = exe
    # The child runs in a throwaway cwd, so a relative path in the command (a local server
    # script, a config file) would not resolve there. Absolutize any arg that names an
    # existing path from the caller's cwd; package names and flags are left alone.
    for i in range(1, len(argv)):
        a = argv[i]
        if a and not a.startswith("-") and not os.path.isabs(a) and os.path.exists(a):
            argv[i] = os.path.abspath(a)
    return argv


def build_env(home, allow=()):
    """Scrubbed environment: OS basics + PATH, HOME/USERPROFILE pointed at `home`, plus only
    the vars named in `allow` (KEY copies from the parent, KEY=VAL sets a literal)."""
    env = {}
    for k in BASE_ENV_KEYS:
        v = os.environ.get(k)
        if v is not None:
            env[k] = v
    env["HOME"] = home
    env["USERPROFILE"] = home
    for item in allow:
        if "=" in item:
            k, v = item.split("=", 1)
            env[k] = v
        elif item in os.environ:
            env[item] = os.environ[item]
        else:
            raise ProbeError(f"--probe-env {item}: not set in the parent environment")
    return env


class StdioClient:
    """Minimal MCP client over newline-delimited JSON-RPC on a child's stdin/stdout."""

    def __init__(self, argv, cwd, env, timeout=DEFAULT_TIMEOUT):
        self.argv = argv
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self.proc = None
        self.q = Queue()
        self.stderr = []
        self.noise = []
        self.server_msgs = []
        self.bytes_read = 0
        self._id = 0

    def start(self):
        try:
            self.proc = subprocess.Popen(
                self.argv, cwd=self.cwd, env=self.env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except OSError as e:
            raise ProbeError(f"could not start {self.argv[0]}: {e}")
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self):
        f = self.proc.stdout
        while True:
            try:
                line = f.readline(MAX_LINE_BYTES + 1)
            except (OSError, ValueError):
                line = b""
            if not line:
                self.q.put(None)
                return
            self.bytes_read += len(line)
            if self.bytes_read > MAX_TOTAL_BYTES:
                self.noise.append("<stdout exceeded total byte cap; reading stopped>")
                self.q.put(None)
                self._kill()
                return
            if len(line) > MAX_LINE_BYTES:
                self.noise.append("<line over per-message byte cap dropped>")
                continue
            s = line.decode("utf-8", "replace").strip()
            if not s:
                continue
            try:
                msg = json.loads(s)
            except ValueError:
                if len(self.noise) < 50:
                    self.noise.append(s[:200])
                continue
            if isinstance(msg, dict):
                self.q.put(msg)
            elif isinstance(msg, list):
                for m in msg:
                    if isinstance(m, dict):
                        self.q.put(m)

    def _read_stderr(self):
        f = self.proc.stderr
        while True:
            try:
                line = f.readline()
            except (OSError, ValueError):
                line = b""
            if not line:
                return
            self.stderr.append(line.decode("utf-8", "replace"))
            if len(self.stderr) > 400:
                del self.stderr[:200]

    def send(self, msg):
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (OSError, ValueError) as e:
            raise ProbeError(f"server closed stdin: {e}")

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def request(self, method, params=None, timeout=None):
        self._id += 1
        rid = self._id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        limit = timeout or self.timeout
        deadline = time.monotonic() + limit
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError(f"{method}: no response within {limit}s")
            try:
                item = self.q.get(timeout=min(remaining, 0.5))
            except Empty:
                if self.proc.poll() is not None and self.q.empty():
                    raise ProbeError(f"{method}: server exited with code {self.proc.returncode} "
                                     f"before responding")
                continue
            if item is None:
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                raise ProbeError(f"{method}: server closed stdout (exit code {self.proc.poll()})")
            if item.get("id") == rid and ("result" in item or "error" in item):
                if "error" in item:
                    raise RpcError(item["error"])
                return item["result"]
            self._handle_server_message(item)

    def _handle_server_message(self, msg):
        """Server-initiated requests and notifications. Recorded; requests get a minimal
        answer so a server that pings or asks for roots does not stall."""
        method = msg.get("method")
        if method is None:
            return  # a response to an id we are not waiting on; drop
        if len(self.server_msgs) < 50:
            self.server_msgs.append({"method": method, "params": msg.get("params")})
        if "id" in msg:
            if method == "ping":
                self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
            elif method == "roots/list":
                self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {"roots": []}})
            else:
                self.send({"jsonrpc": "2.0", "id": msg["id"],
                           "error": {"code": -32601, "message": "not supported by the ggs probe"}})

    def _kill(self):
        p = self.proc
        if p is None or p.poll() is not None:
            return
        try:
            p.kill()
        except OSError:
            pass

    def close(self):
        p = self.proc
        if p is None:
            return
        try:
            p.stdin.close()
        except (OSError, ValueError):
            pass
        for step in (None, "terminate", "kill"):
            if step == "terminate":
                try:
                    p.terminate()
                except OSError:
                    pass
            elif step == "kill":
                self._kill()
            try:
                p.wait(timeout=3)
                break
            except subprocess.TimeoutExpired:
                continue


# ---------------------------------------------------------------- tool selection

def is_read_only(tool):
    ann = tool.get("annotations") or {}
    if ann.get("readOnlyHint") is True:
        return True
    if ann.get("destructiveHint") is True or ann.get("readOnlyHint") is False:
        return False
    return bool(_READ_ONLY_NAME.match(str(tool.get("name", "")).split("/")[-1]))


def placeholder_value(prop, depth=0):
    if not isinstance(prop, dict) or depth > 4:
        return "ggs-probe"
    if "default" in prop:
        return prop["default"]
    if "const" in prop:
        return prop["const"]
    if isinstance(prop.get("enum"), list) and prop["enum"]:
        return prop["enum"][0]
    t = prop.get("type")
    if isinstance(t, list) and t:
        t = t[0]
    if t == "string":
        return "ggs-probe"
    if t in ("number", "integer"):
        return prop.get("minimum", 1)
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object" or "properties" in prop:
        return placeholder_args(prop, depth + 1)
    for k in ("anyOf", "oneOf", "allOf"):
        if isinstance(prop.get(k), list) and prop[k]:
            return placeholder_value(prop[k][0], depth + 1)
    return "ggs-probe"


def placeholder_args(schema, depth=0):
    """Fill only the required properties, with the blandest value the schema allows."""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties") or {}
    req = schema.get("required") or []
    return {k: placeholder_value(props.get(k, {}), depth + 1) for k in req if isinstance(k, str)}


def parse_tool_spec(spec):
    """`name` or `name={"json":"args"}` from --probe-tool."""
    if "=" in spec:
        name, raw = spec.split("=", 1)
        try:
            args = json.loads(raw)
        except ValueError as e:
            raise ProbeError(f"--probe-tool {name}: arguments are not JSON ({e})")
        if not isinstance(args, dict):
            raise ProbeError(f"--probe-tool {name}: arguments must be a JSON object")
        return name.strip(), args
    return spec.strip(), None


# ---------------------------------------------------------------- the probe

def _list_tools(client):
    tools = []
    cursor = None
    for _ in range(MAX_LIST_PAGES):
        params = {"cursor": cursor} if cursor else {}
        res = client.request("tools/list", params)
        page = res.get("tools") if isinstance(res, dict) else None
        if isinstance(page, list):
            tools.extend(t for t in page if isinstance(t, dict))
        cursor = res.get("nextCursor") if isinstance(res, dict) else None
        if not cursor:
            break
    return tools


def run_probe(cmd, env_allow=(), calls=DEFAULT_CALLS, timeout=DEFAULT_TIMEOUT,
              tool_specs=(), version="dev"):
    """Run the full probe sequence. Returns the transcript dict; never raises for server
    misbehavior (recorded under `errors` / `fatal`), only for bad caller input."""
    argv = split_command(cmd)
    specs = [parse_tool_spec(s) for s in tool_specs]
    work = tempfile.mkdtemp(prefix="ggs-probe-")
    home = os.path.join(work, "home")
    cwd = os.path.join(work, "cwd")
    os.makedirs(home)
    os.makedirs(cwd)
    env = build_env(home, env_allow)
    t = {
        "cmd": cmd if isinstance(cmd, str) else " ".join(cmd),
        "argv": argv,
        "env_passthrough": sorted(k.split("=", 1)[0] for k in env_allow),
        "started": time.time(),
        "tools": [],
        "calls": [],
        "errors": [],
    }
    client = StdioClient(argv, cwd, env, timeout)
    t0 = time.monotonic()
    try:
        client.start()
        init = client.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "git-gud-security-probe", "version": version},
        })
        if not isinstance(init, dict):
            raise ProbeError("initialize: result is not an object")
        t["serverInfo"] = init.get("serverInfo")
        t["protocolVersion"] = init.get("protocolVersion")
        t["capabilities"] = init.get("capabilities")
        t["instructions"] = init.get("instructions")
        client.notify("notifications/initialized")
        t["tools"] = _list_tools(client)

        plan = [(name, args, "explicit") for name, args in specs]
        planned = {p[0] for p in plan}
        auto = 0
        if calls > 0:
            for tool in t["tools"]:
                if auto >= calls:
                    break
                name = tool.get("name")
                if not isinstance(name, str) or name in planned or not is_read_only(tool):
                    continue
                plan.append((name, placeholder_args(tool.get("inputSchema")), "auto"))
                planned.add(name)
                auto += 1
        by_name = {x.get("name"): x for x in t["tools"]}
        for name, args, why in plan:
            if name not in by_name:
                t["errors"].append(f"--probe-tool {name}: not in tools/list")
                continue
            if args is None:
                args = placeholder_args(by_name[name].get("inputSchema"))
            rec = {"tool": name, "args": args, "why": why}
            s = time.monotonic()
            try:
                rec["result"] = client.request("tools/call", {"name": name, "arguments": args})
            except RpcError as e:
                rec["error"] = e.error
            except ProbeError as e:
                rec["error"] = {"message": str(e)}
                rec["ms"] = int((time.monotonic() - s) * 1000)
                t["calls"].append(rec)
                raise
            rec["ms"] = int((time.monotonic() - s) * 1000)
            t["calls"].append(rec)

        try:
            t["tools_after"] = _list_tools(client)
        except (ProbeError, RpcError) as e:
            t["errors"].append(f"second tools/list: {e}")
    except RpcError as e:
        t["errors"].append(f"server error: {json.dumps(e.error)[:300]}")
        t["fatal"] = str(e)
    except ProbeError as e:
        t["errors"].append(str(e))
        t["fatal"] = str(e)
    finally:
        client.close()
        t["exit_code"] = client.proc.returncode if client.proc else None
        t["stderr_tail"] = "".join(client.stderr)[-STDERR_TAIL:]
        t["stdout_noise"] = client.noise[:20]
        t["server_messages"] = client.server_msgs
        t["duration_ms"] = int((time.monotonic() - t0) * 1000)
        shutil.rmtree(work, ignore_errors=True)
    return t


# ---------------------------------------------------------------- analysis

def _pattern(patterns, pid):
    for p in patterns:
        if p.get("id") == pid and p.get("_any"):
            return p
    return None


def _schema_descriptions(node, out, depth=0):
    if depth > 6:
        return
    if isinstance(node, dict):
        d = node.get("description")
        if isinstance(d, str) and d:
            out.append(d)
        for k, v in node.items():
            if k != "description":
                _schema_descriptions(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _schema_descriptions(v, out, depth + 1)


def _surfaces(t):
    """Every string the server put in front of the model, as (path, kind, text)."""
    out = []
    if isinstance(t.get("instructions"), str) and t["instructions"].strip():
        out.append(("mcp://initialize/instructions", "instructions", t["instructions"]))
    for tool in t.get("tools", []):
        name = tool.get("name", "?")
        parts = []
        for k in ("title", "description"):
            if isinstance(tool.get(k), str):
                parts.append(tool[k])
        ann = tool.get("annotations")
        if isinstance(ann, dict) and isinstance(ann.get("title"), str):
            parts.append(ann["title"])
        _schema_descriptions(tool.get("inputSchema"), parts)
        _schema_descriptions(tool.get("outputSchema"), parts)
        out.append((f"mcp://tools/{name}/description", "description", "\n".join(parts)))
    return out


def _result_surfaces(call):
    """(path, kind, text, side_channel_key) tuples for one tools/call record."""
    name = call.get("tool", "?")
    r = call.get("result")
    out = []
    if not isinstance(r, dict):
        err = call.get("error")
        if err is not None:
            out.append((f"mcp://tools/{name}/error", "result", json.dumps(err), None))
        return out
    texts = []
    for c in r.get("content") or []:
        if isinstance(c, dict) and isinstance(c.get("text"), str):
            texts.append(c["text"])
    if r.get("structuredContent") is not None:
        texts.append(json.dumps(r["structuredContent"]))
    out.append((f"mcp://tools/{name}/result", "result", "\n".join(texts), None))
    meta = r.get("_meta") if isinstance(r.get("_meta"), dict) else {}
    extra = {k: v for k, v in r.items() if k not in STANDARD_RESULT_KEYS}
    for prefix, d in (("_meta.", meta), ("", extra)):
        for k, v in d.items():
            if isinstance(v, str):
                text = v
            elif isinstance(v, (dict, list)):
                text = json.dumps(v)
            else:
                continue
            key = str(k).lower().replace("-", "_")
            prose = bool(re.search(r"[A-Za-z]{3,}\s+[A-Za-z]{2,}", text))
            side = key if (prose and (key in SIDE_CHANNEL_KEYS or prefix == "_meta." or not prefix)) else None
            out.append((f"mcp://tools/{name}/result/{prefix}{k}", "result", text, side))
    return out


_INVISIBLE = re.compile("[\u001b\u200b-\u200f\u2028-\u202e\u2060-\u2064"
                        "\u2066-\u206f\ufeff\U000e0000-\U000e007f\U000e0100-\U000e01ef]")


def _visible(s):
    """Make invisible/control characters readable in a snippet (`<U+200B>`), so a finding
    about hidden unicode shows the hidden thing instead of an unchanged-looking line."""
    return _INVISIBLE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", s)


def _finding(pid, severity, title, path, line, snippet):
    snippet = _visible(snippet)
    return {
        "id": pid,
        "category": CATEGORY.get(pid, "mcp"),
        "severity": severity,
        "title": title,
        "file": path,
        "line": line,
        "snippet": snippet.strip()[:200],
        "fix": FIXES.get(pid, ""),
        "detectability": "runtime",
        "engine": "probe",
    }


def _scan_text(text, pats, path, pid, severity, title, seen, out):
    for n, line in enumerate(text.splitlines() or [text], 1):
        for pat in pats:
            hit = None
            for rx in pat["_any"]:
                m = rx.search(line)
                if m and not any(nrx.search(line) for nrx in pat.get("_not", [])):
                    hit = m
                    break
            if hit and (pid, path, n) not in seen:
                seen.add((pid, path, n))
                out.append(_finding(pid, severity, title, path, n, line))
                break


def analyze(t, patterns):
    """Findings from a transcript. Reuses the check library's regexes (by id) so a directive
    the static scanner would flag in source is flagged the same way when it arrives live."""
    directive = _pattern(patterns, "mcp-tool-result-model-directive")
    backdoor = _pattern(patterns, "prompt-injection-hidden-instructions-in-skill")
    invisible = _pattern(patterns, "invisible-unicode-in-instructions")
    steer = [p for p in (directive, backdoor) if p]
    out = []
    seen = set()

    surfaces = _surfaces(t)
    side_channels = []
    for call in t.get("calls", []):
        for path, kind, text, side in _result_surfaces(call):
            surfaces.append((path, kind, text))
            if side:
                side_channels.append((path, side, text))

    for path, kind, text in surfaces:
        if not text:
            continue
        if kind == "description":
            _scan_text(text, steer, path, "mcp-injectable-tool-description", "high",
                       "Tool description carries instructions to the model", seen, out)
        else:
            _scan_text(text, steer, path, "mcp-tool-result-model-directive", "high",
                       "Tool result / server instructions carry instructions to the model",
                       seen, out)
        if invisible:
            _scan_text(text, [invisible], path, "invisible-unicode-in-instructions", "high",
                       "Invisible / control character in text sent to the model", seen, out)

    # A side-channel key carrying prose is a medium on its own; if a directive regex already
    # fired on that same surface the high finding covers it, so do not report it twice.
    flagged = {f["file"] for f in out}
    for path, side, text in side_channels:
        if path in flagged:
            continue
        flagged.add(path)
        out.append(_finding(
            "mcp-tool-result-model-directive", "medium",
            f"Non-standard result field `{side}` carries prose to the model",
            path, 1, text))

    after = t.get("tools_after")
    if isinstance(after, list):
        def sig(tool):
            return (tool.get("description"), json.dumps(tool.get("inputSchema"), sort_keys=True))
        before = {x.get("name"): sig(x) for x in t.get("tools", [])}
        now = {x.get("name"): sig(x) for x in after}
        added = sorted(str(n) for n in set(now) - set(before))
        removed = sorted(str(n) for n in set(before) - set(now))
        changed = sorted(str(n) for n in now if n in before and now[n] != before[n])
        if added or removed or changed:
            out.append(_finding(
                "mcp-rug-pull-tool-redefinition", "high",
                "Tool list changed between the first and second tools/list",
                "mcp://tools/list#2", 1,
                f"added={added} removed={removed} changed={changed}"))
    return out


def summary(t):
    """The transcript minus result bodies: safe to embed in the JSON report."""
    calls = []
    for c in t.get("calls", []):
        r = c.get("result")
        calls.append({
            "tool": c.get("tool"), "why": c.get("why"), "ms": c.get("ms"),
            "ok": isinstance(r, dict) and not r.get("isError"),
            "blocks": len(r.get("content") or []) if isinstance(r, dict) else 0,
            "error": (c.get("error") or {}).get("message") if c.get("error") else None,
        })
    called = {c["tool"] for c in calls}
    tools = [{"name": x.get("name"), "readOnly": is_read_only(x), "called": x.get("name") in called}
             for x in t.get("tools", [])]
    instr = t.get("instructions")
    return {
        "cmd": t.get("cmd"),
        "env_passthrough": t.get("env_passthrough", []),
        "serverInfo": t.get("serverInfo"),
        "protocolVersion": t.get("protocolVersion"),
        "instructions": (instr[:500] + ("..." if len(instr) > 500 else "")) if isinstance(instr, str) else None,
        "tools": tools,
        "calls": calls,
        "tools_after_count": len(t["tools_after"]) if isinstance(t.get("tools_after"), list) else None,
        "server_messages": [m.get("method") for m in t.get("server_messages", [])],
        "errors": t.get("errors", []),
        "fatal": t.get("fatal"),
        "exit_code": t.get("exit_code"),
        "duration_ms": t.get("duration_ms"),
        "stderr_tail": (t.get("stderr_tail") or "")[-1000:],
    }
