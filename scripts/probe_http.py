#!/usr/bin/env python3
"""
Git Gud Security - live MCP probe, Streamable HTTP transport + OAuth 2.1.

Same probe sequence as the stdio transport (probe.py), spoken over HTTPS to a remote MCP
endpoint: POST JSON-RPC, answers as JSON or as a text/event-stream, `Mcp-Session-Id` carried
after initialize. This is the transport hosted servers use (mcp.notion.com and the like), so
it is the only way to read what a closed-source server puts in front of the model.

Auth, in order of preference:
  1. a bearer from an env var named by --bearer-env (never from argv, never printed)
  2. a cached OAuth token in the token file (0600, keyed by endpoint URL), refreshed if expired
  3. the OAuth 2.1 flow the MCP auth spec describes: resource metadata from the 401's
     WWW-Authenticate (or the well-known path), authorization-server metadata, dynamic client
     registration, authorization-code + PKCE (S256) with a loopback redirect the user's browser
     lands on, token exchange. The user clicks consent in their own browser; nothing here sees
     their password.

Tokens are written to the token file only. They never appear in the report, the transcript,
or stdout.

No third-party deps. Python 3.8+. scan.py imports this for `scan.py --mcp-url`.
"""
import base64
import hashlib
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

from probe import PROTOCOL_VERSION, ProbeError, RpcError

USER_AGENT = "git-gud-security-probe"
DEFAULT_TOKEN_FILE = os.path.join(os.path.expanduser("~"), ".ggs", "mcp-tokens.json")
OAUTH_WAIT = 300  # seconds to wait for the browser consent
MAX_BODY = 20_000_000


class AuthRequired(Exception):
    """The endpoint answered 401. Carries the WWW-Authenticate header for discovery."""

    def __init__(self, www_authenticate):
        super().__init__("401 Unauthorized")
        self.www_authenticate = www_authenticate or ""


# ---------------------------------------------------------------- tiny HTTP helper

def _http(method, url, headers=None, body=None, timeout=30, stream=False):
    """Returns (status, headers-dict-lowercased, body-bytes-or-response). Never raises on an
    HTTP error status (returned as data); raises ProbeError on a transport failure."""
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    req.add_header("User-Agent", USER_AGENT)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        try:
            data = e.read(MAX_BODY)
        except Exception:
            data = b""
        return e.code, hdrs, data
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
        raise ProbeError(f"{method} {url}: {getattr(e, 'reason', e)}")
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    if stream:
        return resp.status, hdrs, resp
    data = resp.read(MAX_BODY)
    resp.close()
    return resp.status, hdrs, data


def _json_or_none(data):
    try:
        return json.loads(data.decode("utf-8", "replace") if isinstance(data, bytes) else data)
    except ValueError:
        return None


# ---------------------------------------------------------------- the transport

class HttpClient:
    """Streamable HTTP MCP client with the same request/notify/close surface as StdioClient,
    so probe._run_sequence drives both."""

    def __init__(self, url, token=None, timeout=30):
        self.url = url
        self.token = token
        self.timeout = timeout
        self.session_id = None
        self.proc = None
        self.stderr = []
        self.noise = []
        self.server_msgs = []
        self.http_statuses = []
        self._id = 0

    def start(self):
        pass

    def _headers(self):
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _dispatch(self, msg, want_id):
        """Return (found, result) for the awaited response; record anything else."""
        if not isinstance(msg, dict):
            return False, None
        if want_id is not None and msg.get("id") == want_id and ("result" in msg or "error" in msg):
            if "error" in msg:
                raise RpcError(msg["error"])
            return True, msg["result"]
        method = msg.get("method")
        if method:
            if len(self.server_msgs) < 50:
                self.server_msgs.append({"method": method, "params": msg.get("params")})
            if "id" in msg:
                # A server-to-client request: answer over a fresh POST, per the spec.
                if method == "ping":
                    reply = {"jsonrpc": "2.0", "id": msg["id"], "result": {}}
                elif method == "roots/list":
                    reply = {"jsonrpc": "2.0", "id": msg["id"], "result": {"roots": []}}
                else:
                    reply = {"jsonrpc": "2.0", "id": msg["id"],
                             "error": {"code": -32601, "message": "not supported by the ggs probe"}}
                try:
                    self._post(reply, None)
                except (ProbeError, AuthRequired, RpcError):
                    pass
        return False, None

    def _read_sse(self, resp, want_id, deadline):
        data_lines = []
        while True:
            if time.monotonic() > deadline:
                resp.close()
                raise ProbeError(f"SSE stream: no response within {self.timeout}s")
            try:
                raw = resp.readline()
            except (socket.timeout, OSError) as e:
                resp.close()
                raise ProbeError(f"SSE stream: {e}")
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line == "":
                if data_lines:
                    event = "\n".join(data_lines)
                    data_lines = []
                    msg = _json_or_none(event)
                    if msg is None:
                        if len(self.noise) < 50:
                            self.noise.append(event[:200])
                        continue
                    for m in (msg if isinstance(msg, list) else [msg]):
                        found, result = self._dispatch(m, want_id)
                        if found:
                            resp.close()
                            return True, result
                continue
            if line.startswith(":"):
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        resp.close()
        if data_lines:
            msg = _json_or_none("\n".join(data_lines))
            for m in (msg if isinstance(msg, list) else [msg]):
                found, result = self._dispatch(m, want_id)
                if found:
                    return True, result
        return False, None

    def _post(self, msg, want_id):
        body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
        status, hdrs, resp = _http("POST", self.url, self._headers(), body,
                                   timeout=self.timeout, stream=True)
        self.http_statuses.append(status)
        sid = hdrs.get("mcp-session-id")
        if sid:
            self.session_id = sid
        if status == 401:
            if hasattr(resp, "close"):
                resp.close()
            raise AuthRequired(hdrs.get("www-authenticate", ""))
        if status >= 400:
            data = resp if isinstance(resp, bytes) else resp.read(2000)
            raise ProbeError(f"HTTP {status} from {self.url}: "
                             f"{data.decode('utf-8', 'replace')[:200]}")
        if status == 202 or want_id is None:
            if hasattr(resp, "close"):
                resp.close()
            return None
        ctype = hdrs.get("content-type", "")
        deadline = time.monotonic() + self.timeout
        if "text/event-stream" in ctype:
            found, result = self._read_sse(resp, want_id, deadline)
        else:
            data = resp if isinstance(resp, bytes) else resp.read(MAX_BODY)
            if hasattr(resp, "close"):
                resp.close()
            parsed = _json_or_none(data)
            if parsed is None:
                raise ProbeError(f"{self.url}: non-JSON body ({ctype or 'no content-type'})")
            found, result = False, None
            for m in (parsed if isinstance(parsed, list) else [parsed]):
                found, result = self._dispatch(m, want_id)
                if found:
                    break
        if not found:
            raise ProbeError(f"{msg.get('method')}: response did not contain an answer for "
                             f"id {want_id}")
        return result

    def request(self, method, params=None, timeout=None):
        self._id += 1
        rid = self._id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        return self._post(msg, rid)

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._post(msg, None)

    def close(self):
        if not self.session_id:
            return
        try:
            _http("DELETE", self.url, self._headers(), timeout=min(self.timeout, 10))
        except ProbeError:
            pass


# ---------------------------------------------------------------- OAuth 2.1

def _parse_www_authenticate(value):
    out = {}
    for part in (value or "").split(","):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k.strip().split()[-1].lower()] = v.strip().strip('"')
    return out


def discover(mcp_url, www_authenticate="", timeout=30):
    """Resolve the authorization server's endpoints for an MCP endpoint."""
    parts = urllib.parse.urlsplit(mcp_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    candidates = []
    hinted = _parse_www_authenticate(www_authenticate).get("resource_metadata")
    if hinted:
        candidates.append(hinted)
    path = parts.path.rstrip("/")
    if path:
        candidates.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    candidates.append(f"{origin}/.well-known/oauth-protected-resource")

    resource_meta = None
    for url in candidates:
        try:
            status, _, data = _http("GET", url, timeout=timeout)
        except ProbeError:
            continue
        if status == 200:
            resource_meta = _json_or_none(data)
            if isinstance(resource_meta, dict):
                break
            resource_meta = None
    auth_servers = (resource_meta or {}).get("authorization_servers") or [origin]
    as_url = str(auth_servers[0]).rstrip("/")
    as_parts = urllib.parse.urlsplit(as_url)
    as_origin = f"{as_parts.scheme}://{as_parts.netloc}"
    as_path = as_parts.path.rstrip("/")

    meta = None
    for url in (f"{as_origin}/.well-known/oauth-authorization-server{as_path}",
                f"{as_origin}{as_path}/.well-known/oauth-authorization-server",
                f"{as_origin}/.well-known/openid-configuration{as_path}",
                f"{as_origin}{as_path}/.well-known/openid-configuration"):
        try:
            status, _, data = _http("GET", url, timeout=timeout)
        except ProbeError:
            continue
        if status == 200:
            meta = _json_or_none(data)
            if isinstance(meta, dict) and meta.get("token_endpoint"):
                break
            meta = None
    if meta is None:
        meta = {"authorization_endpoint": f"{as_url}/authorize",
                "token_endpoint": f"{as_url}/token",
                "registration_endpoint": f"{as_url}/register"}
    scopes = (resource_meta or {}).get("scopes_supported") or meta.get("scopes_supported") or []
    return {
        "resource": (resource_meta or {}).get("resource") or mcp_url,
        "authorization_endpoint": meta.get("authorization_endpoint"),
        "token_endpoint": meta.get("token_endpoint"),
        "registration_endpoint": meta.get("registration_endpoint"),
        "scopes": [s for s in scopes if isinstance(s, str)],
        "pkce": meta.get("code_challenge_methods_supported") or ["S256"],
        "issuer": meta.get("issuer") or as_url,
    }


def register_client(meta, redirect_uri, timeout=30):
    """Dynamic client registration (RFC 7591). Public client, no secret."""
    if not meta.get("registration_endpoint"):
        raise ProbeError("authorization server offers no registration endpoint; pass a bearer "
                         "via --bearer-env instead")
    body = json.dumps({
        "client_name": "Git Gud Security probe",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }).encode("utf-8")
    status, _, data = _http("POST", meta["registration_endpoint"],
                            {"Content-Type": "application/json", "Accept": "application/json"},
                            body, timeout=timeout)
    reg = _json_or_none(data)
    if status not in (200, 201) or not isinstance(reg, dict) or not reg.get("client_id"):
        raise ProbeError(f"client registration failed: HTTP {status} "
                         f"{data.decode('utf-8', 'replace')[:200]}")
    return {"client_id": reg["client_id"], "client_secret": reg.get("client_secret")}


class _Callback(BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        self.server.result = {k: v[0] for k, v in q.items()}
        self.server.done.set()
        page = (b"<html><body style='font-family:sans-serif'><p>git-gud-security probe: "
                b"authorization received. You can close this tab.</p></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *a):
        pass


def _loopback():
    srv = HTTPServer(("127.0.0.1", 0), _Callback)
    srv.result = None
    srv.done = threading.Event()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/callback"


def _token_request(meta, form, timeout):
    body = urllib.parse.urlencode(form).encode("utf-8")
    status, _, data = _http("POST", meta["token_endpoint"],
                            {"Content-Type": "application/x-www-form-urlencoded",
                             "Accept": "application/json"}, body, timeout=timeout)
    tok = _json_or_none(data)
    if status != 200 or not isinstance(tok, dict) or not tok.get("access_token"):
        raise ProbeError(f"token endpoint: HTTP {status} {data.decode('utf-8', 'replace')[:200]}")
    return tok


def authorize(mcp_url, meta, open_url=None, wait=OAUTH_WAIT, timeout=30, log=None):
    """Authorization-code + PKCE with a loopback redirect. `open_url(url)` opens the consent
    page (default: the system browser). Returns the token record to cache."""
    log = log or (lambda s: print(s, file=sys.stderr))
    srv, redirect_uri = _loopback()
    try:
        client = register_client(meta, redirect_uri, timeout)
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(24)
        params = {
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "resource": meta.get("resource") or mcp_url,
        }
        if meta.get("scopes"):
            params["scope"] = " ".join(meta["scopes"])
        url = meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
        log(f"git-gud-security: OAuth consent needed for {mcp_url}. Opening the browser; "
            f"approve there (waiting up to {wait}s).")
        (open_url or webbrowser.open)(url)
        if not srv.done.wait(wait):
            raise ProbeError(f"no OAuth callback within {wait}s")
        res = srv.result or {}
        if res.get("error"):
            raise ProbeError(f"authorization denied: {res.get('error')} "
                             f"{res.get('error_description', '')}".strip())
        if res.get("state") != state or not res.get("code"):
            raise ProbeError("OAuth callback missing code or state mismatch")
        form = {
            "grant_type": "authorization_code",
            "code": res["code"],
            "redirect_uri": redirect_uri,
            "client_id": client["client_id"],
            "code_verifier": verifier,
            "resource": meta.get("resource") or mcp_url,
        }
        if client.get("client_secret"):
            form["client_secret"] = client["client_secret"]
        tok = _token_request(meta, form, timeout)
    finally:
        srv.shutdown()
        srv.server_close()
    return _record(tok, client, meta)


def _record(tok, client, meta):
    expires_in = tok.get("expires_in")
    return {
        "access_token": tok["access_token"],
        "refresh_token": tok.get("refresh_token"),
        "expires_at": (time.time() + float(expires_in) - 30) if isinstance(expires_in, (int, float)) else None,
        "client_id": client.get("client_id"),
        "client_secret": client.get("client_secret"),
        "token_endpoint": meta.get("token_endpoint"),
        "resource": meta.get("resource"),
        "issued": time.time(),
    }


def refresh(rec, mcp_url, timeout=30):
    if not rec.get("refresh_token") or not rec.get("token_endpoint"):
        raise ProbeError("no refresh token")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": rec["refresh_token"],
        "client_id": rec.get("client_id") or "",
        "resource": rec.get("resource") or mcp_url,
    }
    if rec.get("client_secret"):
        form["client_secret"] = rec["client_secret"]
    tok = _token_request({"token_endpoint": rec["token_endpoint"]}, form, timeout)
    new = _record(tok, rec, rec)
    if not new.get("refresh_token"):
        new["refresh_token"] = rec.get("refresh_token")
    return new


# ---------------------------------------------------------------- token file

def load_tokens(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_tokens(path, tokens):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def obtain_token(mcp_url, www_authenticate, token_file, open_url=None, timeout=30, log=None):
    """Cached -> refreshed -> full flow. Returns (access_token, how)."""
    log = log or (lambda s: print(s, file=sys.stderr))
    tokens = load_tokens(token_file)
    rec = tokens.get(mcp_url)
    if isinstance(rec, dict) and rec.get("access_token"):
        exp = rec.get("expires_at")
        if not exp or exp > time.time():
            return rec["access_token"], "oauth-cached"
        try:
            new = refresh(rec, mcp_url, timeout)
            tokens[mcp_url] = new
            save_tokens(token_file, tokens)
            return new["access_token"], "oauth-refreshed"
        except ProbeError as e:
            log(f"git-gud-security: token refresh failed ({e}); re-authorizing.")
    meta = discover(mcp_url, www_authenticate, timeout)
    if not meta.get("authorization_endpoint"):
        raise ProbeError("no authorization endpoint discovered; pass a bearer via --bearer-env")
    rec = authorize(mcp_url, meta, open_url=open_url, timeout=timeout, log=log)
    tokens[mcp_url] = rec
    save_tokens(token_file, tokens)
    return rec["access_token"], "oauth"


def forget_token(mcp_url, token_file):
    tokens = load_tokens(token_file)
    if mcp_url in tokens:
        del tokens[mcp_url]
        save_tokens(token_file, tokens)
