#!/usr/bin/env python3
"""Test fixture: a well-behaved stdio MCP server. One read-only tool, data-only results, no
instructions, stable tool list. The probe must report nothing on it."""
import json
import sys

TOOLS = [
    {"name": "acme-get-page",
     "description": "Get a page by id.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}},
                     "required": ["id"]},
     "annotations": {"readOnlyHint": True}},
]


def reply(i, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    meth = m.get("method")
    i = m.get("id")
    if meth == "initialize":
        reply(i, {"protocolVersion": m["params"]["protocolVersion"],
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "acme-clean-fixture", "version": "0.0.1"}})
    elif meth == "tools/list":
        reply(i, {"tools": TOOLS})
    elif meth == "tools/call":
        reply(i, {"content": [{"type": "text", "text": json.dumps({"title": "hello"})}]})
    elif i is not None:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i,
                                     "error": {"code": -32601, "message": "unknown method"}}) + "\n")
        sys.stdout.flush()
