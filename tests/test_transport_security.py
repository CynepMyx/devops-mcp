"""DNS rebinding guard on the HTTP transports.

A page on attacker.example can resolve its own name to 127.0.0.1 and reach the SSH
tunnel from the browser. Such a request arrives with Host: attacker.example, so the
same tools/list call is sent with the loopback Host and with foreign ones.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server

BODY = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()


def _scope(path, host=None, origin=None, query=b""):
    headers = [(b"content-type", b"application/json"),
               (b"accept", b"application/json, text/event-stream")]
    if host is not None:
        headers.append((b"host", host.encode()))
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    return {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
            "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": query,
            "root_path": "", "headers": headers, "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 8765)}


async def _status(scope):
    sent = []
    pending = [{"type": "http.request", "body": BODY, "more_body": False}]

    async def receive():
        if pending:
            return pending.pop(0)
        await asyncio.sleep(3600)

    async def send(message):
        sent.append(message)

    await asyncio.wait_for(server._asgi_handler(scope, receive, send), timeout=10)
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


MCP_CASES = [
    ("127.0.0.1:8765", None, 200),
    ("localhost:18765", None, 200),  # tunnel moved to another local port
    ("attacker.example:8765", None, 421),
    ("127.0.0.1.attacker.example:8765", None, 421),
    ("127.0.0.1:8765", "http://attacker.example:8765", 403),
    ("127.0.0.1:8765", "http://127.0.0.1:8765", 200),
    (None, None, 421),
]


def test_streamable_http_checks_host_and_origin():
    async def run():
        results = []
        async with server.session_manager.run():
            for host, origin, _ in MCP_CASES:
                results.append(await _status(_scope("/mcp", host, origin)))
        return results

    got = asyncio.run(run())
    want = [w for _, _, w in MCP_CASES]
    assert got == want, list(zip(MCP_CASES, got))


def test_sse_post_checks_host():
    query = b"session_id=00000000000000000000000000000000"
    assert asyncio.run(_status(_scope("/messages/", "attacker.example:8765", query=query))) == 421
    assert asyncio.run(_status(_scope("/messages/", "127.0.0.1:8765", query=query))) != 421
