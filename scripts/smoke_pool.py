"""Live check that connections are actually kept open between calls.

    docker run --rm -v /opt/devops-mcp:/app:ro -v /opt/devops-mcp/keys:/app/keys:ro \
        -e SMOKE_HOST=10.0.0.5 -e SMOKE_USER=deploy -e SMOKE_KEY=/app/keys/my.pem \
        -w /app --entrypoint python devops-mcp-mcp-server:latest scripts/smoke_pool.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.file_transfer import file_get
from tools.ssh_exec import ssh_exec
from tools.ssh_sessions import ssh_sessions

HOST = {
    "host": os.environ.get("SMOKE_HOST", ""),
    "user": os.environ.get("SMOKE_USER", ""),
    "key": os.environ.get("SMOKE_KEY", ""),
}
ROUNDS = 8


def run(coro):
    return asyncio.run(coro)


def main():
    if not all(HOST.values()):
        print("Set SMOKE_HOST, SMOKE_USER and SMOKE_KEY first.")
        return 2

    fails = []
    timings = []

    for i in range(ROUNDS):
        r = run(ssh_exec({**HOST, "command": "uptime"}))
        if r.get("error"):
            print("error:", r["error"])
            return 1
        timings.append(r["duration_ms"])
        print(f"{i + 1}. {r['duration_ms']:>5} ms  connection={r['connection']}")
        expected = "new" if i == 0 else "reused"
        if r["connection"] != expected:
            fails.append(f"call {i + 1} reported {r['connection']}, expected {expected}")

    first, rest = timings[0], timings[1:]
    average = sum(rest) / len(rest)
    print(f"\nfirst call {first} ms, later calls {average:.0f} ms on average, "
          f"{first / average:.1f}x faster")
    print(f"handshakes: 1 instead of {ROUNDS}")
    if average >= first:
        fails.append("reused calls should be faster than the first one")

    status = run(ssh_sessions({"action": "status"}))
    print("\nopen connections:", status["open"], "uses:",
          [c["uses"] for c in status["connections"]])
    if status["open"] != 1:
        fails.append(f"expected exactly one pooled connection, got {status['open']}")

    r = run(file_get({**HOST, "path": "/etc/hostname"}))
    print("file_get connection:", r.get("connection"))
    if r.get("connection") != "reused":
        fails.append("file_get should ride the same connection as ssh_exec")

    closed = run(ssh_sessions({"action": "close"}))
    print("closed:", closed["closed"], "remaining:", closed["remaining"])
    if closed["remaining"] != 0:
        fails.append("close should leave nothing open")

    r = run(ssh_exec({**HOST, "command": "uptime"}))
    print("after close:", r["connection"])
    if r["connection"] != "new":
        fails.append("a call after close must open a fresh connection")

    run(ssh_sessions({"action": "close"}))

    print("\nFAILURES:" if fails else "\nALL CHECKS PASSED")
    for f in fails:
        print(" -", f)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
