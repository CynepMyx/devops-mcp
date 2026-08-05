"""Live smoke test for file_get / file_put against a real host.

Unlike tests/, this one actually connects: it writes a file, reads it back and
checks the backup, the mode and the diff. Not part of CI, since it needs a
reachable host and a key.

    docker run --rm -v /opt/devops-mcp:/app:ro -v /opt/devops-mcp/keys:/app/keys:ro \
        -e SMOKE_HOST=10.0.0.5 -e SMOKE_USER=deploy -e SMOKE_KEY=/app/keys/my.pem \
        -e SMOKE_PATH=/home/deploy/smoke/test.conf \
        -w /app --entrypoint python devops-mcp-mcp-server:latest scripts/smoke_file_transfer.py

The target directory has to exist; the file itself is created and rewritten.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.file_transfer import file_get, file_put

HOST = {
    "host": os.environ.get("SMOKE_HOST", ""),
    "user": os.environ.get("SMOKE_USER", ""),
    "key": os.environ.get("SMOKE_KEY", ""),
    "timeout": 20,
}
TARGET = os.environ.get("SMOKE_PATH", "")

# Everything that used to need escaping through the shell.
BODY_1 = """server {
    listen 443 ssl;
    server_name example.test;
    location / {
        limit_req zone=ingest_zone burst=10 nodelay;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
# literal backtick ` and substitution $(date) and html <b>alert</b>
"""

BODY_2 = BODY_1.replace("burst=10", "burst=20") + "# second revision\n"


def show(label, result):
    trimmed = {k: v for k, v in result.items() if k != "content"}
    if "diff" in trimmed and trimmed["diff"]:
        trimmed["diff"] = trimmed["diff"].splitlines()
    print(f"--- {label}\n{json.dumps(trimmed, indent=2, ensure_ascii=False)}\n")
    return result


def run(coro):
    return asyncio.run(coro)


def main():
    if not all([HOST["host"], HOST["user"], HOST["key"], TARGET]):
        print("Set SMOKE_HOST, SMOKE_USER, SMOKE_KEY and SMOKE_PATH first.")
        return 2

    fails = []

    r = show("1. new file without mode", run(file_put({**HOST, "path": TARGET, "content": BODY_1, "confirmed": True})))
    if r.get("outcome") != "refused":
        fails.append("new file without mode should be refused")

    r = show("2. create with mode 0640", run(file_put({**HOST, "path": TARGET, "content": BODY_1,
                                                       "mode": "0640", "confirmed": True})))
    if not r.get("written"):
        fails.append("create failed")

    r = show("3. read back", run(file_get({**HOST, "path": TARGET})))
    if r.get("content") != BODY_1:
        fails.append("content came back different")
    if r.get("mode") != "0o640":
        fails.append(f"mode is {r.get('mode')}, expected 0o640")

    r = show("4. dry run of a change", run(file_put({**HOST, "path": TARGET, "content": BODY_2,
                                                     "dry_run": True})))
    if r.get("written") is not False or not r.get("diff"):
        fails.append("dry run should show a diff and write nothing")

    r = show("5. same content again", run(file_put({**HOST, "path": TARGET, "content": BODY_1,
                                                    "confirmed": True})))
    if r.get("written") is not False:
        fails.append("identical content should not be rewritten")

    r = show("6. real change", run(file_put({**HOST, "path": TARGET, "content": BODY_2,
                                             "confirmed": True})))
    if not r.get("written") or not r.get("backup"):
        fails.append("change should write and leave a backup")
    backup = r.get("backup")
    if r.get("result", {}).get("mode") != "0o640":
        fails.append("mode was not preserved across the write")

    r = show("7. read the change", run(file_get({**HOST, "path": TARGET})))
    if r.get("content") != BODY_2:
        fails.append("change did not land")

    if backup:
        r = show("8. backup holds the old text", run(file_get({**HOST, "path": backup})))
        if r.get("content") != BODY_1:
            fails.append("backup does not hold the previous content")

    r = show("9. credential file", run(file_get({**HOST, "path": "/etc/shadow"})))
    if r.get("outcome") != "refused":
        fails.append("/etc/shadow should be refused")

    r = show("10. write without confirmation", run(file_put({**HOST, "path": TARGET, "content": "x"})))
    if r.get("outcome") != "refused":
        fails.append("write without confirmed should be refused")

    print("FAILURES:" if fails else "ALL CHECKS PASSED")
    for f in fails:
        print(" -", f)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
