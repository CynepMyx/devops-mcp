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

    # The first checks are about creating a file, so a leftover from an earlier
    # run would make them pass for the wrong reason.
    probe = run(file_get({**HOST, "path": TARGET}))
    if probe.get("content") is not None or probe.get("size") is not None:
        print(f"{TARGET} already exists. Point SMOKE_PATH at a fresh name.")
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

    # The point of the whole tool: a config that fails its own test must not survive.
    json_path = TARGET + ".json"
    good = '{"listen": 443, "name": "smoke"}'
    broken = '{"listen": 443, "name": "smoke",}'
    check = "python3 -m json.tool " + json_path

    r = show("9. create a valid json", run(file_put({**HOST, "path": json_path, "content": good,
                                                     "mode": "0640", "confirmed": True})))
    if not r.get("written"):
        fails.append("could not create the json fixture")

    r = show("10. write broken json with a check", run(file_put({
        **HOST, "path": json_path, "content": broken, "confirmed": True,
        "verify_cmd": check})))
    if not r.get("verify_failed"):
        fails.append("the check should have failed on broken json")
    if not r.get("rolled_back"):
        fails.append("a failed check must roll the file back")
    if r.get("written"):
        fails.append("written must be false after a rollback")
    if r.get("backup"):
        fails.append("the backup should be removed when nothing changed in the end")
    if r.get("verify_after_rollback", {}).get("exit_code") != 0:
        fails.append("the restored file should pass the same check")

    r = show("11. the old content is back", run(file_get({**HOST, "path": json_path})))
    if r.get("content") != good:
        fails.append("rollback did not restore the previous content")
    if r.get("mode") != "0o640":
        fails.append("rollback did not restore the mode")

    r = show("12. a valid change passes the check", run(file_put({
        **HOST, "path": json_path, "content": '{"listen": 8443, "name": "smoke"}',
        "confirmed": True, "verify_cmd": check})))
    if not r.get("written") or r.get("rolled_back"):
        fails.append("a valid config should be kept")
    if r.get("verify", {}).get("exit_code") != 0:
        fails.append("the check should pass on valid json")

    backup_12 = r.get("backup")

    r = show("13. broken json without rollback", run(file_put({
        **HOST, "path": json_path, "content": broken, "confirmed": True,
        "verify_cmd": check, "rollback_on_failure": False})))
    if not r.get("verify_failed") or r.get("rolled_back") is not False:
        fails.append("rollback_on_failure=false should keep the broken content")
    if backup_12 and r.get("backup") == backup_12:
        fails.append("two writes in the same second reused one backup name")

    r = show("14. credential file", run(file_get({**HOST, "path": "/etc/shadow"})))
    if r.get("outcome") != "refused":
        fails.append("/etc/shadow should be refused")

    r = show("15. write without confirmation", run(file_put({**HOST, "path": TARGET, "content": "x"})))
    if r.get("outcome") != "refused":
        fails.append("write without confirmed should be refused")

    print("FAILURES:" if fails else "ALL CHECKS PASSED")
    for f in fails:
        print(" -", f)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
