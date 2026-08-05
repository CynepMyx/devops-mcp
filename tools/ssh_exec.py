import asyncio
import logging
import os
import time

import paramiko

from security import (
    is_read_only_command,
    parse_jump,
    validate_ssh_command,
    validate_ssh_key_path,
)
from tools import ssh_pool

KNOWN_HOSTS_PATH = os.environ.get("SSH_KNOWN_HOSTS", "/app/ssh/known_hosts")
ALLOW_SSH_PASSWORD = os.environ.get("ALLOW_SSH_PASSWORD", "false").lower() == "true"

logger = logging.getLogger(__name__)


def _run_ssh(
    host: str,
    user: str,
    key_path: str,
    command: str,
    timeout: int,
    password: str = None,
    verify_host_key: bool = False,
    jump: dict = None,
) -> dict:
    start = time.monotonic()

    # A pooled connection can die between calls: the server rebooted, a firewall
    # dropped it, sshd was restarted. That shows up here, not at acquire time,
    # so one retry on a fresh connection is part of normal operation — but only
    # for a read. If the transport died after the server started running
    # 'apt install', we cannot tell whether it finished, and running it again to
    # find out is worse than reporting the truth.
    retryable = is_read_only_command(command)

    for attempt in (1, 2):
        entry, reused = ssh_pool.acquire(
            host, user, key_path, password or "", timeout=timeout,
            verify_host_key=verify_host_key, jump=jump,
        )
        try:
            with entry.lock:
                stdin, stdout, stderr = entry.client.exec_command(command, timeout=timeout)
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                exit_code = stdout.channel.recv_exit_status()
                ssh_pool.touch(entry)
            break
        except (paramiko.SSHException, EOFError, OSError) as exc:
            ssh_pool.drop(entry)
            if not reused or attempt == 2:
                raise
            if not retryable:
                raise paramiko.SSHException(
                    f"Connection dropped while the command was running, so it may have "
                    f"already taken effect on {host}. Not retrying it blindly; check the "
                    f"server before running it again. ({exc})"
                )

    duration_ms = round((time.monotonic() - start) * 1000)
    result = {
        "host": host,
        "command": command,
        "stdout": out,
        "stderr": err,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "connection": "reused" if reused else "new",
        "host_key": entry.host_key,
    }
    return result


async def ssh_exec(args: dict) -> dict:
    host = args.get("host", "").strip()
    user = args.get("user", "").strip()
    key_path = args.get("key", "").strip()
    password = args.get("password", "").strip()
    command = args.get("command", "").strip()
    timeout = min(int(args.get("timeout", 30)), 120)
    confirmed = bool(args.get("confirmed", False))
    verify_host_key = bool(args.get("verify_host_key", False))

    # "refused" marks a rejection by our own rules, so the audit log can tell it
    # apart from a server that was unreachable or an authentication failure.
    if not host:
        return {"error": "Parameter 'host' is required", "outcome": "refused"}
    if not user:
        return {"error": "Parameter 'user' is required", "outcome": "refused"}
    if password and not ALLOW_SSH_PASSWORD:
        return {"error": "Password authentication is disabled. Set ALLOW_SSH_PASSWORD=true to enable.",
                "outcome": "refused"}
    if not key_path and not password:
        return {"error": "Parameter 'key' or 'password' is required", "outcome": "refused"}
    if not command:
        return {"error": "Parameter 'command' is required", "outcome": "refused"}

    try:
        if key_path:
            validate_ssh_key_path(key_path)
        validate_ssh_command(command, confirmed)
        jump = parse_jump(args, ALLOW_SSH_PASSWORD)
    except (ValueError, PermissionError) as e:
        return {"error": str(e), "outcome": "refused"}

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _run_ssh, host, user, key_path, command, timeout, password or None,
                verify_host_key, jump,
            ),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        return {"error": f"SSH timed out after {timeout}s"}
    except paramiko.SSHException as e:
        return {"error": f"SSH error: {e}"}
    except Exception as e:
        logger.error("Unexpected ssh_exec error: %s", type(e).__name__)
        return {"error": f"Unexpected error: {type(e).__name__}"}
