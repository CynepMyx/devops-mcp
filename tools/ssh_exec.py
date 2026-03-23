import asyncio
import logging
import os
import socket
import time

import paramiko

from security import validate_ssh_key_path, validate_ssh_command

KNOWN_HOSTS_PATH = os.environ.get("SSH_KNOWN_HOSTS", "/app/ssh/known_hosts")

logger = logging.getLogger(__name__)


class _CapturingWarningPolicy(paramiko.MissingHostKeyPolicy):
    """Like WarningPolicy but captures the warning for the response instead of logging it."""

    def __init__(self):
        self.warnings = []

    def missing_host_key(self, client, hostname, key):
        self.warnings.append(
            f"Unknown host key for {hostname} ({key.get_name()}). "
            "Add it to /app/ssh/known_hosts for strict verification."
        )


def _run_ssh(
    host: str,
    user: str,
    key_path: str,
    command: str,
    timeout: int,
    password: str = None,
    verify_host_key: bool = False,
) -> dict:
    start = time.monotonic()
    client = paramiko.SSHClient()

    known_hosts_loaded = False
    if os.path.isfile(KNOWN_HOSTS_PATH):
        client.load_host_keys(KNOWN_HOSTS_PATH)
        known_hosts_loaded = True

    if verify_host_key:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        host_key_mode = "strict"
        warning_policy = None
    else:
        warning_policy = _CapturingWarningPolicy()
        client.set_missing_host_key_policy(warning_policy)
        host_key_mode = "warn"

    try:
        sock = socket.create_connection((host, 22), timeout=timeout)
        sock.settimeout(timeout)
        connect_kwargs = dict(
            hostname=host,
            sock=sock,
            username=user,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        if password:
            connect_kwargs["password"] = password
        else:
            connect_kwargs["key_filename"] = key_path
        try:
            client.connect(**connect_kwargs)
        except paramiko.AuthenticationException:
            raise paramiko.AuthenticationException("Authentication failed")
        finally:
            # Clear password from local scope so it never appears in tracebacks
            connect_kwargs.pop("password", None)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        exit_code = stdout.channel.recv_exit_status()
    finally:
        client.close()

    duration_ms = round((time.monotonic() - start) * 1000)
    result = {
        "host": host,
        "command": command,
        "stdout": out,
        "stderr": err,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "host_key": {
            "mode": host_key_mode,
            "known_hosts_loaded": known_hosts_loaded,
        },
    }
    if warning_policy and warning_policy.warnings:
        result["host_key"]["warnings"] = warning_policy.warnings
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

    if not host:
        return {"error": "Parameter 'host' is required"}
    if not user:
        return {"error": "Parameter 'user' is required"}
    if not key_path and not password:
        return {"error": "Parameter 'key' or 'password' is required"}
    if not command:
        return {"error": "Parameter 'command' is required"}

    try:
        if key_path:
            validate_ssh_key_path(key_path)
        validate_ssh_command(command, confirmed)
    except (ValueError, PermissionError) as e:
        return {"error": str(e)}

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _run_ssh, host, user, key_path, command, timeout, password or None, verify_host_key
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
