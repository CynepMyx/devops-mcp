import asyncio
import socket
import time

import paramiko

from security import validate_ssh_key_path, validate_ssh_command


def _run_ssh(host: str, user: str, key_path: str, command: str, timeout: int, password: str = None) -> dict:
    start = time.monotonic()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        exit_code = stdout.channel.recv_exit_status()
    finally:
        client.close()

    duration_ms = round((time.monotonic() - start) * 1000)
    return {
        "host": host,
        "command": command,
        "stdout": out,
        "stderr": err,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
    }


async def ssh_exec(args: dict) -> dict:
    host = args.get("host", "").strip()
    user = args.get("user", "").strip()
    key_path = args.get("key", "").strip()
    password = args.get("password", "").strip()
    command = args.get("command", "").strip()
    timeout = min(int(args.get("timeout", 30)), 120)
    confirmed = bool(args.get("confirmed", False))

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
            asyncio.to_thread(_run_ssh, host, user, key_path, command, timeout, password or None),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        return {"error": f"SSH timed out after {timeout}s"}
