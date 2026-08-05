"""Read and write remote files over SFTP, without involving a shell.

ssh_exec has to guess where shell syntax ends and payload begins, which is why
writing an nginx config through it means fighting ';', backticks and the 500
character ceiling. SFTP has no such problem: the bytes travel as bytes.

file_put is deliberately conservative about the file it replaces. It keeps the
existing mode and owner, writes to a temporary file in the same directory and
renames it into place, so a reader never sees a half-written config.
"""
import asyncio
import difflib
import errno
import hashlib
import logging
import os
import posixpath
import socket
import stat as stat_mod
import time
from datetime import datetime, timezone

import paramiko

from security import MAX_FILE_BYTES, validate_remote_file_path, validate_ssh_key_path

KNOWN_HOSTS_PATH = os.environ.get("SSH_KNOWN_HOSTS", "/app/ssh/known_hosts")
ALLOW_SSH_PASSWORD = os.environ.get("ALLOW_SSH_PASSWORD", "false").lower() == "true"

MAX_DIFF_LINES = 200

logger = logging.getLogger(__name__)


def _connect(host: str, user: str, key_path: str, password: str, timeout: int,
             verify_host_key: bool) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if os.path.isfile(KNOWN_HOSTS_PATH):
        client.load_host_keys(KNOWN_HOSTS_PATH)
    client.set_missing_host_key_policy(
        paramiko.RejectPolicy() if verify_host_key else paramiko.WarningPolicy()
    )
    sock = socket.create_connection((host, 22), timeout=timeout)
    sock.settimeout(timeout)
    connect_kwargs = dict(
        hostname=host, sock=sock, username=user, timeout=timeout,
        auth_timeout=timeout, banner_timeout=timeout,
        look_for_keys=False, allow_agent=False,
    )
    if password:
        connect_kwargs["password"] = password
    else:
        connect_kwargs["key_filename"] = key_path
    try:
        client.connect(**connect_kwargs)
    finally:
        connect_kwargs.pop("password", None)
    return client


def _common_args(args: dict) -> tuple:
    host = args.get("host", "").strip()
    user = args.get("user", "").strip()
    key_path = args.get("key", "").strip()
    password = args.get("password", "").strip()
    timeout = min(int(args.get("timeout", 30)), 120)
    verify_host_key = bool(args.get("verify_host_key", False))

    if not host:
        raise ValueError("Parameter 'host' is required")
    if not user:
        raise ValueError("Parameter 'user' is required")
    if password and not ALLOW_SSH_PASSWORD:
        raise PermissionError(
            "Password authentication is disabled. Set ALLOW_SSH_PASSWORD=true to enable."
        )
    if not key_path and not password:
        raise ValueError("Parameter 'key' or 'password' is required")
    if key_path:
        validate_ssh_key_path(key_path)
    return host, user, key_path, password, timeout, verify_host_key


def _describe(st) -> dict:
    return {
        "mode": oct(stat_mod.S_IMODE(st.st_mode)),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
    }


def _read_remote(sftp, path: str, max_bytes: int) -> tuple[bytes, bool]:
    with sftp.open(path, "rb") as fh:
        fh.prefetch()
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        return data[:max_bytes], True
    return data, False


def _decode(data: bytes) -> tuple[str | None, str | None]:
    """Return (text, reason_it_is_not_text)."""
    if b"\x00" in data:
        return None, "binary file (contains null bytes)"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "not valid UTF-8"


def _get_sync(host, user, key_path, password, timeout, verify_host_key,
              path, max_bytes) -> dict:
    client = _connect(host, user, key_path, password, timeout, verify_host_key)
    try:
        sftp = client.open_sftp()
        try:
            st = sftp.stat(path)
            if stat_mod.S_ISDIR(st.st_mode):
                return {"error": f"Not a regular file: {path}", "outcome": "refused"}
            data, truncated = _read_remote(sftp, path, max_bytes)
        finally:
            sftp.close()
    finally:
        client.close()

    result = {"host": host, "path": path, **_describe(st),
              "sha256": hashlib.sha256(data).hexdigest(),
              "truncated": truncated}
    text, why_not = _decode(data)
    if text is None:
        result["content"] = None
        result["note"] = f"Content not returned: {why_not}"
    else:
        result["content"] = text
    return result


def _backup_name(path: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{path}.bak_{stamp}"


def _put_sync(host, user, key_path, password, timeout, verify_host_key,
              path, payload: bytes, mode, backup, dry_run) -> dict:
    client = _connect(host, user, key_path, password, timeout, verify_host_key)
    warnings: list[str] = []
    try:
        sftp = client.open_sftp()
        try:
            try:
                st = sftp.stat(path)
                exists = True
            except IOError as exc:
                if not isinstance(exc, FileNotFoundError) and getattr(exc, "errno", None) not in (
                        None, errno.ENOENT):
                    raise
                st = None
                exists = False

            if exists and stat_mod.S_ISDIR(st.st_mode):
                return {"error": f"Path is a directory: {path}", "outcome": "refused"}

            # A new file has no mode to inherit, and 644 is a guess that leaks
            # configs to every user on the box. Make the caller state it.
            target_mode = mode if mode is not None else (
                stat_mod.S_IMODE(st.st_mode) if exists else None)
            if target_mode is None:
                return {
                    "error": (f"{path} does not exist yet; pass mode explicitly, "
                              "e.g. mode='0644'"),
                    "outcome": "refused",
                }

            old_bytes = b""
            if exists:
                old_bytes, truncated = _read_remote(sftp, path, MAX_FILE_BYTES)
                if truncated:
                    return {
                        "error": (f"Existing file is larger than {MAX_FILE_BYTES} bytes; "
                                  "refusing to replace it blindly"),
                        "outcome": "refused",
                    }

            old_text, _ = _decode(old_bytes)
            new_text, _ = _decode(payload)
            diff_lines: list[str] = []
            if old_text is not None and new_text is not None:
                diff_lines = list(difflib.unified_diff(
                    old_text.splitlines(), new_text.splitlines(),
                    fromfile=f"{path} (current)", tofile=f"{path} (new)",
                    lineterm="", n=3,
                ))
            diff_truncated = len(diff_lines) > MAX_DIFF_LINES
            diff = "\n".join(diff_lines[:MAX_DIFF_LINES])

            summary = {
                "host": host,
                "path": path,
                "exists": exists,
                "old_sha256": hashlib.sha256(old_bytes).hexdigest() if exists else None,
                "new_sha256": hashlib.sha256(payload).hexdigest(),
                "new_size": len(payload),
                "diff": diff,
                "diff_truncated": diff_truncated,
            }
            if exists:
                summary["current"] = _describe(st)

            if not diff_lines and exists and old_bytes == payload:
                summary["written"] = False
                summary["note"] = "Content identical, nothing to write"
                return summary

            if dry_run:
                summary["written"] = False
                summary["dry_run"] = True
                return summary

            backup_path = None
            if exists and backup:
                backup_path = _backup_name(path)
                with sftp.open(backup_path, "wb") as fh:
                    fh.write(old_bytes)
                sftp.chmod(backup_path, stat_mod.S_IMODE(st.st_mode))

            tmp_path = posixpath.join(
                posixpath.dirname(path) or "/",
                f".{posixpath.basename(path)}.mcp_tmp_{os.getpid()}",
            )
            with sftp.open(tmp_path, "wb") as fh:
                fh.write(payload)
            sftp.chmod(tmp_path, target_mode)
            if exists:
                try:
                    sftp.chown(tmp_path, st.st_uid, st.st_gid)
                except (IOError, OSError) as exc:
                    warnings.append(
                        f"Could not restore owner {st.st_uid}:{st.st_gid} ({exc}). "
                        "File is owned by the connecting user."
                    )
            try:
                sftp.posix_rename(tmp_path, path)
            except (IOError, OSError, AttributeError):
                if exists:
                    sftp.remove(path)
                sftp.rename(tmp_path, path)
                warnings.append("Server lacks posix-rename; used remove+rename")

            written = sftp.stat(path)
        finally:
            sftp.close()
    finally:
        client.close()

    summary["written"] = True
    summary["backup"] = backup_path
    summary["result"] = _describe(written)
    if warnings:
        summary["warnings"] = warnings
    return summary


async def file_get(args: dict) -> dict:
    path_arg = args.get("path", "").strip()
    max_bytes = min(int(args.get("max_bytes", MAX_FILE_BYTES)), MAX_FILE_BYTES)
    try:
        host, user, key_path, password, timeout, verify_host_key = _common_args(args)
        if not path_arg:
            raise ValueError("Parameter 'path' is required")
        path = validate_remote_file_path(path_arg)
    except (ValueError, PermissionError) as e:
        return {"error": str(e), "outcome": "refused"}

    start = time.monotonic()
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_get_sync, host, user, key_path, password, timeout,
                              verify_host_key, path, max_bytes),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        return {"error": f"SFTP timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": f"File not found: {path}"}
    except PermissionError as e:
        return {"error": f"Permission denied: {e}"}
    except paramiko.SSHException as e:
        return {"error": f"SSH error: {e}"}
    except Exception as e:
        logger.error("Unexpected file_get error: %s", type(e).__name__)
        return {"error": f"Unexpected error: {type(e).__name__}: {e}"}
    result["duration_ms"] = round((time.monotonic() - start) * 1000)
    return result


async def file_put(args: dict) -> dict:
    path_arg = args.get("path", "").strip()
    content = args.get("content")
    backup = bool(args.get("backup", True))
    dry_run = bool(args.get("dry_run", False))
    confirmed = bool(args.get("confirmed", False))
    mode_arg = args.get("mode")

    try:
        host, user, key_path, password, timeout, verify_host_key = _common_args(args)
        if not path_arg:
            raise ValueError("Parameter 'path' is required")
        if content is None:
            raise ValueError("Parameter 'content' is required")
        if not isinstance(content, str):
            raise ValueError("Parameter 'content' must be a string")
        path = validate_remote_file_path(path_arg)

        payload = content.encode("utf-8")
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError(f"Content exceeds {MAX_FILE_BYTES} bytes")

        mode = None
        if mode_arg is not None:
            mode_str = str(mode_arg).strip()
            try:
                mode = int(mode_str, 8)
            except ValueError:
                raise ValueError(f"mode must be octal, e.g. '0640' (got {mode_arg!r})")
            if not 0 <= mode <= 0o7777:
                raise ValueError(f"mode out of range: {mode_arg!r}")

        if not dry_run and not confirmed:
            raise PermissionError(
                "file_put writes to a remote file and requires confirmed=true. "
                "Use dry_run=true to see the diff first."
            )
    except (ValueError, PermissionError) as e:
        return {"error": str(e), "outcome": "refused"}

    start = time.monotonic()
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_put_sync, host, user, key_path, password, timeout,
                              verify_host_key, path, payload, mode, backup, dry_run),
            timeout=timeout + 15,
        )
    except asyncio.TimeoutError:
        return {"error": f"SFTP timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"error": f"Directory does not exist: {e}"}
    except PermissionError as e:
        return {"error": f"Permission denied: {e}"}
    except paramiko.SSHException as e:
        return {"error": f"SSH error: {e}"}
    except Exception as e:
        logger.error("Unexpected file_put error: %s", type(e).__name__)
        return {"error": f"Unexpected error: {type(e).__name__}: {e}"}
    result["duration_ms"] = round((time.monotonic() - start) * 1000)
    return result
