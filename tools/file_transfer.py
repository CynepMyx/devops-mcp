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
import stat as stat_mod
import time
from datetime import datetime, timezone

import paramiko

from security import (
    MAX_FILE_BYTES,
    validate_remote_file_path,
    validate_ssh_key_path,
    validate_verify_command,
)
from tools import ssh_pool

ALLOW_SSH_PASSWORD = os.environ.get("ALLOW_SSH_PASSWORD", "false").lower() == "true"

MAX_DIFF_LINES = 200

logger = logging.getLogger(__name__)


class ConnectionLostMidWrite(Exception):
    """The transport died after we had already started changing the file."""


def _pooled(host, user, key_path, password, timeout, verify_host_key, work,
            retry=True):
    """Run `work(client, sftp)` on a pooled connection, opening SFTP for it.

    Only connection-level failures are retried. An SFTP error about a missing
    file or denied permission is an answer, not a broken link, and must reach
    the caller unchanged.

    retry=False is for work that is not safe to replay. file_put stats the file,
    reads the old content, backs it up and renames the new one into place; if the
    transport dies after the rename, a second pass would read the *new* content
    as the old one, report "nothing to write", and treat the replacement as the
    thing to restore.
    """
    for attempt in (1, 2) if retry else (1,):
        entry, reused = ssh_pool.acquire(
            host, user, key_path, password or "", timeout=timeout,
            verify_host_key=verify_host_key,
        )
        try:
            with entry.lock:
                sftp = entry.client.open_sftp()
                try:
                    result = work(entry.client, sftp)
                finally:
                    sftp.close()
                ssh_pool.touch(entry)
        except (paramiko.SSHException, EOFError, ConnectionError):
            ssh_pool.drop(entry)
            if not retry or attempt == 2 or not reused:
                raise
            continue

        meta = {"host_key": entry.host_key, "connection": "reused" if reused else "new"}
        return result, meta


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
    def work(client, sftp):
        st = sftp.stat(path)
        if stat_mod.S_ISDIR(st.st_mode):
            return {"error": f"Not a regular file: {path}", "outcome": "refused"}
        data, truncated = _read_remote(sftp, path, max_bytes)
        return st, data, truncated

    outcome, meta = _pooled(host, user, key_path, password, timeout,
                            verify_host_key, work)
    if isinstance(outcome, dict):
        return {**outcome, **meta}
    st, data, truncated = outcome

    result = {"host": host, "path": path, **_describe(st),
              "sha256": hashlib.sha256(data).hexdigest(),
              "truncated": truncated, **meta}
    text, why_not = _decode(data)
    if text is None:
        result["content"] = None
        result["note"] = f"Content not returned: {why_not}"
    else:
        result["content"] = text
    return result


def _backup_name(sftp, path: str) -> str:
    """Pick a free backup name. The stamp is per second, and two writes can land
    inside the same second, which would silently overwrite the older copy."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    candidate = f"{path}.bak_{stamp}"
    for suffix in range(2, 50):
        try:
            sftp.stat(candidate)
        except IOError:
            return candidate
        candidate = f"{path}.bak_{stamp}-{suffix}"
    raise IOError(f"Could not find a free backup name for {path}")


def _exec(client, command: str, timeout: int) -> dict:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    return {
        "command": command,
        "exit_code": stdout.channel.recv_exit_status(),
        "stdout": out[-4000:],
        "stderr": err[-4000:],
    }


def _write_atomic(sftp, path: str, payload: bytes, target_mode: int,
                  owner: tuple | None, exists: bool, warnings: list) -> None:
    """Write through a temporary file in the same directory, then rename over."""
    tmp_path = posixpath.join(
        posixpath.dirname(path) or "/",
        f".{posixpath.basename(path)}.mcp_tmp_{os.getpid()}",
    )
    with sftp.open(tmp_path, "wb") as fh:
        fh.write(payload)
    sftp.chmod(tmp_path, target_mode)
    if owner:
        try:
            sftp.chown(tmp_path, owner[0], owner[1])
        except (IOError, OSError) as exc:
            warnings.append(
                f"Could not restore owner {owner[0]}:{owner[1]} ({exc}). "
                "File is owned by the connecting user."
            )
    try:
        sftp.posix_rename(tmp_path, path)
    except (IOError, OSError, AttributeError):
        if exists:
            sftp.remove(path)
        sftp.rename(tmp_path, path)
        warnings.append("Server lacks posix-rename; used remove+rename")


def _put_sync(host, user, key_path, password, timeout, verify_host_key,
              path, payload: bytes, mode, backup, dry_run,
              verify_cmd=None, rollback=True) -> dict:
    warnings: list[str] = []
    # Written from inside work(), read after a connection failure so the error
    # can tell the user where the previous content is.
    progress: dict = {"stage": "not started", "backup": None}

    def work(client, sftp):
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
            if verify_cmd:
                summary["verify_planned"] = verify_cmd
            return summary

        backup_path = None
        if exists and backup:
            backup_path = _backup_name(sftp, path)
            with sftp.open(backup_path, "wb") as fh:
                fh.write(old_bytes)
            sftp.chmod(backup_path, stat_mod.S_IMODE(st.st_mode))
            progress["backup"] = backup_path

        owner = (st.st_uid, st.st_gid) if exists else None
        progress["stage"] = "writing"
        _write_atomic(sftp, path, payload, target_mode, owner, exists, warnings)
        progress["stage"] = "written"
        written = sftp.stat(path)

        # Checking the config we just wrote, and putting the old one back when
        # the check fails, is the whole point: a bad config on a client server
        # is only harmless for as long as nothing reloads it.
        if verify_cmd:
            verify = _exec(client, verify_cmd, timeout)
            summary["verify"] = verify
            if verify["exit_code"] != 0:
                summary["verify_failed"] = True
                if rollback:
                    if exists:
                        _write_atomic(sftp, path, old_bytes, target_mode,
                                      owner, True, warnings)
                        written = sftp.stat(path)
                    else:
                        sftp.remove(path)
                        written = None
                    summary["rolled_back"] = True
                    summary["verify_after_rollback"] = _exec(client, verify_cmd, timeout)
                    if backup_path:
                        # Nothing changed in the end, so the copy is just litter.
                        try:
                            sftp.remove(backup_path)
                            backup_path = None
                        except (IOError, OSError):
                            warnings.append(f"Could not remove backup {backup_path}")
                else:
                    summary["rolled_back"] = False
                    warnings.append(
                        "Verification failed and rollback_on_failure=false: "
                        "the new content is still in place."
                    )

        summary["written"] = not summary.get("rolled_back", False)
        summary["backup"] = backup_path
        summary["result"] = _describe(written) if written else None
        return summary

    try:
        summary, meta = _pooled(host, user, key_path, password, timeout,
                                verify_host_key, work, retry=False)
    except (paramiko.SSHException, EOFError, ConnectionError) as exc:
        if progress["stage"] == "not started":
            raise
        where = ("The new content is already in place; verification did not finish"
                 if progress["stage"] == "written"
                 else "The write was interrupted and the file may be incomplete")
        backup_note = (f" The previous content is in {progress['backup']}."
                       if progress["backup"] else "")
        raise ConnectionLostMidWrite(
            f"Connection lost while writing {path}. {where}.{backup_note} "
            f"Check the file before writing again. ({exc})"
        ) from exc

    summary.update(meta)
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
    verify_cmd = (args.get("verify_cmd") or "").strip()
    rollback = bool(args.get("rollback_on_failure", True))

    try:
        host, user, key_path, password, timeout, verify_host_key = _common_args(args)
        if not path_arg:
            raise ValueError("Parameter 'path' is required")
        if content is None:
            raise ValueError("Parameter 'content' is required")
        if not isinstance(content, str):
            raise ValueError("Parameter 'content' must be a string")
        path = validate_remote_file_path(path_arg)
        if verify_cmd:
            validate_verify_command(verify_cmd)

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
                              verify_host_key, path, payload, mode, backup, dry_run,
                              verify_cmd or None, rollback),
            # The verification and a possible rollback each need their own round
            # trip after the write, so the outer deadline has to allow for them.
            timeout=timeout * 3 + 15,
        )
    except asyncio.TimeoutError:
        return {"error": f"SFTP timed out after {timeout}s"}
    except ConnectionLostMidWrite as e:
        return {"error": str(e)}
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
