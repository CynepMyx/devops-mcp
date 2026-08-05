"""Keep SSH connections open between tool calls.

Every ssh_exec used to be a full TCP connect plus key exchange plus auth, then
a close. A twenty command diagnostic paid that twenty times, and to a filter
like fail2ban twenty connections in a row from one address look exactly like an
attack, which is how we once got banned for fifteen minutes mid-incident.

This module hands out live paramiko clients keyed by host and credential, and
keeps them warm until they go idle. Commands still run as separate channels on
the same transport, so nothing is carried between them: no shell state, no cwd,
no leftover environment. That is deliberate. A persistent *shell* would let two
separately-validated calls add up to one command neither of them was.

The module is never hot-reloaded (it is absent from _TOOL_MODULES in server.py)
because a reload would drop the dict while the sockets stay open.
"""
import hashlib
import logging
import os
import socket
import threading
import time

import paramiko

KNOWN_HOSTS_PATH = os.environ.get("SSH_KNOWN_HOSTS", "/app/ssh/known_hosts")
IDLE_TTL = int(os.environ.get("SSH_POOL_IDLE_TTL", "300"))
MAX_CONNECTIONS = int(os.environ.get("SSH_POOL_MAX", "20"))
KEEPALIVE = int(os.environ.get("SSH_POOL_KEEPALIVE", "30"))
POOL_ENABLED = os.environ.get("SSH_POOL", "true").lower() != "false"

logger = logging.getLogger(__name__)


class CapturingWarningPolicy(paramiko.MissingHostKeyPolicy):
    """Like WarningPolicy, but the warning reaches the caller instead of a log file."""

    def __init__(self):
        self.warnings = []

    def missing_host_key(self, client, hostname, key):
        self.warnings.append(
            f"Unknown host key for {hostname} ({key.get_name()}). "
            "Add it to /app/ssh/known_hosts for strict verification."
        )


class _Entry:
    __slots__ = ("client", "host_key", "last_used", "created", "uses", "lock")

    def __init__(self, client, host_key):
        self.client = client
        self.host_key = host_key
        self.last_used = time.monotonic()
        self.created = time.monotonic()
        self.uses = 0
        self.lock = threading.Lock()

    def alive(self) -> bool:
        transport = self.client.get_transport()
        return bool(transport and transport.is_active())

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


_POOL: dict[tuple, _Entry] = {}
_POOL_LOCK = threading.Lock()
_REAPER_STARTED = False


def _auth_id(key_path: str, password: str) -> str:
    """Identify the credential without keeping the secret around."""
    if key_path:
        return f"key:{key_path}"
    return "pw:" + hashlib.sha256(password.encode("utf-8")).hexdigest()[:12]


def _connect(host, port, user, key_path, password, timeout, verify_host_key):
    client = paramiko.SSHClient()
    known_hosts_loaded = False
    if os.path.isfile(KNOWN_HOSTS_PATH):
        client.load_host_keys(KNOWN_HOSTS_PATH)
        known_hosts_loaded = True

    if verify_host_key:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        policy = None
        host_key = {"mode": "strict", "known_hosts_loaded": known_hosts_loaded}
    else:
        policy = CapturingWarningPolicy()
        client.set_missing_host_key_policy(policy)
        host_key = {"mode": "warn", "known_hosts_loaded": known_hosts_loaded}

    sock = socket.create_connection((host, port), timeout=timeout)
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

    transport = client.get_transport()
    if transport:
        # Without this a NAT or firewall drops an idle connection silently and
        # we only find out in the middle of the next command.
        transport.set_keepalive(KEEPALIVE)
    if policy and policy.warnings:
        host_key["warnings"] = policy.warnings
    return client, host_key


def _reap(now: float | None = None) -> int:
    """Close connections that have been idle too long. Returns how many."""
    now = now if now is not None else time.monotonic()
    closed = 0
    with _POOL_LOCK:
        for key, entry in list(_POOL.items()):
            if now - entry.last_used <= IDLE_TTL and entry.alive():
                continue
            # last_used is only refreshed once a command finishes, so a long
            # running one looks idle. Its lock is held for the whole execution:
            # if we cannot take it, the connection is busy, not abandoned.
            if not entry.lock.acquire(blocking=False):
                continue
            try:
                _POOL.pop(key, None)
                entry.close()
                closed += 1
            finally:
                entry.lock.release()
    return closed


def _start_reaper() -> None:
    global _REAPER_STARTED
    if _REAPER_STARTED:
        return
    _REAPER_STARTED = True

    def loop():
        while True:
            time.sleep(60)
            try:
                _reap()
            except Exception as exc:
                logger.warning("ssh pool reaper: %s", exc)

    threading.Thread(target=loop, daemon=True, name="ssh-pool-reaper").start()


def _evict_oldest_locked() -> None:
    if len(_POOL) < MAX_CONNECTIONS:
        return
    oldest_key = min(_POOL, key=lambda k: _POOL[k].last_used)
    entry = _POOL.pop(oldest_key)
    entry.close()


def acquire(host, user, key_path="", password="", port=22, timeout=30,
            verify_host_key=False):
    """Return (entry, reused). The caller runs inside `with entry.lock`."""
    key = (host, port, user, _auth_id(key_path, password), bool(verify_host_key))

    if not POOL_ENABLED:
        client, host_key = _connect(host, port, user, key_path, password,
                                    timeout, verify_host_key)
        return _Entry(client, host_key), False

    _start_reaper()

    with _POOL_LOCK:
        entry = _POOL.get(key)
        if entry is not None:
            if entry.alive():
                entry.last_used = time.monotonic()
                entry.uses += 1
                return entry, True
            # The server was restarted, or something in between dropped us.
            _POOL.pop(key, None)
            entry.close()
        _evict_oldest_locked()

    client, host_key = _connect(host, port, user, key_path, password,
                                timeout, verify_host_key)
    entry = _Entry(client, host_key)
    entry.uses = 1
    with _POOL_LOCK:
        existing = _POOL.get(key)
        if existing is not None and existing.alive():
            # Another thread won the race; keep theirs and drop ours.
            entry.close()
            existing.last_used = time.monotonic()
            existing.uses += 1
            return existing, True
        _POOL[key] = entry
    return entry, False


def drop(entry) -> None:
    """Remove a connection that turned out to be dead mid-command."""
    with _POOL_LOCK:
        for key, candidate in list(_POOL.items()):
            if candidate is entry:
                _POOL.pop(key, None)
                break
    entry.close()


def touch(entry) -> None:
    entry.last_used = time.monotonic()


def close_all(host: str = "", user: str = "") -> int:
    """Close pooled connections, optionally only those matching host and user."""
    closed = 0
    with _POOL_LOCK:
        for key, entry in list(_POOL.items()):
            if host and key[0] != host:
                continue
            if user and key[2] != user:
                continue
            _POOL.pop(key, None)
            entry.close()
            closed += 1
    return closed


def status() -> dict:
    now = time.monotonic()
    with _POOL_LOCK:
        entries = [
            {
                "host": key[0],
                "port": key[1],
                "user": key[2],
                "credential": key[3],
                "alive": entry.alive(),
                "uses": entry.uses,
                "idle_seconds": round(now - entry.last_used, 1),
                "age_seconds": round(now - entry.created, 1),
            }
            for key, entry in _POOL.items()
        ]
    return {
        "enabled": POOL_ENABLED,
        "idle_ttl_seconds": IDLE_TTL,
        "max_connections": MAX_CONNECTIONS,
        "open": len(entries),
        "connections": entries,
    }
