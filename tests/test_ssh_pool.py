"""Tests for the connection pool.

No sockets here: the pool's job is bookkeeping, and the parts that go wrong are
bookkeeping mistakes. Handing out one host's connection to another credential,
handing back a dead one, or never letting go of an idle session on a client
server are all decided in this dict.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tools import ssh_pool


class FakeTransport:
    def __init__(self, active=True):
        self.active = active
        self.keepalive = None

    def is_active(self):
        return self.active

    def set_keepalive(self, interval):
        self.keepalive = interval


class FakeClient:
    def __init__(self, active=True):
        self.transport = FakeTransport(active)
        self.closed = False

    def get_transport(self):
        return self.transport

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def clean_pool(monkeypatch):
    ssh_pool.close_all()
    created = []

    def fake_connect(host, port, user, key_path, password, timeout, verify_host_key,
                     sock=None):
        client = FakeClient()
        created.append(client)
        return client, {"mode": "warn", "known_hosts_loaded": False}

    monkeypatch.setattr(ssh_pool, "_connect", fake_connect)
    monkeypatch.setattr(ssh_pool, "_start_reaper", lambda: None)
    yield created
    ssh_pool.close_all()


def test_second_call_reuses_the_same_connection(clean_pool):
    first, reused_first = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    second, reused_second = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")

    assert reused_first is False
    assert reused_second is True
    assert first is second
    assert len(clean_pool) == 1, "the second call must not authenticate again"


def test_different_credentials_never_share_a_connection(clean_pool):
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/b.pem")
    ssh_pool.acquire("10.0.0.1", "deploy", "/app/keys/a.pem")
    ssh_pool.acquire("10.0.0.2", "root", "/app/keys/a.pem")

    assert ssh_pool.status()["open"] == 4


def test_password_is_not_stored_in_the_pool_key(clean_pool):
    ssh_pool.acquire("10.0.0.1", "root", password="hunter2")
    credential = ssh_pool.status()["connections"][0]["credential"]
    assert "hunter2" not in credential
    assert credential.startswith("pw:")


def test_a_dead_connection_is_replaced(clean_pool):
    entry, _ = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    entry.client.transport.active = False  # server rebooted between calls

    fresh, reused = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")

    assert reused is False
    assert fresh is not entry
    assert entry.client.closed is True
    assert ssh_pool.status()["open"] == 1


def test_idle_connections_are_reaped(clean_pool, monkeypatch):
    entry, _ = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    monkeypatch.setattr(ssh_pool, "IDLE_TTL", 60)
    entry.last_used = time.monotonic() - 61

    assert ssh_pool._reap() == 1
    assert entry.client.closed is True
    assert ssh_pool.status()["open"] == 0


def test_pool_stops_growing_past_the_cap(clean_pool, monkeypatch):
    monkeypatch.setattr(ssh_pool, "MAX_CONNECTIONS", 3)
    for i in range(5):
        ssh_pool.acquire(f"10.0.0.{i}", "root", "/app/keys/a.pem")
    assert ssh_pool.status()["open"] <= 3


def test_close_all_can_target_one_host(clean_pool):
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    ssh_pool.acquire("10.0.0.2", "root", "/app/keys/a.pem")

    assert ssh_pool.close_all(host="10.0.0.1") == 1
    remaining = ssh_pool.status()["connections"]
    assert [c["host"] for c in remaining] == ["10.0.0.2"]


def test_drop_removes_a_specific_entry(clean_pool):
    entry, _ = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    ssh_pool.drop(entry)
    assert ssh_pool.status()["open"] == 0
    assert entry.client.closed is True


def test_disabled_pool_hands_out_fresh_connections(clean_pool, monkeypatch):
    monkeypatch.setattr(ssh_pool, "POOL_ENABLED", False)
    first, reused_first = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    second, reused_second = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")

    assert (reused_first, reused_second) == (False, False)
    assert first is not second
    assert ssh_pool.status()["open"] == 0


def test_reaper_leaves_a_busy_connection_alone(clean_pool, monkeypatch):
    """last_used only moves when a command finishes, so a long one looks idle."""
    entry, _ = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    monkeypatch.setattr(ssh_pool, "IDLE_TTL", 60)
    entry.last_used = time.monotonic() - 61

    entry.lock.acquire()  # stands in for a command still running
    try:
        assert ssh_pool._reap() == 0
        assert entry.client.closed is False
    finally:
        entry.lock.release()

    assert ssh_pool._reap() == 1


# --- going through a jump host --------------------------------------------

JUMP = {"host": "203.0.113.9", "user": "oleg", "key": "/app/keys/vps.pem"}


@pytest.fixture
def fake_channels(monkeypatch):
    """Let a pooled connection open channels, the way a jump host does."""
    opened = []

    def open_channel(self, kind, dest, src, timeout=None):
        opened.append(dest)
        return f"channel-to-{dest[0]}:{dest[1]}"

    monkeypatch.setattr(FakeTransport, "open_channel", open_channel, raising=False)
    return opened


def test_a_jump_host_is_pooled_and_shared(clean_pool, fake_channels):
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem", jump=JUMP)
    ssh_pool.acquire("10.0.0.2", "root", "/app/keys/a.pem", jump=JUMP)

    hosts = sorted(c["host"] for c in ssh_pool.status()["connections"])
    assert hosts == ["10.0.0.1", "10.0.0.2", "203.0.113.9"]
    assert len(fake_channels) == 2, "both targets tunnel through one jump connection"

    jump_entry = [c for c in ssh_pool.status()["connections"]
                  if c["host"] == JUMP["host"]][0]
    assert jump_entry["uses"] == 2
    assert jump_entry["via"] is None


def test_the_same_target_through_a_jump_is_reused(clean_pool, fake_channels):
    first, reused_first = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem", jump=JUMP)
    second, reused_second = ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem", jump=JUMP)

    assert (reused_first, reused_second) == (False, True)
    assert first is second
    assert len(fake_channels) == 1


def test_direct_and_jumped_connections_are_different_entries(clean_pool, fake_channels):
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem", jump=JUMP)

    vias = sorted(str(c["via"]) for c in ssh_pool.status()["connections"]
                  if c["host"] == "10.0.0.1")
    assert vias == ["203.0.113.9", "None"]


def test_reaper_keeps_a_jump_host_that_carries_someone(clean_pool, fake_channels, monkeypatch):
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem", jump=JUMP)
    monkeypatch.setattr(ssh_pool, "IDLE_TTL", 60)
    for key, entry in list(ssh_pool._POOL.items()):
        if key[0] == JUMP["host"]:
            entry.last_used = time.monotonic() - 61  # looks idle, is not

    ssh_pool._reap()
    assert any(c["host"] == JUMP["host"] for c in ssh_pool.status()["connections"])


def test_closing_a_jump_host_takes_its_dependants(clean_pool, fake_channels):
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem", jump=JUMP)
    ssh_pool.acquire("10.0.0.2", "root", "/app/keys/a.pem", jump=JUMP)

    closed = ssh_pool.close_all(host=JUMP["host"])

    assert closed == 3, "the tunnelled connections die with the jump host"
    assert ssh_pool.status()["open"] == 0


def test_status_reports_usage(clean_pool):
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    ssh_pool.acquire("10.0.0.1", "root", "/app/keys/a.pem")
    entry = ssh_pool.status()["connections"][0]
    assert entry["uses"] == 2
    assert entry["alive"] is True
    assert entry["idle_seconds"] < 5
