"""Tests for running a command over a pooled connection.

Two failures seen in production on 26.09.2026. A command that reads its input
('grep' without a file, 'cat', 'read') waited for stdin that nobody closed and
hit the timeout. The timeout itself then went down the "connection died" branch:
a healthy pooled connection was thrown away, the user saw "Connection dropped",
and a read-only command was run a second time.
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko
import pytest

from tools import ssh_exec, ssh_pool


class FakeTransport:
    def is_active(self):
        return True

    def set_keepalive(self, interval):
        pass


class FakeChannel:
    def __init__(self):
        self.write_shut = False
        self.closed = False

    def shutdown_write(self):
        self.write_shut = True

    def recv_exit_status(self):
        return 0

    def close(self):
        self.closed = True


class FakeStream:
    def __init__(self, channel, data=b"", error=None):
        self.channel = channel
        self.data = data
        self.error = error

    def read(self, size=-1):
        if self.error is not None:
            raise self.error
        return self.data if size < 0 else self.data[:size]


class FakeClient:
    payload = b"ok\n"

    def __init__(self, script):
        self.transport = FakeTransport()
        self.script = script
        self.channels = []

    def get_transport(self):
        return self.transport

    def close(self):
        pass

    def exec_command(self, command, timeout=None):
        channel = FakeChannel()
        self.channels.append(channel)
        error = self.script.pop(0) if self.script else None
        stdout = FakeStream(channel, self.payload, error)
        return FakeStream(channel), stdout, FakeStream(channel)


@pytest.fixture
def clients(monkeypatch):
    ssh_pool.close_all()
    made = []
    script = []

    def fake_connect(host, port, user, key_path, password, timeout, verify_host_key,
                     sock=None):
        client = FakeClient(script)
        made.append(client)
        return client, {"mode": "warn", "known_hosts_loaded": False}

    monkeypatch.setattr(ssh_pool, "_connect", fake_connect)
    monkeypatch.setattr(ssh_pool, "_start_reaper", lambda: None)
    yield made, script
    ssh_pool.close_all()


def run(command="cat /etc/hostname", timeout=5):
    return ssh_exec._run_ssh("h", "u", "/app/keys/k.pem", command, timeout)


def test_stdin_is_closed_so_a_command_reading_input_gets_eof(clients):
    made, _ = clients
    run("grep -c x")
    assert made[0].channels[0].write_shut


def test_a_timeout_is_reported_as_a_timeout(clients):
    _, script = clients
    script.append(socket.timeout())
    with pytest.raises(paramiko.SSHException) as exc:
        run(timeout=7)
    assert "timed out after 7s" in str(exc.value)
    assert "Connection dropped" not in str(exc.value)


def test_a_timeout_keeps_the_connection_and_does_not_rerun_the_command(clients):
    made, script = clients
    run()                          # opens the pooled connection
    script.append(socket.timeout())
    with pytest.raises(paramiko.SSHException):
        run()                      # read-only, on a reused connection
    assert len(made) == 1          # nothing was thrown away and reopened
    assert len(made[0].channels) == 2  # the command ran once, not twice
    assert made[0].channels[1].closed  # only its own channel was closed
    assert run()["connection"] == "reused"


def test_a_dead_transport_still_gets_one_retry_for_a_read(clients):
    made, script = clients
    run()
    script.append(EOFError())
    result = run()
    assert result["exit_code"] == 0
    assert len(made) == 2          # the dead one was replaced


def test_output_past_the_cap_is_cut_instead_of_filling_memory(clients, monkeypatch):
    """'head -c 300000000 /dev/zero' passed the allowlist and the 256M container was
    OOM-killed reading it (audit 12.10.2026)."""
    made, _ = clients
    monkeypatch.setattr(FakeClient, "payload", b"x" * (ssh_exec.MAX_OUTPUT_BYTES + 10))
    result = run("cat /var/log/nginx/access.log")
    assert result["truncated"] is True
    assert len(result["stdout"]) == ssh_exec.MAX_OUTPUT_BYTES
    assert result["exit_code"] is None
    assert made[0].channels[0].closed


def test_normal_output_is_untouched(clients):
    result = run()
    assert result["stdout"] == "ok\n"
    assert "truncated" not in result
    assert result["exit_code"] == 0


@pytest.mark.parametrize("value", [0, -5])
def test_timeout_is_at_least_one_second(value, monkeypatch):
    seen = {}

    def fake_run(host, user, key, command, timeout, *rest):
        seen["timeout"] = timeout
        return {"ok": True}

    monkeypatch.setattr(ssh_exec, "_run_ssh", fake_run)
    import asyncio
    asyncio.run(ssh_exec.ssh_exec({"host": "h", "user": "u", "key": "/app/keys/k.pem",
                                   "command": "uptime", "timeout": value}))
    assert seen["timeout"] == 1
