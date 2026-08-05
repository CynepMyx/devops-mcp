"""Tests for file_get / file_put — the SFTP path that replaces printf | tee.

Nothing here touches a network: every case is decided before the connection is
opened, which is exactly where the guarantees have to live.
"""
import asyncio
import os
import sys

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


def test_key_outside_the_keys_directory_is_refused():
    result = run(file_get({"host": "192.0.2.1", "user": "root",
                           "key": "/home/oleg/.ssh/id_rsa", "path": "/etc/hosts"}))
    assert result["outcome"] == "refused"


def test_password_auth_is_off_by_default():
    result = run(file_get({"host": "192.0.2.1", "user": "root",
                           "password": "hunter2", "path": "/etc/hosts"}))
    assert result["outcome"] == "refused"
    assert "ALLOW_SSH_PASSWORD" in result["error"]
