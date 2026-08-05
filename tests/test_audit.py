"""Tests for the audit trail written by call_tool().

The bug these pin down: every tool reports failure by returning {"error": ...}
instead of raising, so the finally-block in call_tool saw a normal return and
wrote result_status "ok". For five months the log recorded every blocked
command and every failed login as a success.

These tests go through call_tool and read the file back, because that is the
only place the lie was visible — a unit test of a classifier would have passed
against the broken code too.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import server

UNROUTABLE = "192.0.2.1"  # TEST-NET-1, guaranteed to go nowhere


@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(server, "AUDIT_LOG_PATH", str(path))
    return path


def last_record(path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.loads(fh.readlines()[-1])


def call(name: str, args: dict):
    """Drive the real handler. asyncio.run keeps pytest-asyncio out of requirements."""
    return asyncio.run(server.call_tool(name, args))


def test_blocked_command_is_not_recorded_as_ok(audit_file):
    call("ssh_exec", {
        "host": UNROUTABLE, "user": "root", "key": "/app/keys/none.pem",
        "command": "rm -rf /tmp/pwn", "confirmed": False,
    })
    record = last_record(audit_file)
    assert record["result_status"] == "refused"
    assert record["error"]


def test_missing_parameter_is_refused(audit_file):
    call("ssh_exec", {"host": UNROUTABLE, "user": "root", "key": "/app/keys/none.pem"})
    assert last_record(audit_file)["result_status"] == "refused"


def test_unreachable_host_is_recorded_as_error(audit_file):
    call("ssh_exec", {
        "host": UNROUTABLE, "user": "root", "key": "/app/keys/none.pem",
        "command": "uptime", "timeout": 2,
    })
    record = last_record(audit_file)
    assert record["result_status"] == "error"
    assert record["error"]


def test_unknown_tool_is_an_error(audit_file):
    call("no_such_tool", {})
    assert last_record(audit_file)["result_status"] == "error"


def test_successful_call_stays_ok(audit_file):
    call("system_info", {})
    record = last_record(audit_file)
    assert record["result_status"] == "ok"
    assert record["error"] is None


def test_file_put_without_confirmation_is_refused(audit_file):
    call("file_put", {
        "host": UNROUTABLE, "user": "root", "key": "/app/keys/none.pem",
        "path": "/etc/nginx/nginx.conf", "content": "worker_processes 1;",
    })
    assert last_record(audit_file)["result_status"] == "refused"


def test_credential_file_is_refused(audit_file):
    call("file_get", {
        "host": UNROUTABLE, "user": "root", "key": "/app/keys/none.pem",
        "path": "/etc/shadow",
    })
    record = last_record(audit_file)
    assert record["result_status"] == "refused"
    assert "credential" in record["error"].lower()


# --- what ends up in the record -------------------------------------------

def test_password_is_masked_and_key_path_is_kept():
    sanitized = server._sanitize_args({
        "host": "10.0.0.1", "user": "root",
        "key": "/app/keys/vps.pem", "password": "hunter2",
    })
    assert sanitized["password"] == "***"
    assert sanitized["key"] == "/app/keys/vps.pem", "which key we used is the point of the audit"
    assert sanitized["host"] == "10.0.0.1"


def test_key_field_holding_something_else_is_masked():
    assert server._sanitize_args({"key": "sk-live-abcdef"})["key"] == "***"


def test_long_content_keeps_a_readable_head_and_a_hash():
    body = "server {\n" + "x" * 5000
    value = server._sanitize_args({"content": body})["content"]
    assert value.startswith("server {"), "the head has to stay greppable"
    assert len(value) < len(body), "the body itself must not be archived in the log"
    assert "5009 chars" in value
    assert "sha256=" in value


def test_ssh_command_is_never_truncated():
    """The validator caps commands at 500 chars; that is short enough to keep whole."""
    command = "sed -i '" + "s/a/b/;" * 40 + "' /etc/nginx/nginx.conf"
    assert 200 < len(command) < 500
    assert server._sanitize_args({"command": command})["command"] == command


def test_audit_survives_an_unwritable_path(monkeypatch, tmp_path):
    """A broken audit path must not take the tool call down with it."""
    monkeypatch.setattr(server, "AUDIT_LOG_PATH", str(tmp_path / "nope" / "\x00bad"))
    result = call("system_info", {})
    assert result and result[0].text
