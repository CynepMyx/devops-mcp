"""Tests for quote-aware command validation in security.py.

Before _mask_quotes() the validator matched dangerous substrings against the
raw command, so a semicolon inside an nginx directive or an HTML tag in an
alert body was indistinguishable from shell syntax. These tests pin down both
sides: what must now be allowed, and what must still be blocked.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from security import validate_ssh_command, _split_shell_commands, _mask_quotes

SQ = chr(39)
DOLLAR = chr(36)
BACKTICK = chr(96)


# --- payload that used to be rejected and must now pass -------------------

@pytest.mark.parametrize("command", [
    # nginx directive: semicolon is data, not a separator
    "sed -i " + SQ + "106a\\        limit_req zone=z burst=10 nodelay;" + SQ + " /etc/nginx/x.conf",
    # HTML in an alert body is not a redirect
    "printf " + SQ + "%s" + SQ + " " + SQ + "<b>alert</b>" + SQ + " | tee /tmp/a.txt",
    # allowlist keywords inside a grep pattern must not trigger confirmation
    "grep -n " + SQ + "ServerLimit httpd" + SQ + " /etc/apache2/apache2.conf",
    # single quotes stop expansion, so this is literal text
    "printf " + SQ + "%s" + SQ + " " + SQ + "x=" + DOLLAR + "(date)" + SQ + " | tee /tmp/b.txt",
])
def test_quoted_payload_is_allowed(command):
    validate_ssh_command(command, confirmed=True)


# --- syntax that must stay blocked ---------------------------------------

@pytest.mark.parametrize("command", [
    "echo " + DOLLAR + "(whoami)",                       # substitution, unquoted
    'echo "' + DOLLAR + '(whoami)"',                     # double quotes still expand
    "echo " + BACKTICK + "id" + BACKTICK,                # backticks, unquoted
    'echo "' + BACKTICK + 'id' + BACKTICK + '"',         # backticks in double quotes
    "cat /etc/passwd > /tmp/x",                          # redirect
    "cat /etc/passwd >/tmp/x",                           # redirect without space
    "echo test >> /etc/crontab",                         # append
])
def test_shell_syntax_is_blocked(command):
    with pytest.raises(ValueError):
        validate_ssh_command(command, confirmed=True)


@pytest.mark.parametrize("separator", [";", "&&", "||", "|", "&", "\n", "\r"])
def test_every_separator_exposes_the_second_command(separator):
    """A dangerous command hidden after any separator must still be inspected.

    Regression: newline and bare '&' were missing from the operator list, so
    'uptime\\nrm -rf /tmp/x' was judged solely by 'uptime' and passed unconfirmed.
    """
    with pytest.raises(ValueError):
        validate_ssh_command("uptime" + separator + "rm -rf /tmp/pwn", confirmed=False)


def test_process_substitution_is_blocked():
    with pytest.raises(ValueError):
        validate_ssh_command("cat <(rm -rf /tmp/pwn)", confirmed=True)


@pytest.mark.parametrize("command", [
    "docker network rm mynet",          # parent prefix must not cover destructive verbs
    "docker network prune -f",
    "docker volume rm data",
    "ip link set eth0 down",            # locks us out of the server
    "ip route del default",
    "ip addr flush dev eth0",
    "journalctl --rotate",              # wipes the evidence
    "journalctl --vacuum-size=1M",
    "top",                              # interactive, would hang until timeout
    "less /var/log/syslog",
])
def test_destructive_or_interactive_need_confirmation(command):
    with pytest.raises(ValueError):
        validate_ssh_command(command, confirmed=False)


@pytest.mark.parametrize("command", [
    "docker network ls",
    "docker network inspect bridge",
    "ip a",
    "ip route show",
    "journalctl -u nginx -n 50",
    "dmesg | tail -20",
])
def test_read_only_variants_still_pass(command):
    validate_ssh_command(command, confirmed=False)


def test_length_limit_still_enforced():
    with pytest.raises(ValueError):
        validate_ssh_command("ls " + "a" * 600, confirmed=True)


# --- splitting ------------------------------------------------------------

def test_operator_outside_quotes_splits():
    parts = _split_shell_commands("ls -la && grep -c " + SQ + "a;b" + SQ + " /tmp/f")
    assert len(parts) == 2
    assert "grep" in parts[1]


def test_operators_inside_quotes_do_not_split():
    parts = _split_shell_commands("grep -n " + SQ + "foo;bar|baz" + SQ + " /tmp/f")
    assert len(parts) == 1


@pytest.mark.parametrize("command", [
    "ls -la",
    "grep " + SQ + "a;b" + SQ + " f",
    'echo "x>y"',
    "sed -i " + SQ + "s/a/b;/" + SQ + " f",
])
def test_mask_preserves_length(command):
    mask, _ = _mask_quotes(command)
    assert len(mask) == len(command), "positions must map onto the original string"


# --- allowlist behaviour unchanged ---------------------------------------

@pytest.mark.parametrize("command", ["docker ps", "systemctl status nginx"])
def test_readonly_commands_need_no_confirmation(command):
    validate_ssh_command(command, confirmed=False)


@pytest.mark.parametrize("command", ["sudo rm -rf /tmp/x", "wp core update"])
def test_unknown_commands_require_confirmation(command):
    with pytest.raises(ValueError):
        validate_ssh_command(command, confirmed=False)
