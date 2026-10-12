"""docker_control must not touch the MCP's own container under any of its names.

The name check compared the argument as typed, and Docker resolves '/devops-mcp'
and an ID prefix to the same container: 'start /devops-mcp' went through on the
live server (audit 12.10.2026). With confirmed=true the same path stops the MCP.
"""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tools import docker_control as dc


class FakeContainer:
    def __init__(self, name):
        self.name = name
        self.status = "running"
        self.calls = []

    def restart(self, timeout=None):
        self.calls.append("restart")

    def stop(self, timeout=None):
        self.calls.append("stop")

    def start(self):
        self.calls.append("start")

    def reload(self):
        pass


@pytest.fixture
def fleet(monkeypatch):
    containers = {"devops-mcp": FakeContainer("devops-mcp"), "nginx": FakeContainer("nginx")}
    aliases = {"/devops-mcp": "devops-mcp", "8911408bc57d": "devops-mcp", "891140": "devops-mcp"}

    def get(name):
        return containers[aliases.get(name, name)]

    client = types.SimpleNamespace(containers=types.SimpleNamespace(get=get), close=lambda: None)
    monkeypatch.setattr(dc.docker, "from_env", lambda timeout=10: client)
    monkeypatch.setattr(dc, "PROTECTED", {"devops-mcp"})
    return containers


@pytest.mark.parametrize("name", ["devops-mcp", "/devops-mcp", "8911408bc57d", "891140"])
def test_the_mcp_container_is_protected_under_every_name(fleet, name):
    result = asyncio.run(dc.docker_control({"action": "stop", "name": name, "confirmed": True}))
    assert result.get("outcome") == "refused"
    assert fleet["devops-mcp"].calls == []


def test_other_containers_still_work(fleet):
    result = asyncio.run(dc.docker_control({"action": "restart", "name": "nginx", "confirmed": True}))
    assert result.get("status") == "running"
    assert fleet["nginx"].calls == ["restart"]
