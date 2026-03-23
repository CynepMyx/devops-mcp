import importlib
import json
import os
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool
import uvicorn

from tools.system_info import get_system_info
from tools.docker_list import get_docker_list
from tools.docker_logs import get_docker_logs
from tools.docker_inspect import get_docker_inspect
from tools.tls_check import check_tls
from tools.log_tail import tail_log
from tools.nginx_test import run_nginx_test
from tools.systemd_status import get_systemd_status
from tools.docker_control import docker_control
from tools.docker_stats import get_docker_stats
from tools.ssh_exec import ssh_exec
from tools.prometheus import prometheus_query, prometheus_targets
from tools.search_tools import search_web, search_ai
from tools.server_health import get_server_health

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/audit/audit.jsonl")
MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", "8765"))

_TOOL_MODULES = [
    "tools.system_info", "tools.docker_list", "tools.docker_logs",
    "tools.docker_inspect", "tools.tls_check", "tools.log_tail",
    "tools.nginx_test", "tools.systemd_status", "tools.docker_control",
    "tools.docker_stats", "tools.ssh_exec", "tools.prometheus",
    "tools.search_tools",
    "tools.server_health",
]


def _reload_tools() -> None:
    for name in _TOOL_MODULES:
        if name in sys.modules:
            try:
                importlib.reload(sys.modules[name])
            except Exception as e:
                print(f"[watcher] reload error {name}: {e}", flush=True)
    from tools.system_info import get_system_info
    from tools.docker_list import get_docker_list
    from tools.docker_logs import get_docker_logs
    from tools.docker_inspect import get_docker_inspect
    from tools.tls_check import check_tls
    from tools.log_tail import tail_log
    from tools.nginx_test import run_nginx_test
    from tools.systemd_status import get_systemd_status
    from tools.docker_control import docker_control
    from tools.docker_stats import get_docker_stats
    from tools.ssh_exec import ssh_exec
    from tools.prometheus import prometheus_query, prometheus_targets
    from tools.search_tools import search_web, search_ai
    from tools.server_health import get_server_health
    with _DISPATCH_LOCK:
        _DISPATCH.update({
            "system_info": get_system_info, "docker_list": get_docker_list,
            "docker_logs": get_docker_logs, "docker_inspect": get_docker_inspect,
            "tls_check": check_tls, "log_tail": tail_log,
            "nginx_test": run_nginx_test, "systemd_status": get_systemd_status,
            "docker_control": docker_control, "docker_stats": get_docker_stats,
            "ssh_exec": ssh_exec, "prometheus_query": prometheus_query,
            "prometheus_targets": prometheus_targets,
            "search_web": search_web, "search_ai": search_ai,
            "server_health": get_server_health,
        })
    print("[watcher] tools reloaded", flush=True)


def _start_watcher() -> None:
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class _Handler(FileSystemEventHandler):
            _last = 0.0

            def on_modified(self, event):
                if not event.src_path.endswith(".py"):
                    return
                now = time.monotonic()
                if now - _Handler._last < 1.0:
                    return
                _Handler._last = now
                print(f"[watcher] changed: {event.src_path}", flush=True)
                _reload_tools()

        obs = Observer()
        obs.schedule(_Handler(), "/app/tools", recursive=False)
        obs.daemon = True
        obs.start()
        print("[watcher] watching /app/tools", flush=True)
    except ImportError:
        print("[watcher] watchdog not installed, hot-reload disabled", flush=True)


@asynccontextmanager
async def lifespan(_app):
    _start_watcher()
    yield


app = FastAPI(title="DevOps MCP Server", docs_url=None, redoc_url=None, lifespan=lifespan)
mcp_server = Server("devops-mcp")
transport = SseServerTransport("/messages/")

_TOOLS = [
    Tool(
        name="system_info",
        description="CPU, RAM, disk usage and system uptime",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="docker_list",
        description="List Docker containers with status",
        inputSchema={
            "type": "object",
            "properties": {
                "all": {"type": "boolean", "description": "Include stopped containers (default true)"},
                "name_filter": {"type": "string", "description": "Filter by container name substring"},
            },
        },
    ),
    Tool(
        name="tls_check",
        description="Check TLS certificate: expiry, CN, SAN, cipher",
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to check"},
                "port": {"type": "integer", "description": "Port (default 443)"},
                "timeout": {"type": "integer", "description": "Connection timeout seconds (default 10, max 30)"},
            },
            "required": ["host"],
        },
    ),
    Tool(
        name="docker_logs",
        description="Get last N log lines from a Docker container",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Container name or ID"},
                "lines": {"type": "integer", "description": "Number of lines (default 100, max 500)"},
                "grep": {"type": "string", "description": "Filter lines containing this substring"},
                "since": {"type": "integer", "description": "Show logs from last N seconds (e.g. 300 = last 5 minutes)"},
            },
            "required": ["name"],
        },
    ),
    Tool(
        name="docker_inspect",
        description="Inspect a Docker container: image, ports, volumes, env, network",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Container name or ID"},
            },
            "required": ["name"],
        },
    ),
    Tool(
        name="log_tail",
        description="Read last N lines from an allowed log file",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Log file path (must be in allowlist)"},
                "lines": {"type": "integer", "description": "Number of lines (default 50, max 500)"},
                "grep": {"type": "string", "description": "Optional substring filter"},
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="nginx_test",
        description="Run nginx -t inside a container to validate config",
        inputSchema={
            "type": "object",
            "properties": {
                "container_name": {"type": "string", "description": "Container name (default: nginx)"},
            },
        },
    ),
    Tool(
        name="docker_control",
        description=(
            "Start, stop, or restart a Docker container. "
            "stop and restart are destructive actions and require confirmed=true. "
            "Always ask the user before setting confirmed=true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Action to perform: restart, stop, start"},
                "name": {"type": "string", "description": "Container name or ID"},
                "confirmed": {
                    "type": "boolean",
                    "description": "Must be true for stop and restart. Set only after explicit user approval.",
                },
            },
            "required": ["action", "name"],
        },
    ),
    Tool(
        name="docker_stats",
        description="Get CPU, memory and network stats for a running Docker container",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Container name or ID"},
            },
            "required": ["name"],
        },
    ),
    Tool(
        name="systemd_status",
        description="Get systemd unit status: active state, sub state, description, memory, PID",
        inputSchema={
            "type": "object",
            "properties": {
                "unit": {"type": "string", "description": "Single unit name, e.g. 'ssh.service'"},
                "units": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple unit names",
                },
            },
        },
    ),
    Tool(
        name="prometheus_query",
        description="Execute a PromQL query against Prometheus. Supports instant and range queries.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "PromQL expression"},
                "time": {"type": "string", "description": "Evaluation timestamp for instant query (RFC3339 or Unix)"},
                "start": {"type": "string", "description": "Range query start (RFC3339 or Unix)"},
                "end": {"type": "string", "description": "Range query end (RFC3339 or Unix)"},
                "step": {"type": "string", "description": "Range query step duration, e.g. '60' or '5m' (default: 60)"},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="prometheus_targets",
        description="List Prometheus scrape targets and their health status",
        inputSchema={
            "type": "object",
            "properties": {
                "state": {"type": "string", "description": "Filter by state: active, dropped, any (default: any)"},
            },
        },
    ),
    Tool(
        name="server_health",
        description="Full server health report: uptime, CPU, RAM, disk, Docker containers, failed systemd units",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="search_web",
        description="Search the web via Google (SerpAPI). Returns titles, URLs and snippets.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "description": "Number of results (default 5, max 10)"},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="search_ai",
        description="Semantic search via EXA — finds dev docs, GitHub, engineering articles. Better than Google for technical queries.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "description": "Number of results (default 5, max 10)"},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="ssh_exec",
        description=(
            "Execute a command on a remote server via SSH. "
            "Key must be located under /app/keys/. "
            "Dangerous commands (rm, reboot, shutdown, systemctl start/stop/restart, etc.) "
            "require confirmed=true — only set this after explicit user approval. "
            "By default connects with warn policy (unknown hosts are allowed but reported). "
            "Set verify_host_key=true to reject hosts not in /app/ssh/known_hosts."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Remote host IP or hostname"},
                "user": {"type": "string", "description": "SSH username"},
                "key": {"type": "string", "description": "Path to SSH key on VPS, e.g. /app/keys/client.pem"},
                "password": {"type": "string", "description": "SSH password (alternative to key)"},
                "command": {"type": "string", "description": "Command to execute (max 500 chars, no shell injection)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 30, max 120)"},
                "confirmed": {"type": "boolean", "description": "Set to true to allow dangerous commands after user approval"},
                "verify_host_key": {"type": "boolean", "description": "Reject unknown hosts not in /app/ssh/known_hosts (default: false)"},
            },
            "required": ["host", "user", "command"],
        },
    ),
]

_DISPATCH_LOCK = threading.Lock()

_DISPATCH = {
    "system_info": get_system_info,
    "docker_list": get_docker_list,
    "docker_logs": get_docker_logs,
    "docker_inspect": get_docker_inspect,
    "tls_check": check_tls,
    "log_tail": tail_log,
    "nginx_test": run_nginx_test,
    "systemd_status": get_systemd_status,
    "docker_control": docker_control,
    "docker_stats": get_docker_stats,
    "ssh_exec": ssh_exec,
    "prometheus_query": prometheus_query,
    "prometheus_targets": prometheus_targets,
    "search_web": search_web,
    "search_ai": search_ai,
    "server_health": get_server_health,
}


_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "key"}


def _sanitize_args(args: dict) -> dict:
    return {k: "***" if k.lower() in _SENSITIVE_KEYS else v for k, v in args.items()}


def _write_audit(tool: str, args: dict, status: str, error: str | None, duration_ms: int) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "args": _sanitize_args(args),
        "result_status": status,
        "error": error,
        "duration_ms": duration_ms,
    }
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


@mcp_server.list_tools()
async def list_tools() -> list[Tool]:
    return _TOOLS


@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    start = time.monotonic()
    error_msg: str | None = None
    status = "ok"

    try:
        with _DISPATCH_LOCK:
            handler = _DISPATCH.get(name)
        if handler is None:
            raise ValueError(f"Unknown tool: {name}")
        result = await handler(arguments)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        return [TextContent(type="text", text=text)]
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        status = "error"
        return [TextContent(type="text", text=json.dumps({"error": error_msg}))]
    finally:
        duration_ms = round((time.monotonic() - start) * 1000)
        _write_audit(name, arguments, status, error_msg, duration_ms)


@app.get("/sse")
async def sse_endpoint(request: Request):
    async with transport.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp_server.run(
            streams[0],
            streams[1],
            mcp_server.create_initialization_options(),
        )


@app.get("/health")
async def health():
    return {"status": "ok"}


async def _asgi_handler(scope, receive, send):
    if (scope["type"] == "http"
            and scope.get("path", "").startswith("/messages/")
            and scope.get("method") == "POST"):
        await transport.handle_post_message(scope, receive, send)
    else:
        await app(scope, receive, send)


if __name__ == "__main__":
    uvicorn.run(_asgi_handler, host=MCP_HOST, port=MCP_PORT, log_level="info")
