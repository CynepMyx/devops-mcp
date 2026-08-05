import hashlib
import importlib
import json
import logging
import os
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import TextContent, Tool, ToolAnnotations
import uvicorn

logger = logging.getLogger(__name__)

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
from tools.db_query import db_query
from tools.file_transfer import file_get, file_put
from tools.ssh_sessions import ssh_sessions
from tools import ssh_pool

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
    "tools.db_query",
    "tools.file_transfer",
    "tools.ssh_sessions",
    # tools.ssh_pool is deliberately absent: reloading it would drop the dict
    # of live connections while the sockets stay open.
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
    from tools.db_query import db_query
    from tools.file_transfer import file_get, file_put
    from tools.ssh_sessions import ssh_sessions
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
            "db_query": db_query,
            "file_get": file_get, "file_put": file_put,
            "ssh_sessions": ssh_sessions,
        })
    print("[watcher] tools reloaded", flush=True)


_HOT_RELOAD = os.environ.get("DEV_HOT_RELOAD", "false").lower() == "true"


def _start_watcher() -> None:
    if not _HOT_RELOAD:
        return
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
    try:
        async with session_manager.run():
            yield
    finally:
        # Leaving sessions open on a client server after we stop is rude and
        # shows up in their auth log as a connection nobody closed.
        closed = ssh_pool.close_all()
        if closed:
            print(f"[pool] closed {closed} ssh connections on shutdown", flush=True)


app = FastAPI(title="DevOps MCP Server", docs_url=None, redoc_url=None, lifespan=lifespan)
mcp_server = Server("devops-mcp")
transport = SseServerTransport("/messages/")

# Streamable HTTP on /mcp, stateless: each request carries everything it needs,
# so restarting the container no longer leaves the client holding a dead session
# id and answering -32602 to every call. SSE stays mounted on /sse for clients
# that still speak it.
session_manager = StreamableHTTPSessionManager(app=mcp_server, stateless=True)

# Annotations tell the client what a tool does before it runs, so "ask the user
# first" stops depending on the model reading a description and deciding to care.
def _read_only(title: str, open_world: bool = False) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, readOnlyHint=True, destructiveHint=False,
        idempotentHint=True, openWorldHint=open_world,
    )


def _mutating(title: str, destructive: bool = True) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, readOnlyHint=False, destructiveHint=destructive,
        idempotentHint=False, openWorldHint=True,
    )


_TOOLS = [
    Tool(
        annotations=_read_only("System info"),
        name="system_info",
        description="CPU, RAM, disk usage and system uptime",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        annotations=_read_only("Docker containers"),
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
        annotations=_read_only("TLS certificate check", True),
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
        annotations=_read_only("Container logs"),
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
        annotations=_read_only("Inspect container"),
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
        annotations=_read_only("Tail log file"),
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
        annotations=_read_only("nginx config test"),
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
        annotations=_mutating("Start/stop container"),
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
        annotations=_read_only("Container stats"),
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
        annotations=_read_only("systemd unit status"),
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
        annotations=_read_only("PromQL query", True),
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
        annotations=_read_only("Prometheus targets", True),
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
        annotations=_read_only("Server health"),
        name="server_health",
        description="Full server health report: uptime, CPU, RAM, disk, Docker containers, failed systemd units",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        annotations=_read_only("Web search", True),
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
        annotations=_read_only("Semantic search", True),
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
        annotations=_mutating("Run command over SSH"),
        name="ssh_exec",
        description=(
            "Execute a command on a remote server via SSH. "
            "SSH commands are read-only by default: only safe commands (uptime, df, cat, grep, "
            "journalctl, systemctl status, docker ps, etc.) are allowed without confirmed=true. "
            "Conditionally safe commands (sed, curl, wget, find) are allowed only without mutating "
            "flags (e.g. sed -i, curl -X POST, find -exec require confirmed=true). "
            "All other commands require confirmed=true — always ask the user before setting it. "
            "Key must be located under /app/keys/. "
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
                "confirmed": {"type": "boolean", "description": "Set to true to allow commands outside the read-only allowlist, after explicit user approval"},
                "verify_host_key": {"type": "boolean", "description": "Reject unknown hosts not in /app/ssh/known_hosts (default: false)"},
            },
            "required": ["host", "user", "command"],
        },
    ),
    Tool(
        annotations=_mutating("SQL query"),
        name="db_query",
        description="Execute SQL query on PostgreSQL or MySQL database. Read-only queries (SELECT, SHOW, DESCRIBE, EXPLAIN) work without confirmation. Write queries require confirmed=true. GRANT/REVOKE/user management always blocked.",
        inputSchema={
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["postgres", "mysql"], "description": "Database type (default: postgres)"},
                "host": {"type": "string", "description": "Database host IP or hostname"},
                "port": {"type": "integer", "description": "Port (default: 5432 for postgres, 3306 for mysql)"},
                "user": {"type": "string", "description": "Database username"},
                "password": {"type": "string", "description": "Database password"},
                "database": {"type": "string", "description": "Database name"},
                "query": {"type": "string", "description": "SQL query (max 10000 chars)"},
                "timeout": {"type": "integer", "description": "Query timeout in seconds (default 30, max 120)"},
                "confirmed": {"type": "boolean", "description": "Required for mutating queries (INSERT/UPDATE/DELETE/DDL)"},
            },
            "required": ["host", "user", "database", "query"],
        },
    ),
    Tool(
        annotations=_read_only("Read remote file"),
        name="file_get",
        description=(
            "Read a file from a remote server over SFTP. No shell involved, so content "
            "with quotes, semicolons or backticks comes back verbatim. Returns content, "
            "size, mode, owner and sha256. Credential files (shadow, sudoers, private "
            "keys, authorized_keys) are refused."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Remote host IP or hostname"},
                "user": {"type": "string", "description": "SSH username"},
                "key": {"type": "string", "description": "Path to SSH key on VPS, e.g. /app/keys/vps.pem"},
                "password": {"type": "string", "description": "SSH password (alternative to key)"},
                "path": {"type": "string", "description": "Absolute path of the file to read"},
                "max_bytes": {"type": "integer", "description": "Read at most N bytes (default and max 524288)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 30, max 120)"},
                "verify_host_key": {"type": "boolean", "description": "Reject unknown hosts (default: false)"},
            },
            "required": ["host", "user", "path"],
        },
    ),
    Tool(
        annotations=_mutating("Write remote file"),
        name="file_put",
        description=(
            "Write a file on a remote server over SFTP: no shell, no length limit, no "
            "quoting problems. Keeps the existing mode and owner, writes through a "
            "temporary file in the same directory and renames it into place, and saves "
            "path.bak_<timestamp> first. Run with dry_run=true to get the unified diff "
            "without touching anything; the actual write requires confirmed=true. "
            "A file that does not exist yet needs an explicit mode. "
            "Pass verify_cmd (a config test such as 'nginx -t') to have the new file "
            "checked right after it lands: if the check fails, the previous content is "
            "put back automatically and the response says so."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Remote host IP or hostname"},
                "user": {"type": "string", "description": "SSH username"},
                "key": {"type": "string", "description": "Path to SSH key on VPS, e.g. /app/keys/vps.pem"},
                "password": {"type": "string", "description": "SSH password (alternative to key)"},
                "path": {"type": "string", "description": "Absolute path of the file to write"},
                "content": {"type": "string", "description": "Full new content of the file"},
                "mode": {"type": "string", "description": "Octal mode for a new file, e.g. '0640'. Overrides the existing mode when given."},
                "backup": {"type": "boolean", "description": "Save path.bak_<timestamp> before overwriting (default true)"},
                "dry_run": {"type": "boolean", "description": "Return the diff without writing (default false)"},
                "verify_cmd": {"type": "string", "description": "Config test to run after writing, e.g. 'nginx -t', 'apachectl configtest', 'php -l /path/file.php'. Must be a test command, not arbitrary shell."},
                "rollback_on_failure": {"type": "boolean", "description": "Restore the previous content if verify_cmd exits non-zero (default true)"},
                "confirmed": {"type": "boolean", "description": "Required for the actual write. Set only after explicit user approval."},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 30, max 120)"},
                "verify_host_key": {"type": "boolean", "description": "Reject unknown hosts (default: false)"},
            },
            "required": ["host", "user", "path", "content"],
        },
    ),
    Tool(
        # Not read-only: action='close' tears down live sessions. Claiming
        # otherwise would defeat the point of shipping annotations at all.
        annotations=_mutating("SSH sessions", destructive=False),
        name="ssh_sessions",
        description=(
            "Inspect or close the SSH connections kept open between calls. "
            "ssh_exec, file_get and file_put reuse a live connection per host and "
            "credential instead of authenticating again every time, which is faster "
            "and stops a burst of tool calls from looking like an attack to fail2ban. "
            "Connections close by themselves after being idle. action='status' lists "
            "them; action='close' drops them now, optionally only for one host or user."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["status", "close"], "description": "status (default) or close"},
                "host": {"type": "string", "description": "Only close connections to this host"},
                "user": {"type": "string", "description": "Only close connections for this username"},
            },
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
    "db_query": db_query,
    "file_get": file_get,
    "file_put": file_put,
    "ssh_sessions": ssh_sessions,
}


_SENSITIVE_KEYS = {"password", "passwd", "secret", "token"}

# Which key we connected with is the fact the audit exists to record, so a path
# under /app/keys/ is kept. Anything else in a field named 'key' is treated as
# a secret, because some future tool will put one there.
_KEY_PATH_PREFIX = "/app/keys/"

# file_put sends whole config files. Storing them verbatim would turn the audit
# log into a config archive, so long values keep a readable head plus the length
# and hash of the whole thing.
_MAX_AUDIT_VALUE = 200

# Fields the validator already bounds. ssh_exec is 72% of all calls and its
# commands are capped at 500 chars; truncating those would trade a log that
# lies for a log that cannot be read.
_LENGTH_EXEMPT = {"command"}


def _sanitize_value(name: str, value):
    lowered = name.lower()
    if lowered in _SENSITIVE_KEYS:
        return "***"
    if lowered == "key":
        if isinstance(value, str) and value.startswith(_KEY_PATH_PREFIX):
            return value
        return "***"
    if lowered in _LENGTH_EXEMPT:
        return value
    if isinstance(value, str) and len(value) > _MAX_AUDIT_VALUE:
        digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
        return f"{value[:_MAX_AUDIT_VALUE]}... <{len(value)} chars, sha256={digest}>"
    return value


def _sanitize_args(args: dict) -> dict:
    return {k: _sanitize_value(k, v) for k, v in args.items()}


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
    except Exception as exc:
        logger.warning("audit write failed: %s", exc)


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
        # Tools report failure by returning {"error": ...} rather than raising, so
        # without this the audit recorded every refusal and every failed login as
        # "ok". Tools that know they refused say so via "outcome".
        if isinstance(result, dict) and result.get("error"):
            error_msg = str(result["error"])
            status = result.get("outcome") or "error"
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
    if scope["type"] == "http" and scope.get("path", "").rstrip("/") == "/mcp":
        await session_manager.handle_request(scope, receive, send)
    elif (scope["type"] == "http"
            and scope.get("path", "").startswith("/messages/")
            and scope.get("method") == "POST"):
        await transport.handle_post_message(scope, receive, send)
    else:
        await app(scope, receive, send)


if __name__ == "__main__":
    uvicorn.run(_asgi_handler, host=MCP_HOST, port=MCP_PORT, log_level="info")
