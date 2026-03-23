import asyncio
import time
import docker


def _fetch_logs(name: str, lines: int, since: int | None, grep: str | None) -> dict:
    client = docker.from_env(timeout=10)
    try:
        container = client.containers.get(name)
        kwargs = dict(tail=lines, timestamps=True)
        if since is not None:
            kwargs["since"] = int(time.time()) - since
        raw = container.logs(**kwargs).decode("utf-8", errors="replace")
        log_lines = [l for l in raw.splitlines() if l]
        if grep:
            log_lines = [l for l in log_lines if grep in l]
        return {
            "name": container.name,
            "status": container.status,
            "lines_returned": len(log_lines),
            "logs": log_lines,
        }
    finally:
        client.close()


async def get_docker_logs(args: dict) -> dict:
    name = args.get("name")
    if not name:
        return {"error": "Parameter 'name' is required"}
    lines = min(int(args.get("lines", 100)), 500)
    since = args.get("since")
    if since is not None:
        since = max(1, int(since))
    grep = args.get("grep") or None
    return await asyncio.to_thread(_fetch_logs, name, lines, since, grep)
