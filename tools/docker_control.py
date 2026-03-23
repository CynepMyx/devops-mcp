import asyncio
import os
import docker

# Read protected containers from env; defaults to devops-mcp
_protected_raw = os.environ.get("PROTECTED_CONTAINERS", "devops-mcp")
PROTECTED = {c.strip() for c in _protected_raw.split(",") if c.strip()}


def _control(action: str, name: str) -> dict:
    if name in PROTECTED:
        return {"error": f"Container '{name}' is protected and cannot be controlled"}

    client = docker.from_env(timeout=10)
    try:
        container = client.containers.get(name)
        if action == "restart":
            container.restart(timeout=30)
        elif action == "stop":
            container.stop(timeout=30)
        elif action == "start":
            container.start()
        else:
            return {"error": f"Unknown action: {action}"}

        container.reload()
        return {
            "action": action,
            "container": name,
            "status": container.status,
        }
    finally:
        client.close()


async def docker_control(args: dict) -> dict:
    action = args.get("action", "").strip().lower()
    name = args.get("name", "").strip()

    if not action:
        return {"error": "Parameter 'action' is required (restart|stop|start)"}
    if not name:
        return {"error": "Parameter 'name' is required"}
    if action not in ("restart", "stop", "start"):
        return {"error": f"Invalid action '{action}'. Must be one of: restart, stop, start"}

    return await asyncio.to_thread(_control, action, name)
