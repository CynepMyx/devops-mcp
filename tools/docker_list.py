import asyncio
import docker


def _fetch_containers(show_all: bool, name_filter: str) -> dict:
    client = docker.from_env(timeout=10)
    try:
        filters = {}
        if name_filter:
            filters["name"] = name_filter

        containers = client.containers.list(all=show_all, filters=filters)

        result = []
        for c in containers:
            ports = [
                f"{hp['HostIp']}:{hp['HostPort']}"
                for bindings in c.attrs["NetworkSettings"]["Ports"].values()
                if bindings
                for hp in bindings
            ]
            health = c.attrs.get("State", {}).get("Health", {}).get("Status")
            entry = {"name": c.name, "status": c.status, "ports": ports}
            if health:
                entry["health"] = health
            result.append(entry)

        return {"count": len(result), "containers": result}
    finally:
        client.close()


async def get_docker_list(args: dict) -> dict:
    show_all = bool(args.get("all", True))
    name_filter = args.get("name_filter", "")
    return await asyncio.to_thread(_fetch_containers, show_all, name_filter)
