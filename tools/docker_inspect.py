import asyncio
import docker


def _fetch_inspect(name: str) -> dict:
    client = docker.from_env(timeout=10)
    try:
        container = client.containers.get(name)
        attrs = container.attrs

        # Сетевые настройки
        networks = {
            net: info.get("IPAddress")
            for net, info in attrs["NetworkSettings"]["Networks"].items()
        }

        # Порты
        ports = [
            f"{hp['HostIp']}:{hp['HostPort']}"
            for bindings in attrs["NetworkSettings"]["Ports"].values()
            if bindings
            for hp in bindings
        ]

        # Volumes
        mounts = [
            {"src": m["Source"], "dst": m["Destination"], "mode": m.get("Mode", "")}
            for m in attrs.get("Mounts", [])
        ]

        # Env (фильтруем секреты по ключевым словам)
        secret_keys = {"password", "secret", "token", "key", "api_key", "apikey", "pass"}
        env_raw = attrs["Config"].get("Env") or []
        env = {}
        for entry in env_raw:
            if "=" in entry:
                k, v = entry.split("=", 1)
                if any(s in k.lower() for s in secret_keys):
                    v = "***"
                env[k] = v

        return {
            "name": container.name,
            "id": container.short_id,
            "status": container.status,
            "image": attrs["Config"]["Image"],
            "created": attrs["Created"],
            "restart_policy": attrs["HostConfig"]["RestartPolicy"]["Name"],
            "ports": ports,
            "networks": networks,
            "mounts": mounts,
            "env": env,
        }
    except docker.errors.NotFound:
        return {"error": f"Container not found: {name}"}
    except docker.errors.DockerException as e:
        return {"error": f"Docker error: {e}"}
    finally:
        client.close()


async def get_docker_inspect(args: dict) -> dict:
    name = args.get("name")
    if not name:
        return {"error": "Parameter 'name' is required"}
    return await asyncio.to_thread(_fetch_inspect, name)
