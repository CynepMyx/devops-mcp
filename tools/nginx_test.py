import asyncio
import docker
from security import validate_nginx_container

_NGINX_CMD = ["nginx", "-t"]


def _run_nginx_test(container_name: str) -> dict:
    client = docker.from_env(timeout=10)
    try:
        container = client.containers.get(container_name)
        exit_code, output = container.exec_run(
            cmd=_NGINX_CMD,
            stderr=True,
            stdout=True,
        )
        return {
            "container": container_name,
            "exit_code": exit_code,
            "success": exit_code == 0,
            "output": output.decode("utf-8", errors="replace"),
        }
    finally:
        client.close()


async def run_nginx_test(args: dict) -> dict:
    container_name = args.get("container_name", "nginx")
    validate_nginx_container(container_name)
    return await asyncio.to_thread(_run_nginx_test, container_name)
