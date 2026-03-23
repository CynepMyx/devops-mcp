import importlib
import sys
import pathlib

# Ensure project root is in path when script runs from scripts/
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

modules = [
    "tools.server_health",
    "tools.system_info",
    "tools.docker_list",
    "tools.docker_logs",
    "tools.docker_inspect",
    "tools.docker_stats",
    "tools.docker_control",
    "tools.ssh_exec",
    "tools.log_tail",
    "tools.nginx_test",
    "tools.systemd_status",
    "tools.tls_check",
    "tools.prometheus",
    "tools.search_tools",
]

failed = []
for m in modules:
    try:
        importlib.import_module(m)
        print("OK:", m)
    except ImportError as e:
        print("SKIP (missing dep):", m, "-", e)
    except Exception as e:
        print("FAIL:", m, "-", e)
        failed.append(m)

if failed:
    print("Failed modules:", failed)
    sys.exit(1)

print("Import smoke test passed")
