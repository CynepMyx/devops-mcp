#!/bin/bash
set -euo pipefail

DOCKER_GID=$(getent group docker | cut -d: -f3)
echo "Using DOCKER_GID=$DOCKER_GID"

cd /opt/devops-mcp
DOCKER_GID=$DOCKER_GID docker compose build
DOCKER_GID=$DOCKER_GID docker compose up -d

echo "Done. Container status:"
docker ps --filter name=devops-mcp --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
