# Two stages: gcc is needed only to build wheels, the final image does not carry it.
FROM python:3.12-slim-trixie AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim-trixie

ARG DOCKER_GID=999

COPY --from=build /install /usr/local

WORKDIR /app

COPY . .

RUN useradd -m -u 1000 mcpuser \
    && groupadd -g ${DOCKER_GID} dockerhost 2>/dev/null || true \
    && usermod -aG dockerhost mcpuser \
    && mkdir -p /audit \
    && chown mcpuser:mcpuser /audit

USER mcpuser

ENV MCP_HOST=127.0.0.1
ENV MCP_PORT=8765
ENV PYTHONUNBUFFERED=1

EXPOSE 8765

CMD ["python", "server.py"]
