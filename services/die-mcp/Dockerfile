# ── Detect It Easy MCP sidecar ──────────────────────
# Detect It Easy's console program, diec (MIT), as the Debian 13 package of the
# pinned release, checked against the sha256 the release publishes for it,
# under the shared MCP plumbing (../cli-sidecar). Built with services/ as the
# context (docker/docker-compose.yml, profile `die`). Keep DIE_VERSION in step
# with DIE_VERSION in server.py, which the install hint names.
#
# Nothing here runs a sample: diec reads the file it is given. The container
# runs as the ids compose gives it (never root), with no capability, a
# read-only root, no route out and the sample directory mounted read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
ARG DIE_VERSION=3.21
ARG DIE_DEB_SHA256=47ed1299fe0fcdf3549e4077573db9651c228144b22a372729eb014548332fcd
WORKDIR /opt/die
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'die.deb')" \
        "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_13_amd64.deb" && \
    echo "${DIE_DEB_SHA256}  die.deb" | sha256sum -c - && \
    apt-get update && \
    apt-get install -y --no-install-recommends ./die.deb && \
    rm -rf die.deb /var/lib/apt/lists/*

WORKDIR /app
COPY cli-sidecar/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cli-sidecar/cli_sidecar.py die-mcp/server.py ./

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8090 \
    MALJAN_SAMPLE_ROOTS=/data/samples
USER 65534:65534
EXPOSE 8090
CMD ["python3", "server.py"]
