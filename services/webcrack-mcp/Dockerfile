# ── webcrack MCP sidecar ────────────────────────────
# webcrack (MIT) on Node.js, under the shared MCP plumbing (../cli-sidecar).
# Node.js is the official Linux build of the pinned release, checked against
# the sha256 its release's SHASUMS256.txt publishes; webcrack and every package
# it needs are pinned by integrity hash in package-lock.json and installed with
# npm ci --ignore-scripts, so no package's install script runs. Built with
# services/ as the context (docker/docker-compose.yml, profile `webcrack`).
# Keep webcrack's version in package.json in step with WEBCRACK_VERSION in
# server.py, which the install hint names.
#
# Nothing here runs a script: webcrack parses the file it is given and
# rewrites the syntax tree. The sandbox webcrack would evaluate an
# obfuscator's string decoders in is never handed to it (deobfuscate.mjs),
# and its module (isolated-vm) is removed from the image after the install.
# The container runs as the ids compose gives it (never root), with no
# capability, a read-only root, no route out and the sample directory mounted
# read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39 AS node
ARG NODE_VERSION=22.23.3
ARG NODE_TXZ_SHA256=df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de
WORKDIR /opt
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'node.tar.xz')" \
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" && \
    echo "${NODE_TXZ_SHA256}  node.tar.xz" | sha256sum -c - && \
    python3 -c "import tarfile; tarfile.open('node.tar.xz').extractall('.', filter='data')" && \
    mv "node-v${NODE_VERSION}-linux-x64" node && \
    rm -f node.tar.xz
WORKDIR /app
COPY webcrack-mcp/package.json webcrack-mcp/package-lock.json ./
RUN PATH="/opt/node/bin:${PATH}" npm ci --ignore-scripts --omit=dev --no-audit --no-fund && \
    rm -rf node_modules/isolated-vm

FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
COPY --from=node /opt/node/bin/node /usr/local/bin/node
WORKDIR /app
COPY --from=node /app/node_modules ./node_modules
COPY cli-sidecar/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cli-sidecar/cli_sidecar.py webcrack-mcp/server.py webcrack-mcp/deobfuscate.mjs webcrack-mcp/package.json ./

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8095 \
    MALJAN_SAMPLE_ROOTS=/data/samples
USER 65534:65534
EXPOSE 8095
CMD ["python3", "server.py"]
