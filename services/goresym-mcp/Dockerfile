# ── GoReSym MCP sidecar ─────────────────────────────
# GoReSym (MIT), the static Linux build of the pinned release, under the
# shared MCP plumbing (../cli-sidecar). The release publishes the archive's
# sha256; the binary's was computed from it when it was pinned, and both are
# checked here before the binary is kept. Built with services/ as the context
# (docker/docker-compose.yml, profile `goresym`). Keep GORESYM_VERSION in step
# with GORESYM_VERSION in server.py, which the install hint names.
#
# Nothing here runs a sample: GoReSym reads the file it is given. The
# container runs as the ids compose gives it (never root), with no capability,
# a read-only root, no route out and the sample directory mounted read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
ARG GORESYM_VERSION=3.4.1
ARG GORESYM_ZIP_SHA256=a557124857f95a589f8ce3525119c2d18c7c7fc7c4225c92ff94e3effb38748d
ARG GORESYM_BINARY_SHA256=821cb44d7bc139a46ff213fbd26ab42e76017c525c71876104708d61c68dd416
WORKDIR /opt/goresym
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'goresym.zip')" \
        "https://github.com/mandiant/GoReSym/releases/download/v${GORESYM_VERSION}/GoReSym-linux.zip" && \
    echo "${GORESYM_ZIP_SHA256}  goresym.zip" | sha256sum -c - && \
    python3 -c "import zipfile; zipfile.ZipFile('goresym.zip').extract('GoReSym', '.')" && \
    echo "${GORESYM_BINARY_SHA256}  GoReSym" | sha256sum -c - && \
    install -m 0755 GoReSym /usr/local/bin/GoReSym && \
    rm -f goresym.zip GoReSym

WORKDIR /app
COPY cli-sidecar/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cli-sidecar/cli_sidecar.py goresym-mcp/server.py ./

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8092 \
    MALJAN_SAMPLE_ROOTS=/data/samples
USER 65534:65534
EXPOSE 8092
CMD ["python3", "server.py"]
