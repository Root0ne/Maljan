# ── YARA-X MCP sidecar ──────────────────────────────
# YARA-X's command-line program, yr (BSD-3-Clause), the Linux build of the
# pinned release, under the shared MCP plumbing (../cli-sidecar). GitHub
# publishes the archive's sha256 with the release; the binary's was computed
# from it when it was pinned, and both are checked here before the binary is
# kept. Built with services/ as the context (docker/docker-compose.yml,
# profile `yarax`). Keep YARA_X_VERSION in step with YARA_X_VERSION in
# server.py, which the install hint names.
#
# Nothing here runs a sample: yr reads the file it is given and matches the
# operator's rule files against it. The container runs as the ids compose
# gives it (never root), with no capability, a read-only root, no route out,
# and the sample and rule directories mounted read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
ARG YARA_X_VERSION=1.21.0
ARG YARA_X_TGZ_SHA256=01585181e8979e36ac10ab123fcf8921cf8ba879bf942916413e091e18d64852
ARG YARA_X_BINARY_SHA256=a4b6fec172c813cdfc099a4a392939cfc2c555e9e7745fb4b5ed369ab1edf93b
WORKDIR /opt/yara-x
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'yara-x.tar.gz')" \
        "https://github.com/VirusTotal/yara-x/releases/download/v${YARA_X_VERSION}/yara-x-v${YARA_X_VERSION}-x86_64-unknown-linux-gnu.tar.gz" && \
    echo "${YARA_X_TGZ_SHA256}  yara-x.tar.gz" | sha256sum -c - && \
    python3 -c "import tarfile; tarfile.open('yara-x.tar.gz').extract('yr', '.', filter='data')" && \
    echo "${YARA_X_BINARY_SHA256}  yr" | sha256sum -c - && \
    install -m 0755 yr /usr/local/bin/yr && \
    rm -f yara-x.tar.gz yr

WORKDIR /app
COPY cli-sidecar/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cli-sidecar/cli_sidecar.py yarax-mcp/server.py ./

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8093 \
    MALJAN_SAMPLE_ROOTS=/data/samples \
    YARA_X_RULES=/data/rules
USER 65534:65534
EXPOSE 8093
CMD ["python3", "server.py"]
