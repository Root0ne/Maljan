# ── unblob MCP sidecar ──────────────────────────────
# unblob (MIT) and the extractors it calls, under the shared MCP plumbing
# (../cli-sidecar). Every Python package is pinned by hash in requirements.txt
# (unblob 26.6.4 and what it needs, the MCP SDK at the versions ../cli-sidecar
# pins), wheels only. sasquatch, the SquashFS extractor unblob needs for
# vendors' variants, is the release's Debian package, checked against the
# sha256 GitHub publishes for it; the other extractors are Debian's own
# packages. Built with services/ as the context (docker/docker-compose.yml,
# profile `unblob`). Keep unblob in requirements.txt in step with
# UNBLOB_VERSION in server.py, which the install hint names.
#
# Nothing here runs a sample or anything carved from one: unblob and its
# extractors read the file and write what it holds into a directory of its own
# under the carve root, a tmpfs (UNBLOB_CARVE_ROOT). The container runs as the
# ids compose gives it (never root, so no device file can be made), with no
# capability, a read-only root, no route out and the sample directory mounted
# read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
ARG SASQUATCH_RELEASE=sasquatch-v4.5.1-6
ARG SASQUATCH_DEB_SHA256=efbc92bd27594e01211e1b582f105a463a0017360a0746a93de3f283906ade95
WORKDIR /opt/unblob
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'sasquatch.deb')" \
        "https://github.com/onekey-sec/sasquatch/releases/download/${SASQUATCH_RELEASE}/sasquatch_1.0_amd64.deb" && \
    echo "${SASQUATCH_DEB_SHA256}  sasquatch.deb" | sha256sum -c - && \
    apt-get update && \
    apt-get install -y --no-install-recommends ./sasquatch.deb \
        7zip android-sdk-libsparse-utils e2fsprogs erofs-utils libmagic1t64 lz4 lziprecover \
        util-linux \
        lzop partclone unar upx-ucl xz-utils zstd && \
    rm -rf sasquatch.deb /var/lib/apt/lists/*

WORKDIR /app
COPY unblob-mcp/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.txt
COPY cli-sidecar/cli_sidecar.py unblob-mcp/server.py ./

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8096 \
    MALJAN_SAMPLE_ROOTS=/data/samples \
    UNBLOB_CARVE_ROOT=/tmp/carved
USER 65534:65534
EXPOSE 8096
CMD ["python3", "server.py"]
