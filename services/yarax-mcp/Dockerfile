# ── YARA-X MCP sidecar ──────────────────────────────
# YARA-X's command-line program, yr (BSD-3-Clause), the pinned release's Linux
# build for the image's architecture (x86_64 or aarch64), under the shared MCP
# plumbing (../cli-sidecar). GitHub publishes each archive's sha256 with the
# release; each binary's was computed from its archive when it was pinned, and
# both are checked here before the binary is kept. Built with services/ as the
# context (docker/docker-compose.yml, profile `yarax`) for the architecture
# BuildKit names in TARGETARCH, else the build host's. Keep YARA_X_VERSION in
# step with YARA_X_VERSION in server.py, which the install hint names.
#
# Nothing here runs a sample: yr reads the file it is given and matches the
# operator's rule files against it. The container runs as the ids compose
# gives it (never root), with no capability, a read-only root, no route out,
# and the sample and rule directories mounted read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
ARG TARGETARCH
ARG YARA_X_VERSION=1.21.0
ARG YARA_X_AMD64_TGZ_SHA256=01585181e8979e36ac10ab123fcf8921cf8ba879bf942916413e091e18d64852
ARG YARA_X_AMD64_BINARY_SHA256=a4b6fec172c813cdfc099a4a392939cfc2c555e9e7745fb4b5ed369ab1edf93b
ARG YARA_X_ARM64_TGZ_SHA256=8d56947d82c7959a65fd4a7327d339d326649f6208c01c9f7fe7fd249e61c66a
ARG YARA_X_ARM64_BINARY_SHA256=bf811bde0a17afde24b731b567f64b854426ef7563990efffd2e19015401b0a4
WORKDIR /opt/yara-x
RUN case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
        amd64) triple=x86_64-unknown-linux-gnu tgz_sha256="${YARA_X_AMD64_TGZ_SHA256}" binary_sha256="${YARA_X_AMD64_BINARY_SHA256}" ;; \
        arm64) triple=aarch64-unknown-linux-gnu tgz_sha256="${YARA_X_ARM64_TGZ_SHA256}" binary_sha256="${YARA_X_ARM64_BINARY_SHA256}" ;; \
        *) echo "yara-x: no Linux build is pinned for ${TARGETARCH:-$(dpkg --print-architecture)}" >&2; exit 1 ;; \
    esac && \
    python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'yara-x.tar.gz')" \
        "https://github.com/VirusTotal/yara-x/releases/download/v${YARA_X_VERSION}/yara-x-v${YARA_X_VERSION}-${triple}.tar.gz" && \
    echo "${tgz_sha256}  yara-x.tar.gz" | sha256sum -c - && \
    python3 -c "import tarfile; tarfile.open('yara-x.tar.gz').extract('yr', '.', filter='data')" && \
    echo "${binary_sha256}  yr" | sha256sum -c - && \
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
    MALSPARK_SAMPLE_ROOTS=/data/samples \
    YARA_X_RULES=/data/rules
USER 65534:65534
EXPOSE 8093
CMD ["python3", "server.py"]
