# ── JADX MCP sidecar ────────────────────────────────
# JADX's command-line decompiler (Apache-2.0) on the Eclipse Temurin 21 Java
# runtime, under the shared MCP plumbing (../cli-sidecar). The runtime is the
# release's Linux archive and JADX the release's own archive, each checked
# against the sha256 GitHub publishes for it before its contents are kept;
# JADX's jar is run on the runtime directly. Built with services/ as the
# context (docker/docker-compose.yml, profile `jadx`). Keep JADX_VERSION in
# step with JADX_VERSION in server.py, which the install hint names.
#
# Nothing here runs a sample: JADX reads the dex bytecode and writes Java
# source, and loads no class of the sample into a virtual machine. The
# container runs as the ids compose gives it (never root), with no capability,
# a read-only root, no route out and the sample directory mounted read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
ARG JRE_VERSION=21.0.12.1
ARG JRE_BUILD=1
ARG JRE_TGZ_SHA256=2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500
ARG JADX_VERSION=1.5.6
ARG JADX_ZIP_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
WORKDIR /opt
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'jre.tar.gz')" \
        "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${JRE_VERSION}%2B${JRE_BUILD}/OpenJDK21U-jre_x64_linux_hotspot_${JRE_VERSION}_${JRE_BUILD}.tar.gz" && \
    echo "${JRE_TGZ_SHA256}  jre.tar.gz" | sha256sum -c - && \
    python3 -c "import tarfile; tarfile.open('jre.tar.gz').extractall('.', filter='data')" && \
    mv "jdk-${JRE_VERSION}+${JRE_BUILD}-jre" jre && \
    rm -f jre.tar.gz
WORKDIR /opt/jadx
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'jadx.zip')" \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" && \
    echo "${JADX_ZIP_SHA256}  jadx.zip" | sha256sum -c - && \
    python3 -c "import pathlib, sys, zipfile; pathlib.Path('jadx.jar').write_bytes(zipfile.ZipFile('jadx.zip').read(f'lib/jadx-{sys.argv[1]}-all.jar'))" "${JADX_VERSION}" && \
    rm -f jadx.zip && \
    test -s jadx.jar

WORKDIR /app
COPY cli-sidecar/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cli-sidecar/cli_sidecar.py jadx-mcp/server.py ./

ENV PATH=/opt/jre/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    JADX_JAR=/opt/jadx/jadx.jar \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8097 \
    MALJAN_SAMPLE_ROOTS=/data/samples
USER 65534:65534
EXPOSE 8097
CMD ["python3", "server.py"]
