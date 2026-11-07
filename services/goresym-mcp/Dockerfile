# ── GoReSym MCP sidecar ─────────────────────────────
# GoReSym (MIT), under the shared MCP plumbing (../cli-sidecar), for the
# architecture BuildKit names in TARGETARCH (amd64 or arm64; no other has a
# stage, so the build stops). Built with services/ as the context
# (docker/docker-compose.yml, profile `goresym`); it needs BuildKit, which
# compose and buildx use. Keep GORESYM_VERSION in step with GORESYM_VERSION in
# server.py, which the install hint names.
#
# On amd64 it is the release's static Linux build: the release publishes the
# archive's sha256; the binary's was computed from it when it was pinned, and
# both are checked before the binary is kept. The release has no arm64 build,
# so on arm64 the pinned tag is cloned, its commit must be GORESYM_COMMIT or
# the build stops, and it is compiled with the Go toolchain of the
# digest-pinned image below, never one fetched at build time, its modules
# checked against the tree's go.sum and the checksum database. The compiler
# runs on the build host's platform and cross-compiles, as upstream's release
# build does (cgo off, version stamped; no VCS stamp, so the clone's metadata
# changes nothing), and the binary must match the sha256 it was pinned with.
# The same bytes come out of an amd64 host's cross-compile and an arm64 host's
# native build: CI builds this stage both ways and checks both against it.
#
# Nothing here runs a sample: GoReSym reads the file it is given. The
# container runs as the ids compose gives it (never root), with no capability,
# a read-only root, no route out and the sample directory mounted read-only.
ARG TARGETARCH
ARG GORESYM_VERSION=3.4.1

FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39 AS goresym-amd64
ARG GORESYM_VERSION
ARG GORESYM_ZIP_SHA256=a557124857f95a589f8ce3525119c2d18c7c7fc7c4225c92ff94e3effb38748d
ARG GORESYM_AMD64_BINARY_SHA256=821cb44d7bc139a46ff213fbd26ab42e76017c525c71876104708d61c68dd416
WORKDIR /opt/goresym
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'goresym.zip')" \
        "https://github.com/mandiant/GoReSym/releases/download/v${GORESYM_VERSION}/GoReSym-linux.zip" && \
    echo "${GORESYM_ZIP_SHA256}  goresym.zip" | sha256sum -c - && \
    python3 -c "import zipfile; zipfile.ZipFile('goresym.zip').extract('GoReSym', '.')" && \
    echo "${GORESYM_AMD64_BINARY_SHA256}  GoReSym" | sha256sum -c - && \
    mkdir /out && install -m 0755 GoReSym /out/GoReSym && \
    rm -f goresym.zip GoReSym

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS goresym-arm64
ARG GORESYM_VERSION
ARG GORESYM_COMMIT=722897e0a80da0a06c00c5e40591a253a551f04e
ARG GORESYM_ARM64_BINARY_SHA256=e6ca60e32a82d8d75cee5b85dace4d720e7399cb1d50b4186899b08e8553f5d0
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS="-trimpath -mod=readonly -buildvcs=false"
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --quiet --depth 1 --branch "v${GORESYM_VERSION}" https://github.com/mandiant/GoReSym.git . && \
    commit="$(git rev-parse HEAD)" && \
    if [ "${commit}" != "${GORESYM_COMMIT}" ]; then \
        echo "goresym: v${GORESYM_VERSION} is commit ${commit}, expected ${GORESYM_COMMIT}" >&2; exit 1; \
    fi && \
    GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=v${GORESYM_VERSION}" -o /out/GoReSym . && \
    echo "${GORESYM_ARM64_BINARY_SHA256}  /out/GoReSym" | sha256sum -c - && \
    chmod 0755 /out/GoReSym

FROM goresym-${TARGETARCH} AS goresym

FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
COPY --from=goresym /out/GoReSym /usr/local/bin/GoReSym

WORKDIR /app
COPY cli-sidecar/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cli-sidecar/cli_sidecar.py goresym-mcp/server.py ./

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8092 \
    MALSPARK_SAMPLE_ROOTS=/data/samples
USER 65534:65534
EXPOSE 8092
CMD ["python3", "server.py"]
