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
# so on arm64 the pinned tag's source (GitHub's archive of the tag, whose
# sha256 was computed when it was pinned) is compiled with the Go toolchain of
# the digest-pinned image below, never one fetched at build time, its modules
# checked against the tree's go.sum. The compiler runs on the build host's
# platform and cross-compiles, as upstream's release build does (cgo off,
# version stamped), and the binary must match the sha256 that build gave when
# it was pinned: Go builds the same bytes from the same source and toolchain on
# any host.
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
ARG GORESYM_SOURCE_SHA256=c8600ad8634aae2166f09af224ac7c257c8ee403acd42d72f6f1276e786a70e8
ARG GORESYM_ARM64_BINARY_SHA256=e6ca60e32a82d8d75cee5b85dace4d720e7399cb1d50b4186899b08e8553f5d0
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS="-trimpath -mod=readonly"
WORKDIR /src
RUN wget -q -O /tmp/goresym.tar.gz \
        "https://github.com/mandiant/GoReSym/archive/refs/tags/v${GORESYM_VERSION}.tar.gz" && \
    echo "${GORESYM_SOURCE_SHA256}  /tmp/goresym.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/goresym.tar.gz --strip-components=1 && \
    rm /tmp/goresym.tar.gz && \
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
