# The ClusterFuzzLite build image for the harnesses under fuzz/. The base is
# pinned by digest; uv comes from the same pinned image docker/Dockerfile.backend
# copies it from.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /usr/local/bin/uv
COPY . $SRC/malspark
WORKDIR $SRC/malspark
COPY .clusterfuzzlite/build.sh $SRC/
