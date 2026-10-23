# ── oletools MCP sidecar ────────────────────────────
# oletools (BSD-2-Clause) and the shared MCP plumbing (../cli-sidecar), every
# Python package pinned by hash in requirements.txt (oletools 0.60.2 and what
# it needs, the MCP SDK at the versions ../cli-sidecar pins). Built with
# services/ as the context (docker/docker-compose.yml, profile `oletools`).
# Keep oletools in requirements.txt in step with OLETOOLS_VERSION in
# server.py, which the install hint names.
#
# Nothing here runs a sample or a macro: oletools parses the document it is
# given, and the XLM emulator olevba would use is not installed (and is
# switched off in ole_report.py besides). The container runs as the ids
# compose gives it (never root), with no capability, a read-only root, no
# route out and the sample directory mounted read-only.
FROM python:3.13-slim-trixie@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39

WORKDIR /app
COPY oletools-mcp/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.txt
COPY cli-sidecar/cli_sidecar.py oletools-mcp/server.py oletools-mcp/ole_report.py ./

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8094 \
    MALJAN_SAMPLE_ROOTS=/data/samples
USER 65534:65534
EXPOSE 8094
CMD ["python3", "server.py"]
