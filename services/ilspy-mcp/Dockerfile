# ── ILSpy MCP sidecar ───────────────────────────────
# ILSpy's command-line decompiler, ilspycmd (MIT), on the .NET 10 runtime it
# targets, under the shared MCP plumbing (../cli-sidecar). The tool's NuGet
# package is checked against the sha512 computed from it when it was pinned,
# and its assembly is run on the runtime directly (no SDK in the image).
# Built with services/ as the context (docker/docker-compose.yml, profile
# `ilspy`). Keep ILSPYCMD_VERSION in step with ILSPYCMD_VERSION in server.py,
# which the install hint names.
#
# Nothing here runs a sample: ilspycmd reads an assembly's metadata and IL and
# never loads it into the runtime. The container runs as the ids compose gives
# it (never root), with no capability, a read-only root, no route out and the
# sample directory mounted read-only.
FROM mcr.microsoft.com/dotnet/runtime:10.0.13-noble@sha256:0cf09aaccf6a9f68900aed4c73fb28fe25bb59ec85de4dea08ba02240a8635f3
ARG ILSPYCMD_VERSION=11.1.0.9782
ARG ILSPYCMD_NUPKG_SHA512=17b0a5bbfad858fb7d7c29432f3660597234376fd1b78e2de6d3ae90e61466dd6d23c930653098f3311956022bede4e425086e645256e9127c1f34429709c842
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-venv && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/ilspycmd
RUN python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], 'ilspycmd.nupkg')" \
        "https://api.nuget.org/v3-flatcontainer/ilspycmd/${ILSPYCMD_VERSION}/ilspycmd.${ILSPYCMD_VERSION}.nupkg" && \
    echo "${ILSPYCMD_NUPKG_SHA512}  ilspycmd.nupkg" | sha512sum -c - && \
    python3 -c "import pathlib, zipfile; z = zipfile.ZipFile('ilspycmd.nupkg'); prefix = 'tools/net10.0/any/'; [pathlib.Path(n[len(prefix):]).parent.mkdir(parents=True, exist_ok=True) or pathlib.Path(n[len(prefix):]).write_bytes(z.read(n)) for n in z.namelist() if n.startswith(prefix) and not n.endswith('/')]" && \
    rm ilspycmd.nupkg && \
    test -f ilspycmd.dll

WORKDIR /app
COPY cli-sidecar/requirements.txt ./
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cli-sidecar/cli_sidecar.py ilspy-mcp/server.py ./

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ILSPYCMD_DLL=/opt/ilspycmd/ilspycmd.dll \
    MCP_BIND_ADDRESS=0.0.0.0 \
    MCP_PORT=8091 \
    MALJAN_SAMPLE_ROOTS=/data/samples
USER 65534:65534
EXPOSE 8091
CMD ["python3", "server.py"]
