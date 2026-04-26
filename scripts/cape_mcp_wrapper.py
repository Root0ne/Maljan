#!/usr/bin/env python3
"""Wrapper that launches CAPEv2's MCP server with stdout isolation.

CAPEv2's import chain prints stray messages to stdout during module
initialization (e.g. "[Errno 19] No such device").  Since MCP uses
stdin/stdout for its JSON-RPC protocol, these prints corrupt the
communication channel.

This wrapper:
  1. Pre-imports fastmcp/httpx so they are cached in sys.modules
  2. Redirects stdout -> stderr during CAPEv2's noisy init phase
  3. Restores stdout before FastMCP takes the stdio channel

Key issue solved:  CAPEv2 ships an `mcp/` directory that shadows the
real `mcp` PyPI package when CAPEv2's root is on sys.path.  By importing
the real `mcp` package BEFORE adding CAPEv2 to sys.path, we avoid the
namespace collision entirely.

Usage (in .env):
  MCP__CAPE__COMMAND=wsl.exe
  MCP__CAPE__ARGS=["-d","Ubuntu","-u","root","-e",
                   "/path/to/.venv-wsl/bin/python",
                   "/path/to/Maljan/scripts/cape_mcp_wrapper.py",
                   "--cape-root", "/path/to/CAPEv2"]
"""

import os
import sys


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="CAPEv2 MCP Server Wrapper (stdout-safe)",
        add_help=False,
    )
    parser.add_argument(
        "--cape-root",
        default=os.environ.get("CAPE_ROOT", ""),
        help="Path to the CAPEv2 installation directory.",
    )
    wrapper_args, server_args = parser.parse_known_args()

    cape_root = wrapper_args.cape_root
    if not cape_root:
        print("ERROR: --cape-root or CAPE_ROOT env var is required.", file=sys.stderr)
        sys.exit(1)

    cape_mcp_server = os.path.join(cape_root, "mcp", "server.py")
    if not os.path.isfile(cape_mcp_server):
        print(
            f"ERROR: CAPEv2 MCP server not found at {cape_mcp_server}",
            file=sys.stderr,
        )
        sys.exit(1)

    # ----------------------------------------------------------------
    # Phase 1: Pre-import packages that conflict with CAPEv2's mcp/ dir
    # ----------------------------------------------------------------
    # CAPEv2 has an `mcp/` directory with __init__.py which shadows the
    # real `mcp` PyPI package.  Import the real one first so it's cached
    # in sys.modules before CAPE_ROOT lands on sys.path.
    import httpx  # noqa: F401
    import mcp  # noqa: F401 — the real MCP SDK
    from fastmcp import FastMCP  # noqa: F401

    # ----------------------------------------------------------------
    # Phase 2: Stdout isolation during CAPEv2 import
    # ----------------------------------------------------------------
    real_stdout_fd = os.dup(1)
    os.dup2(2, 1)  # stdout -> stderr

    # Now it's safe to add CAPEv2 to path (mcp is already cached)
    sys.path.insert(0, cape_root)
    os.chdir(cape_root)

    import importlib.util

    spec = importlib.util.spec_from_file_location("cape_mcp_server", cape_mcp_server)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cape_mcp_server"] = mod

    try:
        spec.loader.exec_module(mod)
    except SystemExit as e:
        os.dup2(real_stdout_fd, 1)
        print(
            f"CAPEv2 MCP server failed to initialize: {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    # ----------------------------------------------------------------
    # Phase 3: Restore stdout, launch MCP
    # ----------------------------------------------------------------
    os.dup2(real_stdout_fd, 1)
    os.close(real_stdout_fd)
    sys.stdout = os.fdopen(1, "w", buffering=1)

    cape_mcp = mod.mcp

    inner_parser = argparse.ArgumentParser(description="CAPE MCP Server")
    inner_parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http", "http"],
        default=os.environ.get("CAPE_MCP_TRANSPORT", "stdio"),
    )
    inner_parser.add_argument(
        "--host",
        default=os.environ.get("CAPE_MCP_HOST", "127.0.0.1"),
    )
    inner_parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CAPE_MCP_PORT", "9004")),
    )
    args = inner_parser.parse_args(server_args)

    if args.transport in ("sse", "streamable-http", "http"):
        print(
            f"Starting {args.transport} server on {args.host}:{args.port}",
            file=sys.stderr,
        )
        cape_mcp.run(transport=args.transport, host=args.host, port=args.port)
    else:
        cape_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
