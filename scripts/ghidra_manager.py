#!/usr/bin/env python3
"""Ghidra MCP lifecycle manager.

Automates version sync, smart rebuilds, and file-watching for the
GhidraMCP headless Docker image.

Usage:
    python scripts/ghidra_manager.py sync      # Sync pom.xml → Dockerfile
    python scripts/ghidra_manager.py build     # Smart rebuild (detects changes)
    python scripts/ghidra_manager.py watch     # Auto-rebuild on file changes
    python scripts/ghidra_manager.py status    # Show current versions & drift
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import NamedTuple

# ── Paths (relative to repo root) ──────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
POM_XML = REPO_ROOT / "external" / "ghidra-mcp" / "pom.xml"
DOCKERFILE = REPO_ROOT / "external" / "ghidra-mcp" / "docker" / "Dockerfile"
GHIDRA_SRC = REPO_ROOT / "external" / "ghidra-mcp" / "src"
COMPOSE_DIR = REPO_ROOT / "docker"
STATE_FILE = REPO_ROOT / ".ghidra_mcp_state.json"

# GitHub API for Ghidra releases
GHIDRA_RELEASES_API = (
    "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases"
)


class Versions(NamedTuple):
    pom_version: str
    pom_date: str
    docker_version: str
    docker_date: str


def _run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> str:
    """Run a shell command and return stdout."""
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=cwd or REPO_ROOT, check=check
    )
    return result.stdout.strip()


def parse_pom() -> tuple[str, str]:
    """Extract ghidra.version and ghidra.date from pom.xml."""
    text = POM_XML.read_text(encoding="utf-8")
    version_match = re.search(r"<ghidra\.version>([^<]+)</ghidra\.version>", text)
    date_match = re.search(r"<ghidra\.date>([^<]+)</ghidra\.date>", text)
    if not version_match:
        sys.exit(f"ERROR: <ghidra.version> not found in {POM_XML}")
    version = version_match.group(1)
    date = date_match.group(1) if date_match else ""
    return version, date


def parse_dockerfile() -> tuple[str, str]:
    """Extract GHIDRA_VERSION and GHIDRA_DATE from Dockerfile."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    version_match = re.search(r'ARG GHIDRA_VERSION=([\d.]+)', text)
    date_match = re.search(r'ARG GHIDRA_DATE=(\d{8})', text)
    if not version_match:
        sys.exit(f"ERROR: GHIDRA_VERSION not found in {DOCKERFILE}")
    version = version_match.group(1)
    date = date_match.group(1) if date_match else ""
    return version, date


def fetch_ghidra_release_date(version: str) -> str | None:
    """Query GitHub API for the release date of a given Ghidra version.

    Returns YYYYMMDD string or None if not found.
    """
    import urllib.request

    try:
        req = urllib.request.Request(
            GHIDRA_RELEASES_API,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "maljan-ghidra-manager"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            releases = json.loads(resp.read().decode())
    except Exception as exc:
        print(f"WARNING: Could not fetch GitHub releases: {exc}")
        return None

    tag_prefix = f"Ghidra_{version}_build"
    for rel in releases:
        tag = rel.get("tag_name", "")
        if tag.startswith(tag_prefix):
            published = rel.get("published_at", "")
            # published_at format: 2026-03-03T... → 20260303
            if published:
                return published[:10].replace("-", "")
    return None


def sync_dockerfile(dry_run: bool = False) -> bool:
    """Update Dockerfile ARGs to match pom.xml.

    Returns True if changes were made (or would be made in dry-run).
    """
    pom_version, pom_date = parse_pom()
    docker_version, docker_date = parse_dockerfile()

    if pom_version == docker_version and (not pom_date or pom_date == docker_date):
        print(f"✓ Versions already in sync: {pom_version}")
        return False

    # Auto-detect date from GitHub if missing in pom.xml
    if not pom_date:
        print(f"🔍 Fetching release date for Ghidra {pom_version} from GitHub...")
        fetched = fetch_ghidra_release_date(pom_version)
        if fetched:
            pom_date = fetched
            print(f"   Found: {pom_date}")
        else:
            print("   Could not auto-detect. Using existing Dockerfile date.")
            pom_date = docker_date or ""

    print(f"📝 pom.xml:     {docker_version} → {pom_version}")
    if docker_date != pom_date:
        print(f"📝 Dockerfile date: {docker_date} → {pom_date}")

    if dry_run:
        print("(dry-run: no files modified)")
        return True

    text = DOCKERFILE.read_text(encoding="utf-8")
    text = re.sub(
        r'ARG GHIDRA_VERSION=[\d.]+', f'ARG GHIDRA_VERSION={pom_version}', text
    )
    if pom_date:
        if re.search(r'ARG GHIDRA_DATE=\d{8}', text):
            text = re.sub(r'ARG GHIDRA_DATE=\d{8}', f'ARG GHIDRA_DATE={pom_date}', text)
        else:
            # Insert after GHIDRA_VERSION line
            text = re.sub(
                r'(ARG GHIDRA_VERSION=[\d.]+\n)',
                rf'\1ARG GHIDRA_DATE={pom_date}\n',
                text,
            )
    DOCKERFILE.write_text(text, encoding="utf-8")
    print(f"✅ Updated {DOCKERFILE}")
    return True


def compute_source_hash() -> str:
    """Hash all Java source files under external/ghidra-mcp/src/."""
    hasher = hashlib.sha256()
    for path in sorted(GHIDRA_SRC.rglob("*.java")):
        hasher.update(path.read_bytes())
    return hasher.hexdigest()[:16]


def load_state() -> dict:
    """Load persisted build state."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def save_state(state: dict) -> None:
    """Persist build state."""
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def smart_rebuild(force: bool = False) -> None:
    """Rebuild Ghidra MCP image only if necessary.

    Detects:
      - Source code changes (src/**/*.java hash)
      - Dockerfile changes
      - pom.xml version drift
    """
    state = load_state()
    current_hash = compute_source_hash()
    current_docker_hash = hashlib.sha256(
        DOCKERFILE.read_bytes()
    ).hexdigest()[:16]
    pom_version, _ = parse_pom()

    last_hash = state.get("src_hash", "")
    last_docker_hash = state.get("docker_hash", "")
    last_version = state.get("pom_version", "")

    reasons: list[str] = []
    if force:
        reasons.append("--force flag")
    if current_hash != last_hash:
        reasons.append("Java source changed")
    if current_docker_hash != last_docker_hash:
        reasons.append("Dockerfile changed")
    if pom_version != last_version:
        reasons.append(f"pom.xml version drift ({last_version} → {pom_version})")

    if not reasons:
        print("✓ No changes detected in Ghidra MCP. Image is up-to-date.")
        print(f"  Source hash: {current_hash}")
        print(f"  Version:     {pom_version}")
        return

    print(f"🔄 Rebuilding Ghidra MCP ({', '.join(reasons)})...")

    # Determine if we need a full rebuild (new Ghidra version)
    needs_full_rebuild = pom_version != last_version or current_docker_hash != last_docker_hash

    build_cmd = [
        "docker", "compose", "build",
        *(["--no-cache"] if needs_full_rebuild else []),
        "ghidra-mcp",
    ]
    print(f"   $ {' '.join(build_cmd)}")
    _run(build_cmd, cwd=COMPOSE_DIR)

    # Restart only ghidra-mcp
    _run(["docker", "compose", "up", "-d", "--no-deps", "ghidra-mcp"], cwd=COMPOSE_DIR)

    # Update state
    state["src_hash"] = current_hash
    state["docker_hash"] = current_docker_hash
    state["pom_version"] = pom_version
    state["last_build"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_state(state)
    print("✅ Ghidra MCP rebuilt and restarted.")


def watch_mode(poll_interval: float = 2.0) -> None:
    """Watch source files and auto-rebuild on changes."""
    print(f"👁️  Watching {GHIDRA_SRC} for changes...")
    print("   Press Ctrl+C to stop.\n")

    last_hash = compute_source_hash()
    try:
        while True:
            time.sleep(poll_interval)
            current = compute_source_hash()
            if current != last_hash:
                print(f"📝 Change detected ({time.strftime('%H:%M:%S')})")
                smart_rebuild()
                last_hash = current
                print("\n👁️  Watching for changes...")
    except KeyboardInterrupt:
        print("\n👋 Watch mode stopped.")


def show_status() -> None:
    """Display current version alignment and build state."""
    pom_version, pom_date = parse_pom()
    docker_version, docker_date = parse_dockerfile()
    state = load_state()

    print("┌─────────────────────────────────────────┐")
    print("│      Ghidra MCP Status Report           │")
    print("├─────────────────────────────────────────┤")
    print(f"│ pom.xml version:     {pom_version:20} │")
    print(f"│ Dockerfile version:  {docker_version:20} │")
    print(f"│ pom.xml date:        {pom_date or 'N/A':20} │")
    print(f"│ Dockerfile date:     {docker_date or 'N/A':20} │")
    print("├─────────────────────────────────────────┤")

    if pom_version != docker_version:
        print("│ ⚠️  VERSION DRIFT DETECTED              │")
    else:
        print("│ ✓ Versions in sync                      │")

    print(f"│ Source hash: {state.get('src_hash', 'N/A'):24} │")
    print(f"│ Last build:  {state.get('last_build', 'N/A'):24} │")
    print("└─────────────────────────────────────────┘")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage Ghidra MCP headless Docker image lifecycle.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_sync = sub.add_parser("sync", help="Sync Dockerfile with pom.xml versions")
    p_sync.add_argument("--dry-run", action="store_true", help="Show changes without applying")

    p_build = sub.add_parser("build", help="Smart rebuild (detects what changed)")
    p_build.add_argument("--force", action="store_true", help="Force rebuild even if unchanged")

    p_watch = sub.add_parser("watch", help="Auto-rebuild on source file changes")
    p_watch.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds")

    sub.add_parser("status", help="Show version alignment and build state")

    args = parser.parse_args()

    if args.command == "sync":
        sync_dockerfile(dry_run=args.dry_run)
    elif args.command == "build":
        smart_rebuild(force=args.force)
    elif args.command == "watch":
        watch_mode(poll_interval=args.interval)
    elif args.command == "status":
        show_status()


if __name__ == "__main__":
    main()
