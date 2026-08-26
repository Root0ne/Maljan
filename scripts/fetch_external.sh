#!/usr/bin/env bash
# Fetch the third-party trees this project builds against.
#
# external/ is not in version control and is not ours to redistribute: each of
# these is someone else's project under its own licence. What the repository
# carries instead is the exact ref each was used at, so a clone can reconstruct
# the tree rather than receive a copy of it.
#
# The ik_llama.cpp commit is the one the paper pins as the inference engine, so
# fetching it here is what makes that pin reproducible rather than merely
# recorded.
#
# CAPE is deliberately absent. It is somebody else's platform, wants a Linux
# host of its own with KVM and registered Windows guest images, and is a
# deployment rather than a dependency. This project talks to one over its REST
# API; it does not install, build or package it.
#
#   scripts/fetch_external.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTERNAL="$REPO_ROOT/external"

# name|url|ref  — the ref is what the project was built and measured against.
targets=(
  "ghidra-mcp|https://github.com/bethington/ghidra-mcp.git|v5.6.0"
  "ik_llama.cpp|https://github.com/ikawrakow/ik_llama.cpp|eb570eb9"
)

mkdir -p "$EXTERNAL"

for spec in "${targets[@]}"; do
  IFS='|' read -r name url ref <<<"$spec"
  dest="$EXTERNAL/$name"

  if [[ -d "$dest/.git" ]]; then
    have=$(git -C "$dest" rev-parse --short HEAD)
    if git -C "$dest" merge-base --is-ancestor "$ref" HEAD 2>/dev/null \
       || [[ "$have" == "${ref:0:${#have}}" ]]; then
      echo "  ok       $name at $have"
      continue
    fi
    echo "  checkout $name -> $ref"
    git -C "$dest" fetch --quiet --tags origin
    git -C "$dest" checkout --quiet "$ref"
    continue
  fi

  if [[ -e "$dest" ]]; then
    echo "  SKIP     $name exists and is not a git checkout: $dest" >&2
    continue
  fi

  echo "  clone    $name $ref"
  git clone --quiet "$url" "$dest"
  git -C "$dest" checkout --quiet "$ref"
done

echo
echo "external/ is ignored by git. Re-run this after a fresh clone."
