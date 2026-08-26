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
# CAPE is not fetched by default. It runs on a separate machine with its own
# Windows guest and is reached over the network; nothing in this repository
# installs it, and docker/cape/ is provided for the case where someone wants to
# stand one up themselves. Pass --with-cape to clone it too.
#
#   scripts/fetch_external.sh              ghidra-mcp and ik_llama.cpp
#   scripts/fetch_external.sh --with-cape  those two and CAPEv2

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTERNAL="$REPO_ROOT/external"

# name|url|ref  — the ref is what the project was built and measured against.
CORE=(
  "ghidra-mcp|https://github.com/bethington/ghidra-mcp.git|v5.6.0"
  "ik_llama.cpp|https://github.com/ikawrakow/ik_llama.cpp|eb570eb9"
)
CAPE="CAPEv2|https://github.com/kevoreilly/CAPEv2|976b36905"

targets=("${CORE[@]}")
[[ "${1:-}" == "--with-cape" ]] && targets+=("$CAPE")

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
