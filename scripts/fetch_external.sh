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

# The Sigma corpus is SigmaHQ's work, not ours, and it lands outside external/
# because the layer reads it from data/sigma_rules by default. It used to be
# committed here: 2,651 rule files by Florian Roth, Nasreddine Bencherchali,
# frack113 and the rest of SigmaHQ, carrying no licence and no attribution, in a
# repository that calls itself MIT. Their rules are under the Detection Rule
# License. Fetching beats vendoring for the same reason it does above.
SIGMA_URL="https://github.com/SigmaHQ/sigma.git"
SIGMA_REF="r2026-07-01"
SIGMA_DEST="$REPO_ROOT/data/sigma_rules"

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


if [[ -d "$SIGMA_DEST/.git" ]]; then
  echo "  ok       sigma rules at $(git -C "$SIGMA_DEST" rev-parse --short HEAD)"
elif [[ -e "$SIGMA_DEST" ]]; then
  echo "  SKIP     $SIGMA_DEST exists and is not a git checkout" >&2
else
  echo "  clone    sigma rules $SIGMA_REF"
  git clone --quiet --depth 1 --branch "$SIGMA_REF" "$SIGMA_URL" "$SIGMA_DEST" \
    || git clone --quiet --depth 1 "$SIGMA_URL" "$SIGMA_DEST"
fi

echo
echo "external/ and data/sigma_rules are ignored by git."
echo "Re-run this after a fresh clone."
