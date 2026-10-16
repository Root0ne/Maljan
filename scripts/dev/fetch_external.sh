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
#   scripts/dev/fetch_external.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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

# capa's rules and its library-identification signatures, for the flare-capa
# version uv.lock pins; the flare-capa wheel carries neither. They land where
# static.capa.rules_dir and static.capa.signatures_dir point by default, which
# is also what the compose stack mounts over the image's own copies. The rules
# are capa-rules' tag of that version, the signatures the sigs/ directory of
# flare-capa's own sdist on PyPI. Each archive is checked against the sha256
# recorded when it was pinned (the sdist's is uv.lock's own), and each
# directory keeps its licence file. Keep the three values in step with uv.lock
# and docker/Dockerfile.backend; a test holds them together. A directory that
# is already there is left as it is.
CAPA_VERSION="9.4.0"
CAPA_RULES_SHA256="273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669"
CAPA_SDIST_SHA256="c4f421abac566e23657241e4ddc66119beb0caf5f082ee42d68b7c879ebb7fc6"
CAPA_RULES_URL="https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.tar.gz"
CAPA_SDIST_URL="https://files.pythonhosted.org/packages/source/f/flare-capa/flare_capa-${CAPA_VERSION}.tar.gz"
CAPA_RULES_DEST="$REPO_ROOT/data/capa-rules"
CAPA_SIGNATURES_DEST="$REPO_ROOT/data/capa-signatures"

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

# Unpacked beside its destination and renamed into place, so a failed fetch or
# a digest that does not match leaves no directory a later run would skip.
capa_work=""
trap 'if [[ -n "$capa_work" ]]; then rm -rf "$capa_work"; fi' EXIT

fetch_checked() {  # url sha256 file
  curl --fail --location --silent --show-error --output "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}

if [[ -e "$CAPA_RULES_DEST" && -e "$CAPA_SIGNATURES_DEST" ]]; then
  echo "  ok       capa rules and signatures are in data/, left as they are"
else
  mkdir -p "$REPO_ROOT/data"
  capa_work="$(mktemp -d "$REPO_ROOT/data/.capa-fetch.XXXXXX")"
  if [[ -e "$CAPA_RULES_DEST" ]]; then
    echo "  ok       capa rules are in data/, left as they are"
  else
    echo "  fetch    capa rules v$CAPA_VERSION"
    fetch_checked "$CAPA_RULES_URL" "$CAPA_RULES_SHA256" "$capa_work/rules.tar.gz"
    mkdir "$capa_work/rules"
    tar -xzf "$capa_work/rules.tar.gz" -C "$capa_work/rules" --strip-components=1
    mv "$capa_work/rules" "$CAPA_RULES_DEST"
  fi
  if [[ -e "$CAPA_SIGNATURES_DEST" ]]; then
    echo "  ok       capa signatures are in data/, left as they are"
  else
    echo "  fetch    capa signatures from flare-capa $CAPA_VERSION"
    fetch_checked "$CAPA_SDIST_URL" "$CAPA_SDIST_SHA256" "$capa_work/sdist.tar.gz"
    mkdir "$capa_work/signatures"
    tar -xzf "$capa_work/sdist.tar.gz" -C "$capa_work/signatures" --strip-components=2 \
      "flare_capa-${CAPA_VERSION}/sigs"
    tar -xzf "$capa_work/sdist.tar.gz" -C "$capa_work/signatures" --strip-components=1 \
      "flare_capa-${CAPA_VERSION}/LICENSE.txt"
    mv "$capa_work/signatures" "$CAPA_SIGNATURES_DEST"
  fi
fi

echo
echo "external/, data/sigma_rules, data/capa-rules and data/capa-signatures are ignored by git."
echo "Re-run this after a fresh clone."
