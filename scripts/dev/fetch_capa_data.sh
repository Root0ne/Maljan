#!/usr/bin/env bash
# Fetch capa's rules and its library-identification signatures into data/.
#
# They are for the flare-capa version uv.lock pins; the flare-capa wheel
# carries neither. They land where static.capa.rules_dir and
# static.capa.signatures_dir point by default, which is also what the compose
# stack mounts over the image's own copies. The rules are capa-rules' tag of
# that version, without its CI folder (.github), so a rule count equals what
# capa loads. The signatures are the sigs/ directory of flare-capa's own sdist
# on PyPI. Each archive is checked against the sha256 recorded when it was
# pinned (the sdist's is uv.lock's own), and each directory keeps its licence
# file and a PINNED.txt line naming what it holds.
#
# Keep the three values in step with uv.lock and docker/Dockerfile.backend; a
# test holds them together. A directory that is already there is never
# touched: it is said to be the pinned version or not, and left as it is.
#
#   scripts/dev/fetch_capa_data.sh   (make setup and make external run it)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CAPA_VERSION="9.4.0"
CAPA_RULES_SHA256="273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669"
CAPA_SDIST_SHA256="c4f421abac566e23657241e4ddc66119beb0caf5f082ee42d68b7c879ebb7fc6"
CAPA_RULES_URL="https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.tar.gz"
CAPA_SDIST_URL="https://files.pythonhosted.org/packages/source/f/flare-capa/flare_capa-${CAPA_VERSION}.tar.gz"
CAPA_RULES_DEST="$REPO_ROOT/data/capa-rules"
CAPA_SIGNATURES_DEST="$REPO_ROOT/data/capa-signatures"
# What each directory's PINNED.txt says when this script fetched it.
CAPA_RULES_PIN="capa-rules v${CAPA_VERSION} sha256:${CAPA_RULES_SHA256}"
CAPA_SIGNATURES_PIN="flare-capa ${CAPA_VERSION} sigs sha256:${CAPA_SDIST_SHA256}"

# Unpacked beside its destination and renamed into place, so a failed fetch or
# a digest that does not match leaves no directory a later run would skip.
capa_work=""
trap 'if [[ -n "$capa_work" ]]; then rm -rf "$capa_work"; fi' EXIT

work_dir() {
  if [[ -z "$capa_work" ]]; then
    mkdir -p "$REPO_ROOT/data"
    capa_work="$(mktemp -d "$REPO_ROOT/data/.capa-fetch.XXXXXX")"
  fi
}

fetch_checked() {  # url sha256 file
  curl --fail --location --silent --show-error --output "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}

# Whether a directory already there holds the pinned version: it says so in
# its PINNED.txt, or, for the rules, it is a checkout of the pinned tag.
is_pinned() {  # directory pin-line [tag]
  if [[ -f "$1/PINNED.txt" && "$(head -n 1 "$1/PINNED.txt")" == "$2" ]]; then
    return 0
  fi
  if [[ -n "${3:-}" && -e "$1/.git" ]] && command -v git >/dev/null; then
    local at tagged
    at="$(git -C "$1" rev-parse -q --verify HEAD 2>/dev/null || true)"
    tagged="$(git -C "$1" rev-parse -q --verify "refs/tags/$3^{commit}" 2>/dev/null || true)"
    [[ -n "$at" && "$at" == "$tagged" ]] && return 0
  fi
  return 1
}

say_present() {  # directory pin-line label [tag]
  if is_pinned "$1" "$2" "${4:-}"; then
    echo "  ok       $3 v$CAPA_VERSION"
  else
    echo "  present  $3 in data/, but not the pinned v$CAPA_VERSION: left as they are"
  fi
}

if [[ -e "$CAPA_RULES_DEST" ]]; then
  say_present "$CAPA_RULES_DEST" "$CAPA_RULES_PIN" "capa rules" "v$CAPA_VERSION"
else
  echo "  fetch    capa rules v$CAPA_VERSION"
  work_dir
  fetch_checked "$CAPA_RULES_URL" "$CAPA_RULES_SHA256" "$capa_work/rules.tar.gz"
  mkdir "$capa_work/rules"
  tar -xzf "$capa_work/rules.tar.gz" -C "$capa_work/rules" --strip-components=1 --exclude=.github
  echo "$CAPA_RULES_PIN" >"$capa_work/rules/PINNED.txt"
  mv "$capa_work/rules" "$CAPA_RULES_DEST"
fi

if [[ -e "$CAPA_SIGNATURES_DEST" ]]; then
  say_present "$CAPA_SIGNATURES_DEST" "$CAPA_SIGNATURES_PIN" "capa signatures"
else
  echo "  fetch    capa signatures from flare-capa $CAPA_VERSION"
  work_dir
  fetch_checked "$CAPA_SDIST_URL" "$CAPA_SDIST_SHA256" "$capa_work/sdist.tar.gz"
  mkdir "$capa_work/signatures"
  tar -xzf "$capa_work/sdist.tar.gz" -C "$capa_work/signatures" --strip-components=2 \
    "flare_capa-${CAPA_VERSION}/sigs"
  tar -xzf "$capa_work/sdist.tar.gz" -C "$capa_work/signatures" --strip-components=1 \
    "flare_capa-${CAPA_VERSION}/LICENSE.txt"
  echo "$CAPA_SIGNATURES_PIN" >"$capa_work/signatures/PINNED.txt"
  mv "$capa_work/signatures" "$CAPA_SIGNATURES_DEST"
fi
