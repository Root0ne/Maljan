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
# A pinned tag that does not build or start as released carries a patch,
# scripts/dev/patches/<name>-<ref>.patch, applied after the checkout. A tree that
# already carries it is left as it is; one where it neither applies nor is in
# place stops the script, since the image built from it would not be the one
# the pin describes.
#
#   scripts/dev/fetch_external.sh               every tree, the Sigma rules and capa's data
#   scripts/dev/fetch_external.sh ghidra-mcp    only the named trees
#
# MALSPARK_EXTERNAL_DIR puts the trees somewhere other than external/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXTERNAL="${MALSPARK_EXTERNAL_DIR:-$REPO_ROOT/external}"
PATCHES="$REPO_ROOT/scripts/dev/patches"

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

# A name that is no target is a typo, and fetching nothing for it would pass for success.
known=" ${targets[*]%%|*} "
for wanted in "$@"; do
  if [[ "$known" != *" $wanted "* ]]; then
    echo "  FAIL     no target named $wanted; the targets are:$known" >&2
    exit 2
  fi
done

mkdir -p "$EXTERNAL"

for spec in "${targets[@]}"; do
  IFS='|' read -r name url ref <<<"$spec"
  dest="$EXTERNAL/$name"
  [[ $# -eq 0 || " $* " == *" $name "* ]] || continue

  if [[ -d "$dest/.git" ]]; then
    have=$(git -C "$dest" rev-parse --short HEAD)
    # The pin is an exact ref: a tree merely ahead of it was not built or
    # measured against it, so only HEAD == ref counts as in place.
    want=$(git -C "$dest" rev-parse --verify --quiet "${ref}^{commit}" 2>/dev/null || true)
    if [[ -n "$want" && "$(git -C "$dest" rev-parse HEAD)" == "$want" ]] \
       || [[ "$have" == "${ref:0:${#have}}" ]]; then
      echo "  ok       $name at $have"
    else
      echo "  checkout $name -> $ref"
      # The patches this script applied for the earlier pin come off first, so
      # they do not stand in the checkout's way; only one that comes off
      # cleanly is taken off, and nothing else in the tree is touched.
      for applied in "$PATCHES/$name"-*.patch; do
        [[ -f "$applied" ]] || continue
        if git -C "$dest" apply --ignore-whitespace --reverse --check "$applied" 2>/dev/null; then
          git -C "$dest" apply --ignore-whitespace --reverse "$applied"
          # The lines it puts back carry the patch's line endings; a file that
          # then differs from the checkout in those alone is the checkout's again.
          while IFS=$'\t' read -r _ _ file; do
            if git -C "$dest" diff --quiet --ignore-cr-at-eol -- "$file"; then
              git -C "$dest" checkout --quiet -- "$file"
            fi
          done < <(git -C "$dest" apply --numstat "$applied")
          echo "  unpatch  $name ${applied##*/}"
        fi
      done
      git -C "$dest" fetch --quiet --tags origin
      git -C "$dest" checkout --quiet "$ref" || {
        echo "  FAIL     $name: cannot check out $ref; local changes in $dest are in the way" \
          "(see git -C $dest status), or the ref is not there" >&2
        exit 1
      }
    fi
  elif [[ -e "$dest" ]]; then
    echo "  SKIP     $name exists and is not a git checkout: $dest" >&2
    continue
  else
    echo "  clone    $name $ref"
    # No default-branch checkout: its .gitattributes line-ending rules can make the
    # pinned ref's files look locally modified and block the checkout below.
    git clone --quiet --no-checkout "$url" "$dest"
    git -C "$dest" checkout --quiet "$ref"
  fi

  # The tag's own files differ in line endings by checkout (CRLF as released,
  # LF once an editor has touched them), so whitespace is not compared.
  patch="$PATCHES/$name-$ref.patch"
  if [[ -f "$patch" ]]; then
    if git -C "$dest" apply --ignore-whitespace --check "$patch" 2>/dev/null; then
      git -C "$dest" apply --ignore-whitespace "$patch"
      echo "  patch    $name ${patch##*/}"
    elif git -C "$dest" apply --ignore-whitespace --reverse --check "$patch" 2>/dev/null; then
      echo "  ok       $name carries ${patch##*/}"
    else
      echo "  FAIL     $name: ${patch##*/} neither applies to $dest nor is in place" >&2
      git -C "$dest" apply --ignore-whitespace --check "$patch" || true
      exit 1
    fi
  fi
done

# Named trees only: the rule corpora below are fetched by a run without names.
(( $# == 0 )) || exit 0


if [[ -d "$SIGMA_DEST/.git" ]]; then
  # Exact pin, as above: a tree ahead of (or behind) the ref is not the corpus measured.
  want=$(git -C "$SIGMA_DEST" rev-parse --verify --quiet "${SIGMA_REF}^{commit}" 2>/dev/null || true)
  if [[ -n "$want" && "$(git -C "$SIGMA_DEST" rev-parse HEAD)" == "$want" ]]; then
    echo "  ok       sigma rules at $(git -C "$SIGMA_DEST" rev-parse --short HEAD)"
  else
    echo "  checkout sigma rules -> $SIGMA_REF"
    git -C "$SIGMA_DEST" fetch --quiet --depth 1 origin "refs/tags/$SIGMA_REF:refs/tags/$SIGMA_REF" \
      || git -C "$SIGMA_DEST" fetch --quiet --tags origin \
      || { echo "  FAIL     cannot fetch sigma rules $SIGMA_REF" >&2; exit 1; }
    git -C "$SIGMA_DEST" checkout --quiet "$SIGMA_REF" \
      || { echo "  FAIL     sigma rules $SIGMA_REF not available" >&2; exit 1; }
  fi
elif [[ -e "$SIGMA_DEST" ]]; then
  echo "  SKIP     $SIGMA_DEST exists and is not a git checkout" >&2
else
  echo "  clone    sigma rules $SIGMA_REF"
  git clone --quiet --depth 1 --branch "$SIGMA_REF" "$SIGMA_URL" "$SIGMA_DEST" \
    || { echo "  FAIL     cannot clone sigma rules at $SIGMA_REF" >&2; exit 1; }
fi

# capa's rules and its library signatures, at the capa version uv.lock pins,
# where the settings point by default and the compose stack mounts them.
bash "$REPO_ROOT/scripts/dev/fetch_capa_data.sh"

echo
echo "external/, data/sigma_rules, data/capa-rules and data/capa-signatures are ignored by git."
echo "Re-run this after a fresh clone."
