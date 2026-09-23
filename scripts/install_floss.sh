#!/usr/bin/env bash
# Install the pinned FLOSS build the analysis server's ``floss`` tool runs.
#
# FLOSS is FLARE's emulating string decoder (Apache-2.0). The tool runs its
# standalone Linux build as a child process, outside this project's Python
# environment, so none of its own dependencies reach the lockfile. This script
# downloads the pinned release asset, checks it against the sha256 recorded when
# it was pinned, unpacks the one executable and checks that too. Nothing is
# installed system-wide.
#
# Where it goes: ${XDG_DATA_HOME:-$HOME/.local/share}/maljan/tools/floss-<version>/floss,
# which is the first place the tool looks. Set MALJAN_FLOSS_PATH in the analysis
# server's env to use a build somewhere else.
#
#   scripts/install_floss.sh

set -euo pipefail

# Keep in step with src/maljan/tools/emulated_strings.py and docker/Dockerfile.backend.
VERSION="3.1.1"
ZIP_SHA256="40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666"
BINARY_SHA256="d71b9ea4fe3b2de974dc1ae3c5d0f67569921bc118dcb02ed72e905a662411cb"
URL="https://github.com/mandiant/flare-floss/releases/download/v${VERSION}/floss-v${VERSION}-linux.zip"

DEST_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/maljan/tools/floss-${VERSION}"
DEST="$DEST_DIR/floss"

if [[ -x "$DEST" ]] && echo "$BINARY_SHA256  $DEST" | sha256sum -c --status; then
  echo "FLOSS $VERSION is already installed at $DEST"
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Downloading FLOSS $VERSION"
curl --fail --location --silent --show-error --output "$WORK/floss.zip" "$URL"
echo "$ZIP_SHA256  $WORK/floss.zip" | sha256sum -c -

python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("floss", sys.argv[2])' \
  "$WORK/floss.zip" "$WORK"
echo "$BINARY_SHA256  $WORK/floss" | sha256sum -c -

mkdir -p "$DEST_DIR"
chmod 0700 "$DEST_DIR"
install -m 0755 "$WORK/floss" "$DEST"
echo "FLOSS $VERSION installed at $DEST"
