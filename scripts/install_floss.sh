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
# Where it goes: $HOME/.local/share/malspark/tools/floss-<version>/floss,
# which is the first place the tool looks. Set MALSPARK_FLOSS_PATH in the analysis
# server's env to use a build somewhere else.
#
# The build is x86-64 Linux. On an arm64 Linux host it runs only through
# x86-64 emulation registered with the kernel (binfmt_misc: QEMU user mode,
# or Rosetta in a Linux VM on a Mac), so there it is installed only when such
# a handler is registered, and the analysis server's version probe still says
# whether it runs. Without one the script stops and says what to do instead:
# the backend image carries FLOSS for arm64 natively. Nothing downloaded is run
# here, on any host.
#
#   scripts/install_floss.sh

set -euo pipefail

# Keep in step with src/malspark/tools/emulated_strings.py and docker/Dockerfile.backend.
VERSION="3.1.1"
ZIP_SHA256="40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666"
BINARY_SHA256="d71b9ea4fe3b2de974dc1ae3c5d0f67569921bc118dcb02ed72e905a662411cb"
URL="https://github.com/mandiant/flare-floss/releases/download/v${VERSION}/floss-v${VERSION}-linux.zip"

# The x86-64 handlers binfmt_misc may hold, by the names their installers give.
x86_64_emulation() {
  local entry
  for entry in /proc/sys/fs/binfmt_misc/*; do
    case "$(basename "$entry")" in
      qemu-x86_64 | x86_64 | rosetta | Rosetta)
        if head -n 1 "$entry" 2>/dev/null | grep -qx enabled; then
          return 0
        fi
        ;;
    esac
  done
  return 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FLOSS's pinned build is a Linux executable; this host runs $(uname -s)." >&2
  echo "Run the analysis server in the backend image, which carries FLOSS, instead." >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64 | amd64) ;;
  aarch64 | arm64)
    if ! x86_64_emulation; then
      cat >&2 <<'EOF'
FLOSS's pinned standalone build is x86-64 only, and this arm64 host has no
x86-64 emulation registered with the kernel (binfmt_misc), so it would not run.
Either run the analysis server in the backend image, which installs FLOSS
natively for arm64, or register x86-64 user-mode emulation (QEMU, or Rosetta in
a Linux VM on a Mac) and run this script again.
EOF
      exit 1
    fi
    echo "This arm64 host runs x86-64 programs through emulation; installing the x86-64 build."
    ;;
  *)
    echo "FLOSS publishes no build for $(uname -m); run the analysis server in the backend image." >&2
    exit 1
    ;;
esac

DEST_DIR="$HOME/.local/share/malspark/tools/floss-${VERSION}"
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
