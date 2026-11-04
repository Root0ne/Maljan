#!/usr/bin/env bash
# Draws the checked-in brand images under public/ from the SVGs beside this
# script: the square icons from icon-tile.svg and the Open Graph card from
# og.svg. Needs rsvg-convert and python3. og.svg sets its text in JetBrains
# Mono; pass a directory holding the font's files as $1 so the card is drawn
# in it rather than in a fallback.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
public="$here/../../public"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ "${1:-}" ]; then
  cat >"$work/fonts.conf" <<EOF
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig><dir>$1</dir><include ignore_missing="yes">/etc/fonts/fonts.conf</include></fontconfig>
EOF
  export FONTCONFIG_FILE="$work/fonts.conf"
fi

rsvg-convert -w 512 -h 512 "$here/icon-tile.svg" -o "$public/icon-512.png"
rsvg-convert -w 192 -h 192 "$here/icon-tile.svg" -o "$public/icon-192.png"
rsvg-convert -w 180 -h 180 "$here/icon-tile.svg" -o "$public/apple-touch-icon.png"
for size in 16 32 48; do
  rsvg-convert -w "$size" -h "$size" "$here/icon-tile.svg" -o "$work/favicon-$size.png"
done

# favicon.ico: the three PNGs as the entries of one icon file.
python3 - "$public/favicon.ico" "$work"/favicon-{16,32,48}.png <<'EOF'
import struct
import sys

target, *sources = sys.argv[1:]
images = [open(path, "rb").read() for path in sources]
sizes = [16, 32, 48]
offset = 6 + 16 * len(images)
head = struct.pack("<HHH", 0, 1, len(images))
for size, data in zip(sizes, images):
    head += struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
with open(target, "wb") as out:
    out.write(head + b"".join(images))
EOF

rsvg-convert -w 1200 -h 630 "$here/og.svg" -o "$public/og.png"
