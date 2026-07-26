#!/usr/bin/env bash
# Run a command with Snap-injected environment variables removed.
#
# Playwright's WebKit build dies with "WebKit encountered an internal error" on
# every page load when it is launched from inside a Snap-confined terminal —
# VS Code's snap, for example. The crash is a glibc mismatch, not a WebKit bug
# and not a test bug:
#
#   WPENetworkProcess: symbol lookup error:
#   /snap/core20/current/lib/x86_64-linux-gnu/libpthread.so.0:
#   undefined symbol: __libc_pthread_init, version GLIBC_PRIVATE
#
# LD_LIBRARY_PATH is empty, so the snap's libraries arrive indirectly:
# GIO_MODULE_DIR, GDK_PIXBUF_MODULEDIR, GTK_PATH and friends point into
# /snap/code/…, whose modules were built against core20's glibc and pull its
# loader in behind them. Chromium and Firefox tolerate the mix; WebKit does not.
#
# Stripping every variable whose value mentions /snap/ (plus SNAP_*), and
# filtering snap entries out of the path-lists rather than dropping those
# wholesale, is enough: WebKit goes from 0/14 to 14/14.
#
# Off a snap there is nothing to strip and this exec's straight through, so CI
# and local runs go through exactly the same entry point.
#
# Usage: scripts/e2e-clean-env.sh npx playwright test
set -euo pipefail

# Drop the components of a colon-separated list that point into a snap.
strip_snap_path() {
  local out="" part
  local IFS=:
  for part in $1; do
    case "$part" in
      "" | */snap/*) continue ;;
    esac
    out="${out:+$out:}$part"
  done
  printf '%s' "$out"
}

# Iterate over variable *names* rather than parsing `env` output: exported
# values can contain characters that make line-based parsing drop entries
# silently, which is exactly what an earlier version of this script did — it
# left half the snap paths in place, and WebKit still crashed.
args=()
for name in $(compgen -e); do
  case "$name" in
    # Never unset these: PATH carries the toolchain (on CI, node itself lives
    # outside /usr/bin), and both are rewritten below instead.
    PATH | XDG_DATA_DIRS) continue ;;
    SNAP | SNAP_*)
      args+=(-u "$name")
      continue
      ;;
  esac
  case "${!name-}" in
    */snap/*) args+=(-u "$name") ;;
  esac
done

clean_path="$(strip_snap_path "${PATH-}")"
clean_xdg="$(strip_snap_path "${XDG_DATA_DIRS-/usr/local/share:/usr/share}")"

if [ ${#args[@]} -eq 0 ] && [ "$clean_path" = "${PATH-}" ]; then
  exec "$@"
fi

exec env "${args[@]}" \
  PATH="${clean_path:-/usr/local/bin:/usr/bin:/bin}" \
  XDG_DATA_DIRS="${clean_xdg:-/usr/local/share:/usr/share}" \
  "$@"
