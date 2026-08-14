#!/usr/bin/env bash
# Install the buzzr binary into $HERDR_PLUGIN_ROOT/bin.
#
# Runs as the manifest [[build]] step of `herdr plugin install` (GitHub
# installs only; `herdr plugin link` skips it). A local release build wins
# when present; otherwise the matching prebuilt
# GitHub Release asset is downloaded and checksum-verified.
set -euo pipefail

ROOT="${HERDR_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
BIN_DIR="$ROOT/bin"
TARGET_BIN="$BIN_DIR/buzzr-bin"
DEV_BUILD="$ROOT/target/release/buzzr"

mkdir -p "$BIN_DIR"

# A local release build (maintainer machine) wins over a download.
if [ -x "$DEV_BUILD" ]; then
    cp "$DEV_BUILD" "$TARGET_BIN"
    chmod +x "$TARGET_BIN"
    echo "buzzr: installed local release build to $TARGET_BIN"
    exit 0
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/herdr-plugin.toml" | head -n 1)
if [ -z "$version" ]; then
    echo "buzzr: cannot read version from herdr-plugin.toml" >&2
    exit 1
fi

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) echo "buzzr: unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64) arch=aarch64 ;;
    *) echo "buzzr: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="buzzr-v${version}-${os}-${arch}"
base="https://github.com/candypoets/buzzr/releases/download/v${version}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "buzzr: downloading $asset"
curl -fSL --retry 3 -o "$tmp/$asset" "$base/$asset"
# Releases always publish a checksum asset: fail closed on any mismatch.
curl -fsSL --retry 3 -o "$tmp/$asset.sha256" "$base/$asset.sha256"
(cd "$tmp" && {
    sha256sum --check "$asset.sha256" 2>/dev/null || shasum -a 256 --check "$asset.sha256"
})
mv "$tmp/$asset" "$TARGET_BIN"
chmod +x "$TARGET_BIN"
echo "buzzr: installed $asset to $TARGET_BIN"
