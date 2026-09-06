#!/bin/sh
# Installs the lumo-cli binary published by the GitHub release workflow.
#
#   curl -fsSL https://raw.githubusercontent.com/r3dlight/lumo-cli/main/install.sh | sh
#
# Environment:
#   LUMO_INSTALL_DIR  destination directory (default: ~/.local/bin)
#   LUMO_VERSION      release tag such as v0.1.0 (default: latest)
#   LUMO_BASE_URL     directory holding the archive and SHA256SUMS (a mirror);
#                     overrides the GitHub release URL
#
# The archive's SHA-256 is checked against the SHA256SUMS file of the same
# release before anything is written to the destination.
set -eu

repo="r3dlight/lumo-cli"
dir="${LUMO_INSTALL_DIR:-$HOME/.local/bin}"
version="${LUMO_VERSION:-latest}"

fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail "lumo-cli runs on Linux only (Landlock is a Linux feature)"
case "$(uname -m)" in
    x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
    *) fail "no prebuilt binary for $(uname -m); build from source with cargo" ;;
esac
command -v curl >/dev/null || fail "curl is required"
command -v sha256sum >/dev/null || fail "sha256sum is required"

if [ -n "${LUMO_BASE_URL:-}" ]; then
    base="${LUMO_BASE_URL%/}"
elif [ "$version" = latest ]; then
    base="https://github.com/$repo/releases/latest/download"
else
    base="https://github.com/$repo/releases/download/$version"
fi
asset="lumo-cli-$target.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fetch() { curl -fsSL --tlsv1.2 -o "$tmp/$2" "$base/$1" || fail "cannot download $base/$1"; }
fetch "$asset" "$asset"
fetch SHA256SUMS SHA256SUMS
(cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c --quiet -) \
    || fail "checksum mismatch for $asset; refusing to install"

mkdir -p "$dir"
tar -xzf "$tmp/$asset" -C "$tmp" lumo-cli
install -m 755 "$tmp/lumo-cli" "$dir/lumo-cli"
printf 'installed %s to %s\n' "$("$dir/lumo-cli" --version)" "$dir/lumo-cli"

case ":$PATH:" in
    *":$dir:"*) ;;
    *) printf 'note: %s is not in PATH\n' "$dir" ;;
esac
# The sandbox needs Landlock (Linux 5.13); the tool itself runs on any kernel.
kernel=$(uname -r | cut -d. -f1,2)
major=${kernel%%.*}
minor=${kernel#*.}
if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "${minor%%[!0-9]*}" -lt 13 ]; }; then
    printf 'note: kernel %s has no Landlock; the agent sandbox will be unavailable\n' "$(uname -r)"
fi
