#!/usr/bin/env bash
# Bakes the mina-rosetta-cli deb that `minimina network check rosetta`
# installs from packages.o1test.net: coinbase mesh-cli with Mina's patch of
# rosetta-sdk-go, as buildkite/scripts/tests/rosetta/install-cli.sh in the mina
# repository builds it, linked statically so one deb serves every codename.
#
# mesh-cli no longer changes, so this is run by hand, once per architecture,
# and the debs are uploaded by hand (see the README).
#
#   GO=<go 1.19>/bin/go CC=<static musl C compiler> ARCH=amd64|arm64 \
#     scripts/rosetta-cli-deb.sh [<out dir>]
#
# mesh-cli needs cgo (DataDog/zstd), hence the C compiler. With nix:
#   amd64: CC=$(nix build --print-out-paths nixpkgs#pkgsStatic.stdenv.cc)/bin/x86_64-unknown-linux-musl-gcc
#   arm64: CC=$(nix build --print-out-paths nixpkgs#pkgsCross.aarch64-multiplatform-musl.pkgsStatic.stdenv.cc)/bin/aarch64-unknown-linux-musl-gcc
set -euo pipefail

MESH_CLI_VERSION="${MESH_CLI_VERSION:-v0.10.1}"
SDK_TAG="${SDK_TAG:-stake-delegation-v1}"
PACKAGE=mina-rosetta-cli
VERSION="${MESH_CLI_VERSION#v}-${SDK_TAG}"
: "${GO:?go 1.19, as mina CI uses}" "${CC:?a C compiler that links statically}" "${ARCH:?amd64 or arm64}"
OUT="$(realpath "${1:-.}")"

case "$ARCH" in
  amd64 | arm64) ;;
  *) echo "ARCH is amd64 or arm64, not $ARCH" >&2; exit 1 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL --retry 5 \
  "https://github.com/coinbase/mesh-cli/archive/refs/tags/${MESH_CLI_VERSION}.tar.gz" \
  | tar -xz -C "$WORK"
cd "$WORK/mesh-cli-${MESH_CLI_VERSION#v}"
"$GO" mod edit -replace \
  "github.com/coinbase/rosetta-sdk-go@v0.8.1=github.com/MinaProtocol/rosetta-sdk-go@${SDK_TAG}"
"$GO" mod tidy

ROOT="$WORK/deb"
mkdir -p "$ROOT/usr/bin" "$ROOT/DEBIAN"
CGO_ENABLED=1 GOOS=linux GOARCH="$ARCH" CC="$CC" "$GO" build -trimpath \
  -tags netgo,osusergo -ldflags "-s -w -linkmode external -extldflags -static" \
  -o "$ROOT/usr/bin/rosetta-cli" .
file "$ROOT/usr/bin/rosetta-cli" | grep -q 'statically linked' \
  || { file "$ROOT/usr/bin/rosetta-cli"; echo "rosetta-cli is not statically linked" >&2; exit 1; }

cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PACKAGE
Version: $VERSION
Architecture: $ARCH
Maintainer: O(1)Labs <build@o1labs.org>
Section: utils
Priority: optional
Homepage: https://github.com/coinbase/mesh-cli
Description: rosetta-cli for Mina's Rosetta API
 coinbase/mesh-cli $MESH_CLI_VERSION built with
 MinaProtocol/rosetta-sdk-go@$SDK_TAG, as mina CI builds it, linked
 statically. minimina network check rosetta runs its check:data.
EOF

mkdir -p "$OUT"
dpkg-deb --root-owner-group -Zxz -b "$ROOT" "$OUT/${PACKAGE}_${VERSION}_${ARCH}.deb"
