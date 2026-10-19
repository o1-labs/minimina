#!/usr/bin/env bash
# Writes target/debian-changelog, the Debian changelog `cargo deb` packages.
set -euo pipefail

cd "$(dirname "$0")/.."
# `cargo pkgid` prints path+file:///dir#minimina@1.2.3 (or ...#1.2.3)
version=$(cargo pkgid | sed -E 's/.*[#@]//')
commit=$(git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)
maintainer=$(sed -n 's/^maintainer = "\(.*\)"$/\1/p' Cargo.toml)

mkdir -p target
cat > target/debian-changelog <<CHANGELOG
minimina (${version}) unstable; urgency=medium

  * Release ${version} (commit ${commit}).

 -- ${maintainer}  $(date -R)
CHANGELOG
echo "target/debian-changelog: minimina ${version} (${commit})"
