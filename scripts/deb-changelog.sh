#!/usr/bin/env bash
# Writes target/debian-changelog, the Debian changelog `cargo deb` packages.
set -euo pipefail

cd "$(dirname "$0")/.."
version=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')
commit=$(git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)
maintainer=$(sed -n 's/^maintainer = "\(.*\)"$/\1/p' Cargo.toml)

mkdir -p target
cat > target/debian-changelog <<CHANGELOG
minimina (${version}) unstable; urgency=medium

  * Release ${version} (commit ${commit}).

 -- ${maintainer}  $(date -R)
CHANGELOG
echo "target/debian-changelog: minimina ${version} (${commit})"
