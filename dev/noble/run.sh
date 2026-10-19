#!/usr/bin/env bash
# Builds the noble dev image and starts (or reuses) the `minimina-dev` container.
#
#   dev/noble/run.sh            # start container, build minimina inside
#   docker exec -it -u dev minimina-dev bash
#
# The container uses the host network: native-mode ports are reachable from the
# host as they would be on a noble machine. Mounts:
#   repo           -> same path (so absolute paths in network dirs stay valid)
#   ~/.minimina    -> /home/dev/.minimina (networks, installed mina versions)
#   MINA_BINS_DIR  -> same path (manually unpacked mina versions, optional)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE=minimina-dev:noble
NAME=minimina-dev
PGPORT="${PGPORT:-5433}"
MINA_BINS_DIR="${MINA_BINS_DIR:-$HOME/work/mina-bins}"

docker build -q -t "$IMAGE" --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" "$REPO/dev/noble" >/dev/null

if ! docker container inspect "$NAME" >/dev/null 2>&1; then
  mkdir -p "$HOME/.minimina" "$MINA_BINS_DIR"
  docker run -d --name "$NAME" --network host \
    -e PGPORT="$PGPORT" \
    -e MINIMINA_POSTGRES_URI="postgres://postgres:postgres@localhost:$PGPORT" \
    -e CARGO_TARGET_DIR="$REPO/target/noble" \
    -v "$REPO:$REPO" -w "$REPO" \
    -v "$HOME/.minimina:/home/dev/.minimina" \
    -v "$MINA_BINS_DIR:$MINA_BINS_DIR" \
    -v minimina-dev-cargo:/home/dev/.cargo/registry \
    "$IMAGE" >/dev/null
elif [[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != true ]]; then
  docker start "$NAME" >/dev/null
fi

docker exec -u dev -e HOME=/home/dev "$NAME" cargo build --release
echo "minimina: $REPO/target/noble/release/minimina (shell: docker exec -it -u dev $NAME bash)"
