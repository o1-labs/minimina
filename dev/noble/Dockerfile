# Ubuntu 24.04 (noble) environment to build minimina and run native-mode networks
# on hosts whose own userland is too old for current mina packages.
FROM ubuntu:24.04

ARG UID=1000
ARG GID=1000
ARG RUST_TOOLCHAIN=1.92.0
ENV DEBIAN_FRONTEND=noninteractive

# build: rust deps; runtime: Depends of mina-generic / mina-archive-generic /
# mina-rosetta-generic 4.x; postgres for native archive nodes; node for Archive-Node-API
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config git curl ca-certificates jq procps iproute2 \
      libssl3t64 libgmp10 libgomp1 tzdata liblmdb0 libffi8 libjemalloc2 libpq-dev libproc2-0 \
      postgresql-16 postgresql-client-16 \
      nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# replace the image's default uid 1000 user by one matching the host user,
# so files written to bind mounts keep the host owner
RUN userdel -r ubuntu 2>/dev/null; groupadd -g ${GID} dev && useradd -m -u ${UID} -g ${GID} -s /bin/bash dev
USER dev
ENV PATH=/home/dev/.cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain ${RUST_TOOLCHAIN} \
    && mkdir -p /home/dev/.cargo/registry /home/dev/.minimina

USER root
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
