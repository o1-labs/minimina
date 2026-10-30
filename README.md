# MiniMina

MiniMina is a command line tool for spinning up Mina networks locally on a user's computer. It supports both Docker Compose and native process deployment modes, enabling integration tests of the Mina protocol outside of GCP. For design details, see the [RFC](docs/rfc/README.md).

## Prerequisites

- **Docker** - required for Docker mode. See [docker install](https://docs.docker.com/engine/install/).
- **Rust & Cargo** - required for building from source. See [Rust install](https://www.rust-lang.org/tools/install).

## Building

```bash
cargo build --release
cp target/release/minimina ~/.local/bin
```

Assuming `~/.local/bin` is on your `$PATH`, `minimina` will be available from the command line.

### Installing from Deb Package

```bash
# codename: bookworm, jammy or noble
echo "deb [trusted=yes] http://packages.o1test.net $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/minimina.list
sudo apt-get update
sudo apt-get install -y minimina
```

Releases are published from `v*` tags. The package depends only on libc (TLS is rustls, so it does not need OpenSSL), so the same binary is built once on the oldest supported codename (jammy) and published for every codename. Focal and bullseye are not supported: Mina 4.x has no packages for them, and their standard support has ended.

To build the package locally: `scripts/deb-changelog.sh && cargo deb`.

## Testing

```bash
cargo test                 # unit + CLI tests; no docker or mina needed
cargo llvm-cov --summary-only

# end-to-end: real daemons must produce a block (minutes; CI runs both)
cargo test --test e2e -- --ignored native_small_network_produces_blocks   # needs a generic mina build
cargo test --test e2e -- --ignored docker_small_network_produces_blocks   # needs docker
```

Use a generic mina build (`mina-devnet-generic`, `*-generic` images) for local networks: network packages install `config_<commit>.json`, which the daemon merges into every config, so the public network's peer list and fork point leak into the local one.

## Usage

```bash
minimina --help
minimina network --help
minimina node --help
```

---

## Default Network

Create a local blockchain network with default settings:

```bash
minimina network create
```

### Network Lifecycle

```bash
minimina network start
minimina network stop
minimina network delete
```

### Query Network

```bash
minimina network info
minimina network status
```

`network status` asks every running node over GraphQL (in parallel, 3 s timeout):
daemons report `sync_status`, `height` and `peers` (via
[mina-sdk](https://github.com/MinaProtocol/mina-sdk-rust)), the archive node api
reports the archive's `canonical_height` and `pending_height` (via
[mina-archive-sdk](https://github.com/o1-labs/mina-archive-sdk-rust)). A node that
does not answer reports `error`.

`network start --wait-synced [--sync-timeout 1800]` returns only when every
daemon is `SYNCED`, which is what scripts need before they send transactions.

### Directory Structure

The default network is stored at `~/.minimina/default/` (override with `$MINIMINA_HOME`):

```
~/.minimina/default/
├── docker-compose.yaml
├── network.json
├── services.json
├── genesis_ledger.json
├── create_schema.sql
├── libp2p-keypairs/    (12 files)
└── network-keypairs/   (12 files)
```

### Default Nodes

| Node | Role | GraphQL |
|------|------|---------|
| `mina-seed-1` | Seed | localhost:3101 |
| `mina-bp-1` | Block producer | localhost:4001 |
| `mina-bp-2` | Block producer | localhost:4006 |
| `mina-snark-worker-1` | SNARK worker | - |
| `mina-snark-coordinator` | SNARK coordinator | localhost:7001 |
| `mina-archive` | Archive node | localhost:5006 |

### Node Operations

**Logs:**
```bash
minimina node logs -n <node-name>                 # JSON logs
minimina node logs -n <node-name> --raw            # raw logs
```

**Start/Stop individual nodes:**
```bash
minimina node stop -n <node-name>
minimina node start -n <node-name>
minimina node start -n <node-name> --fresh-state
minimina node start -n <node-name> --import-accounts
minimina node start -n <node-name> --graphql-filtered-logs
```

**Dump data:**
```bash
minimina node dump-precomputed-blocks -n <node-name>
minimina node dump-archive-data -n <node-name>
minimina node run-replayer -n <node-name>
```

---

## Network Spec

To choose the nodes of a network, write a short TOML spec. minimina generates
the keys, ports, peers and genesis ledger:

```toml
# net.toml
[[nodes]]
role = "seed"

[[nodes]]
role = "block-producer"
count = 2

[[nodes]]
role = "plain"          # follows the chain, produces no blocks

[[nodes]]
role = "archive"
```

```bash
minimina network create -n mynet --spec net.toml
minimina network start -n mynet
```

Roles: `seed`, `block-producer`, `plain`, `archive`, `snark-coordinator`, `rosetta`,
`archive-node-api`.
A `rosetta` node runs `mina-rosetta` against the archive database and the GraphQL
API of a daemon (`node = "<name>"`, default: the archive node); the output of
`network create` gives its `rosetta_uri`. An `archive-node-api` node runs
[Archive-Node-API](https://github.com/o1-labs/Archive-Node-API) against the archive
database (GraphQL at `/` on its port). In native mode it needs Node.js 22.12 or newer:
minimina installs the npm package once per version into `~/.minimina/.tools`
(`version`, default `2.0.0`), or runs your own build (`bin`).
Names default to `<role>-<n>` (`seed-1`, `bp-1`, `node-1`); client ports start at
3100 in steps of 10. Only block producers hold stake unless a node sets `balance`.
[docs/examples/network.toml](docs/examples/network.toml) shows every option:
balances, funded test accounts, runtime config overrides, docker images and the
profile. The default network is a built-in spec.

### Profile

Since 4.0 the mina binaries are generic and select their build profile at
runtime. `network create --profile dev|devnet|lightnet|mainnet` (or `profile` in
the spec; default `devnet`) is recorded in the network and exported as
`MINA_PROFILE` to every mina process. `lightnet` runs without proofs and is the
fastest for local tests; `devnet` and `mainnet` compile full proofs, so each
daemon spends 2-3 minutes on start.

### Genesis timestamp

`network create` writes a temporary genesis timestamp. The first
`network start` sets it to the time of the start, so the first slots of the
chain are not gone while the daemons start. Later starts keep it.

### Hardfork

A `[hardfork]` section plans a fork of the network to other (postfork)
binaries. Native mode only.

```toml
[runtime_config]
genesis = { k = 10 }
proof = { block_window_duration_ms = 30000 }

[hardfork]
mode = "manual"                  # or "auto": the daemons run --hardfork-handling migrate-exit
at = { slot = 42 }               # slot_chain_end, or an RFC 3339 date: at = "2026-10-29T14:00:00Z"
# tx_end_before = 12             # slot_tx_end = slot_chain_end - tx_end_before [default: k + 2]
# genesis_slot_delta = 10        # fork genesis slot = slot_chain_end + genesis_slot_delta
# method = "legacy"              # manual only: legacy (GraphQL fork_config) | advanced

[hardfork.postfork]
bin_path = "/opt/mina-postfork/bin"   # relative to the spec file
# archive_upgrade = "/opt/mina-postfork/upgrade.sql"   # default: from the package
```

`network create` writes `daemon.slot_tx_end`, `daemon.slot_chain_end` and
`daemon.hard_fork_genesis_slot_delta` into the genesis runtime config. It
refuses the spec, with a list of all problems, before it changes anything, if:

- `genesis.k` or `proof.block_window_duration_ms` is not set;
- `tx_end_before` is not more than k, or `slot_tx_end` is less than 10 minutes
  after the genesis (the daemons need this time to start and sync);
- `[runtime_config]` also sets one of the three `daemon` keys;
- `bin_path` is missing, does not have `mina` (and `mina-archive`,
  `mina-rosetta`, `mina-create-genesis` when the network needs them), or its
  `mina` does not run;
- `mode = "auto"` and the prefork daemon has no `--hardfork-handling`;
- the network has an archive, and minimina finds no postfork `upgrade.sql`.
  The default is the script of the postfork package,
  `<package root>/etc/mina/archive/upgrade.sql`, where the package root is
  `bin_path` without `usr/local/bin` (for example, a package unpacked with
  `dpkg-deb -x`). Packages of all versions install the script as
  `/etc/mina/archive/upgrade.sql`, so for a build that is not in a package
  directory, set `archive_upgrade`.

A date is changed to a slot again at the first `network start`, from the real
genesis timestamp.

```bash
minimina network hardfork status -n mynet
```

shows the phase of the network (`not-started`, `before-genesis`, `prefork`,
`tx-end`, `chain-end`, `fork-genesis`), the state of the hardfork (`planned`,
`prepared`, `applied`), the slot and time of `slot_tx_end`, `slot_chain_end`
and the fork genesis, and the time to the next phase.

#### Manual mode

```bash
minimina network hardfork prepare -n mynet --wait   # after slot_chain_end
minimina network hardfork apply -n mynet            # before the fork genesis
```

`prepare` works on the running prefork network, one slot after
`slot_chain_end` (`--wait` waits for it). It writes the postfork data to
`<network dir>/hardfork/` and stops with all problems if a check fails:

1. It gets `fork_config` (GraphQL) from every daemon. All daemons must give
   the same fork point (the state hash and height of the last prefork block).
2. The postfork `mina-create-genesis` (`runtime_genesis_ledger`) makes the
   postfork ledgers and `ledger_hashes.json` from the fork config.
3. It writes `daemon.json`: the fork point, the epoch seeds, the ledger
   hashes, and the genesis timestamp of the fork genesis slot.
4. `method = "advanced"` only: each prefork daemon writes its own fork data
   (`mina advanced generate-hardfork-config`). Its ledger hash must be the
   hash of step 2. If not, the prefork and postfork versions do not agree on
   the hardfork ledger, and the postfork daemon cannot load the data.
5. The postfork `mina internal chain-id` must give one chain id for all
   nodes. This also checks that the ledger files are there.

`apply` stops the network and then:

1. keeps the prefork `genesis_ledger.json` as `genesis_ledger.prefork.json`,
   and writes the shared postfork config (without `ledger`, `daemon` and
   `genesis.genesis_state_timestamp`);
2. copies `daemon.json` to the config directory of each daemon, and the
   ledgers to `<config dir>/<chain id>/genesis`;
3. applies the postfork `upgrade.sql` to the archive database, and checks
   that the last `migration_history` row says `applied`;
4. records the postfork `bin_path` and starts the network with it.

---

## Custom Networks (Lucy-Generated Genesis & Topology)

Pre-configured test networks are available in `./tests/data/`:

**Large network:**
```bash
minimina network create \
  -g ./tests/data/large_network/genesis_ledger.json \
  -t ./tests/data/large_network/topology.json \
  -n large-network
```

**Small network:**
```bash
minimina network create \
  -g ./tests/data/small_network/genesis_ledger.json \
  -t ./tests/data/small_network/topology.json \
  -n small-network
```

Manage custom networks with the same commands, using `-n <name>`:
```bash
minimina network start -n large-network
minimina network status -n large-network
minimina network stop -n large-network
minimina network delete -n large-network
```

---

## Network with Uptime-Service-Backend

Test data is in `tests/data/uptime_service_network`.

1. Populate `app_config.json` and `minasheets.json` with AWS S3 and Google Sheets credentials
2. Rename `uptime_service_config_test` to `uptime_service_config`
3. Create and start:

```bash
minimina network create \
  -n uptime \
  -t tests/data/uptime_service_network/topology.json \
  -g tests/data/uptime_service_network/genesis_ledger.json

minimina network start -n uptime
```

---

## Architecture

MiniMina supports two deployment modes:

- **Docker mode** (`src/docker/`): Uses Docker Compose to manage containerized Mina nodes
- **Native mode** (`src/native/`): Spawns Mina processes directly on the host machine

### Native mode

```bash
minimina --mode native [--bin-path /usr/local/bin] network create -n local -t topology.json -g genesis_ledger.json
minimina network start -n local          # mode and bin path come from the network
minimina network status -n local
minimina node stop -n local -i seed-0 --timeout 30
minimina network stop -n local
```

- `network create` records the mode, `mina` directory and postgres URI in `<network>/minimina.json`; later commands use them, and a conflicting `--mode` is an error. Networks without the file are treated as docker networks.
- `network start` starts the seeds first and starts the other nodes only when every seed accepts connections on its libp2p port (`--seed-timeout`, default 900 s): a non-seed daemon exits if it finds no peer during its initialization. Seeds are dialled on `127.0.0.1`.
- Each node is a process group (the daemon and its `libp2p_helper`). `stop` sends SIGTERM to all groups at once and SIGKILL after `--timeout` seconds (default 60). A second `start` of a running node or network is refused.
- Logs are appended to `<network>/logs/<node>.log`; `node logs`, `node dump-precomputed-blocks`, `node dump-archive-data` and `node run-replayer` work in both modes.
- Daemons advertise `127.0.0.1` (`-external-ip`). Daemons that have `-precomputed-blocks-dir` (4.0.2+) write one file per block to `config-directory/<node>/precomputed_blocks`; older ones append to `precomputed_blocks.log`.
- The archive schema comes from the archive package next to `mina` (`<root>/etc/mina/archive/create_schema.sql` for `<root>/usr/local/bin`); minimina downloads it from GitHub only when the package has none.
- Archive nodes run `mina-archive` (from the same directory as `mina`) against a database `minimina_<network_id>`, recreated on every `network create`. The postgres server is `postgres://postgres:postgres@localhost:5432` unless `MINIMINA_POSTGRES_URI` is set at create time; `psql`, `pg_dump` and `mina-replayer` must be installed.

### Integration with Lucy

MiniMina is designed to work with [Lucy](../test_executive/README.md) (the Mina integration test executive). Lucy generates network topology and genesis files, then uses MiniMina to create and manage the test network:

1. Lucy generates topology and genesis files
2. Lucy calls `minimina network create` with those files
3. MiniMina returns GraphQL endpoints and log paths
4. Lucy executes integration tests via GraphQL
5. Lucy can start/stop individual nodes during tests
6. Lucy calls `minimina network delete` to tear down

## License

This project is licensed under the [MIT License](LICENSE).
