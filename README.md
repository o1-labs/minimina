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
# codename: bullseye, bookworm, focal, jammy or noble
echo "deb [trusted=yes] http://packages.o1test.net $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/minimina.list
sudo apt-get update
sudo apt-get install -y minimina
```

Releases are published from `v*` tags. The package has no runtime dependency besides libc (TLS is rustls), so the same binary is built once on the oldest supported glibc and published for every codename.

To build the package locally: `scripts/deb-changelog.sh && cargo deb`.

## Testing

```bash
cargo test
```

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

### Directory Structure

The default network is stored at `~/.minimina/default/` (override with `$MINIMINA_HOME`):

```
~/.minimina/default/
├── docker-compose.yaml
├── network.json
├── services.json
├── genesis_ledger.json
├── create_schema.sql
├── zkapp_tables.sql
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
- Each node is a process group (the daemon and its `libp2p_helper`). `stop` sends SIGTERM to all groups at once and SIGKILL after `--timeout` seconds (default 60). A second `start` of a running node or network is refused.
- Logs are appended to `<network>/logs/<node>.log`; `node logs`, `node dump-precomputed-blocks`, `node dump-archive-data` and `node run-replayer` work in both modes.
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
