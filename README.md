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
`archive-node-api`, `uptime-service-backend` (see [Uptime service
backend](#uptime-service-backend)).
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

### Node flags

The nodes can also be given as flags, without a file, or on top of one:

```bash
minimina network create -n mynet --block-producers 2 --plain-nodes 1 --archive --rosetta
minimina network create -n mynet --spec net.toml --bps 3     # the spec, with 3 block producers
minimina spec init --bps 2 --archive --accounts 5 > net.toml # the same flags, as a commented spec
```

| Flag | |
|------|---|
| `--seeds N` | seed nodes |
| `--block-producers N` (`--bps`) | block producers |
| `--plain-nodes N` (`--plains`) | plain nodes |
| `--archive` | an archive node |
| `--rosetta` | mina-rosetta (needs an archive node) |
| `--archive-node-api` | the archive node api (needs an archive node) |
| `--snark-workers N` | snark workers and their coordinator (`0`: none) |
| `--accounts N` | funded test accounts (`account-1`, ...) |

- Flags win over `--spec`, which wins over the built-in defaults. A count
  replaces the nodes of its role in the spec (`0` removes them; the first
  group keeps its balance, and its name and port while it is one node). A
  switch adds its node when the spec has none.
- Flags without `--spec` change a network of one seed and one block producer.
  With neither, `network create` makes the default network above.
- `network create` writes the spec as resolved, with absolute paths, to
  `<network>/network.toml`: `--spec ~/.minimina/mynet/network.toml` creates
  the same network again.

### Ledger file

`[ledger] file` gives the accounts the genesis ledger starts with; the
generated ones (block producers, `accounts`) are added after them. A relative
path is relative to the spec file.

```toml
[ledger]
file = "accounts.csv"   # or a .json runtime config (ledger.accounts)
accounts = 2
```

- `.json`: a runtime config (`ledger.accounts`), `{"accounts": [...]}` or an
  array of accounts. The accounts are kept as they are (timing, delegate, ...).
- `.csv`: a header line naming the columns, then one account per line.
  `public_key` and `balance` (in MINA, like every balance in the spec) are
  required; `private_key` and `delegate` are optional. Empty lines and lines
  starting with `#` are skipped.

```csv
public_key,balance,delegate
B62qrPN5Y5yq8kGE3FbVKbGTdTAJNdtNtB5sNVpxyRwWGcDEhpMzc8g,1000,
B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg,0.5,B62qrPN5Y5yq8kGE3FbVKbGTdTAJNdtNtB5sNVpxyRwWGcDEhpMzc8g
```

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
# tx_end_before = 8              # slot_tx_end = slot_chain_end - tx_end_before [default: k - 2]
# genesis_slot_delta = 20        # fork genesis slot = slot_chain_end + genesis_slot_delta
# method = "legacy"              # manual only: legacy (GraphQL fork_config) | advanced

[hardfork.postfork]
bin_path = "/opt/mina-postfork/bin"   # relative to the spec file
# archive_upgrade = "/opt/mina-postfork/upgrade.sql"   # default: from the package
# mina_version = "4.0.4"              # or an installed version (minimina mina install)
```

`network create` writes `daemon.slot_tx_end`, `daemon.slot_chain_end` and
`daemon.hard_fork_genesis_slot_delta` into the genesis runtime config. It
refuses the spec, with a list of all problems, before it changes anything, if:

- `genesis.k` or `proof.block_window_duration_ms` is not set;
- `tx_end_before` is not from 1 to k - 1 (see `prepare` below), or
  `slot_tx_end` is less than 10 minutes after the genesis (the daemons need this time to start and sync);
- `[runtime_config]` also sets one of the three `daemon` keys;
- neither `bin_path` nor `mina_version` is set, both are, `mina_version` is
  not installed, or the directory does not have `mina` (and `mina-archive`,
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
   A daemon makes it from the last block before `slot_tx_end`, which it finds
   in its transition frontier: the k blocks below its best tip. Up to
   `tx_end_before + 1` blocks follow that block, so `tx_end_before` must be
   less than k, as in mina's own hardfork test (k = 10, 8 slots). With more,
   the daemons answer `Block with state hash ... not found in transition
   frontier` whenever most slots get a block.
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
6. With an archive, the postfork `mina-archive-hardfork-toolbox` checks the
   prefork archive: `fork-candidate last-filled-block` must give the fork
   block of step 1, and `fork-candidate is-in-best-chain` must find it on the
   best chain. `fork-candidate confirmations` (k blocks after the fork block,
   up to the best tip of the daemon of step 1) only warns: with fewer than k
   slots from `slot_tx_end` to `slot_chain_end`, fewer than k blocks follow
   the fork block.
   `fork-candidate no-commands-after` does not run: in 4.0.4 it always fails
   ([MinaProtocol/mina#19982](https://github.com/MinaProtocol/mina/issues/19982)).

`apply` stops the network and then:

1. keeps the prefork `genesis_ledger.json` as `genesis_ledger.prefork.json`,
   and writes the shared postfork config (without `ledger`, `daemon` and
   `genesis.genesis_state_timestamp`);
2. copies `daemon.json` to the config directory of each daemon, and the
   ledgers to `<config dir>/<chain id>/genesis`;
3. applies the postfork `upgrade.sql` to the archive database, checks that
   the last `migration_history` row says `applied`, and runs the toolbox's
   `verify-upgrade` with its versions;
4. writes the postfork archive config `hardfork/archive_config.json`: the
   shared config with `fork_config.json` (the fork ledger's accounts) on top.
   From it `mina-archive` makes the same postfork genesis block as the
   daemons and records the fork ledger's accounts;
5. records the postfork `bin_path` and starts the network with it;
6. with an archive, waits for the archive to insert the postfork genesis
   block, then runs the toolbox's `validate-fork` on that block and
   `convert-chain-to-canonical`. This marks the prefork chain canonical up to
   the fork block and its other blocks orphaned, which the archive does not do
   on a network with a smaller k than its compiled one
   ([MinaProtocol/mina#19986](https://github.com/MinaProtocol/mina/issues/19986)).
   The network is running by then, so a failure here leaves it on the
   postfork binaries.

A failed upgrade or `verify-upgrade` stops `apply` before the network starts.
`populate-genesis-accounts` is not needed: the archive records the fork
ledger's accounts from `archive_config.json`.

A manual fork of a network with an archive needs
`mina-archive-hardfork-toolbox` in the postfork `bin_path`.

### Checks

Checks of a running network, for example after a hardfork. Each prints a
JSON report and exits with 1 when a check fails.

```bash
minimina network check vesting -n mynet
minimina network check rosetta -n mynet [--wait] [--start-index N] [--rosetta-cli PATH]
minimina network check fork -n mynet
```

`check fork`, after `hardfork apply`, holds the postfork chain against what
`hardfork prepare` made (`hardfork/prepared.json`, `ledger_hashes.json` and
`fork_config.json`):

- chain: every daemon runs the same postfork genesis; its parent is the fork
  block, its height the next one, its slot the fork slot, and its ledger and
  staking ledger hashes are the ones prepare made; the best tip is above it;
- ledger: the accounts the archive recorded for the postfork genesis are
  the MINA accounts of the fork ledger (balance, nonce, receipt chain hash,
  delegate, vesting schedule), and no others;
- archive: `migration_history` says the upgrade is applied, and one chain
  runs from the highest block through the postfork genesis and the fork
  block down to the first block, canonical up to the postfork genesis;
- payments, with [payment loads](#payment-loads): a payment sent before the
  fork is in a block up to the fork block, or in none (it was in the pool at
  `slot_tx_end`, which the fork drops), never after it; each sender's nonce
  in the fork ledger follows its last prefork payment in a block; a payment
  sent after the fork is in a postfork block or still pending. A load started
  before the fork with `--across-fork` gives both. Without payments, the
  report notes what to run.

The ledger, archive and payment checks read the archive database of a
native network.

`check vesting` checks every timed account of the (prefork) genesis ledger,
the accounts with a `timing` in the `[ledger] file`:

- after `hardfork prepare`, the fork config (`hardfork/fork_config.json`)
  has the same vesting schedule;
- the daemon rosetta reads (else the first daemon) has that schedule, and
  locks the amount the schedule gives at its best tip's slot;
- with rosetta, `/account/balance` locks that amount at the slot of the block
  it answers for, and the liquid balance is the rest.

`check rosetta` runs `rosetta-cli check:data` with the config of the
network's mina package (`etc/mina/rosetta/rosetta-cli-config/config.json`),
as mina CI does: every balance change of every block is reconciled against
`/account/balance`, until every account seen is reconciled. The config,
data and results are in `<network dir>/rosetta-cli`. After a hardfork:

- rosetta names the postfork genesis as its genesis, and rosetta-cli refuses
  the prefork one, so the sync starts at block 2 and crosses the fork;
- until the postfork chain is taller than the prefork tip, rosetta answers
  with orphaned prefork blocks
  ([MinaProtocol/mina#19984](https://github.com/MinaProtocol/mina/issues/19984)),
  and check:data fails. `check rosetta` refuses to start then, or with
  `--wait` waits for it.

rosetta-cli is mesh-cli v0.10.1 built with Mina's
`MinaProtocol/rosetta-sdk-go@stake-delegation-v1`, as
`buildkite/scripts/tests/rosetta/install-cli.sh` of the mina repository
builds it. Nothing needs to be built: minimina runs `--rosetta-cli` if given,
else `~/.minimina/.tools/rosetta-cli/<version>/usr/bin/rosetta-cli`, which it
installs from the `mina-rosetta-cli` deb in the stable channel of
packages.o1test.net the first time, as it installs mina: the deb is checked
against the repository index and unpacked with `dpkg-deb`, without root. The
binary is linked statically, so one deb serves every codename; it can also be
installed with apt (`apt-get install mina-rosetta-cli`, from the repository
in [Installing from Deb Package](#installing-from-deb-package)).

Another mesh-cli version or patch tag needs a new deb and `VERSION` in
`src/install/rosetta_cli`.

### Payment loads

A load sends payments between the test accounts of a network (`[ledger]
accounts = N`, keys `account-N` in `network-keypairs`) in the background,
through one daemon, until it is stopped or has a reason to stop.

```bash
minimina network load start -n mynet [--scenario once|steady|burst] [options]
minimina network load list -n mynet
minimina network load status -n mynet load-1
minimina network load stop -n mynet load-1     # or --all
```

| scenario | payments per round (`--count`) | between rounds (`--interval`) | rounds (`--rounds`) |
|----------|-----|------|-----------------|
| once     | 1   |      | 1               |
| steady (default) | 1   | 10 s | until stopped   |
| burst    | 10  | 120 s | until stopped  |

- `--duration SECS` ends a load after a time;
- `--senders account-1,account-3` pays from some test accounts (by key name
  or public key) [default: all]; each sender pays the next test account, and
  the senders take turns;
- `--amount` and `--fee` in MINA [default: 1 and 0.1];
- `--node bp-2` sends through another daemon [default: the first block
  producer]. The load imports the senders' keys into it (GraphQL
  `importAccount`) and unlocks them, so the daemon signs and sets the nonces.

A load stops, and `status` says why:

| reason | when |
|--------|------|
| `stopped` | `load stop`, `network stop` or `network delete` |
| `done` | its rounds or `--duration` are over |
| `tx_window_closed` | the daemon refused a payment with `After_slot_tx_end`: the hardfork transaction window is closed |
| `funds_drained` | no sender can pay amount + fee from its liquid balance (vesting funds that are still locked do not count) |
| `failed` | `--max-failures` (5) payments failed since the last accepted one, or a key could not be unlocked |
| `died` | the process is gone without a reason (see `load.log`) |

With `--across-fork`, a load that meets `After_slot_tx_end` waits instead:
once the daemon answers with a new genesis and is synced (after `hardfork
apply`), it unlocks the keys again and goes on. Each sender is in one running
load at a time, so loads do not race for its nonces.

A load is the process `minimina network load run`, in its own process group
(a Ctrl-C in the shell that started it does not stop it). Its files are in
`<network dir>/load/<id>`: `load.json` (what was asked), `status.json`,
`payments.jsonl` (every payment with its hash and nonce, or the daemon's
error, and the genesis of the chain it was sent on; the memo is `<id> <n>`)
and `load.log`.

---

## Uptime service backend

A network can run the [uptime service
backend](https://github.com/MinaFoundation/uptime-service-backend) (docker mode
only; native mode skips it). Its block producers submit to it:

```toml
[[nodes]]
role = "uptime-service-backend"
app_config = "uptime/app_config.json"     # relative to the spec file
minasheets = "uptime/minasheets.json"     # Google Sheets credentials
# config_files = ["uptime/other.json"]    # other files the app config names

[docker]
uptime_service_backend_image = "<the backend's image>"
```

[tests/data/uptime](tests/data/uptime) has empty templates of both files; fill
in the AWS S3 and Google Sheets credentials. minimina copies the files to
`<network>/uptime_service_config/`, the backend listens on port 8080, and the
block producers get `-uptime-url` and `-uptime-submitter-key`.

---

## Architecture

MiniMina supports two deployment modes:

- **Docker mode** (`src/docker/`): Uses Docker Compose to manage containerized Mina nodes
- **Native mode** (`src/native/`): Spawns Mina processes directly on the host machine

### Native mode

```bash
minimina --mode native [--bin-path /usr/local/bin] network create -n local --spec net.toml
minimina network start -n local          # mode and bin path come from the network
minimina network status -n local
minimina node stop -n local -i seed-0 --timeout 30
minimina network stop -n local
```

- `network create` records the mode, `mina` directory (and `--mina-version`) and postgres URI in `<network>/minimina.json`; later commands use them, and a conflicting `--mode` is an error. Networks without the file are treated as docker networks.
- `network start` starts the seeds first and starts the other nodes only when every seed accepts connections on its libp2p port (`--seed-timeout`, default 900 s): a non-seed daemon exits if it finds no peer during its initialization. Seeds are dialled on `127.0.0.1`.
- Each node is a process group (the daemon and its `libp2p_helper`). `stop` sends SIGTERM to all groups at once and SIGKILL after `--timeout` seconds (default 60). A second `start` of a running node or network is refused.
- Logs are appended to `<network>/logs/<node>.log`; `node logs`, `node dump-precomputed-blocks`, `node dump-archive-data` and `node run-replayer` work in both modes.
- Daemons advertise `127.0.0.1` (`-external-ip`). Daemons that have `-precomputed-blocks-dir` (4.0.2+) write one file per block to `config-directory/<node>/precomputed_blocks`; older ones append to `precomputed_blocks.log`.
- The archive schema comes from the archive package next to `mina` (`<root>/etc/mina/archive/create_schema.sql` for `<root>/usr/local/bin`); minimina downloads it from GitHub only when the package has none.
- Archive nodes run `mina-archive` (from the same directory as `mina`) against a database `minimina_<network_id>`, recreated on every `network create`. `mina-archive` gets the network's genesis config (`--config-file`, in both modes; after a hardfork, `hardfork/archive_config.json`): it inserts the genesis block as canonical and records the genesis accounts. It marks later blocks canonical with the `k` its profile was compiled with (devnet, mainnet: 290), not the runtime config's, so a network with a smaller `k` keeps its blocks `pending`. The postgres server is `postgres://postgres:postgres@localhost:5432` unless `MINIMINA_POSTGRES_URI` is set at create time; `psql`, `pg_dump` and `mina-replayer` must be installed.

### mina versions

`minimina mina` downloads the generic packages of a mina version
(`mina-generic`, `mina-archive-generic`, `mina-rosetta-generic`,
`mina-logproc`) and unpacks them with `dpkg-deb -x` into
`~/.minimina/.tools/mina/<version>`, so that versions sit side by side (a
hardfork test runs two). Nothing is installed system-wide and no root is needed.

```bash
minimina mina list --available                 # installed versions, and those of the channel
minimina mina install 4.0.2                    # or 4.0.2-84b8d96, or latest
minimina mina install latest --channel alpha   # a channel of packages.o1test.net; stable by default
minimina mina upgrade                          # install the newest version of the channel
minimina mina uninstall 4.0.2                  # refused while a network runs it, unless --force
minimina mina check 4.0.2                      # what this host lacks to run it

minimina --mina-version 4.0.2 network create -n local --spec net.toml   # implies --mode native
```

- The packages come from https://packages.o1test.net: `--channel` is one of
  its apt components (`stable`, `unstable`, `alpha`, `beta`, ...; an unknown
  one lists those the codename has), for the codename of the host
  (`VERSION_CODENAME` in `/etc/os-release`; `--codename` overrides).
  A version that is missing names the codenames that have it.
- Every deb is checked against the SHA-256 of the repository index. An
  interrupted install leaves no version behind; the next one starts again.
- `--mina-version` takes the binaries of the install, as `--bin-path
  ~/.minimina/.tools/mina/<version>/usr/local/bin` would; the version is
  recorded with the network. The archive schema comes from the same install.
- The host must have the libraries the binaries load (`libssl3`, `libgmp10`,
  `libjemalloc2`, `libpq5`, ...). `mina install` and `mina check` report:
  - `missing_libraries`: what `ldd` finds `not found` in `mina`,
    `mina-archive`, `mina-rosetta`, `mina-create-genesis` and the libp2p
    helper. Such a binary does not load, so `runnable` is false, and native
    `network create`, `network start`, `node start` and `hardfork apply`
    refuse to run it (also for `--bin-path` directories).
  - `missing_packages` and `install_command`: the `Depends` of the packages
    that dpkg has no package (or `Provides`) for. Only advice: the packages
    declare more than the binaries load (`libpq-dev` where `libpq5` is
    enough), and dpkg knows nothing of libraries installed another way.
  - `unchecked`: a check the host has no tool for (`dpkg-query`, `ldd`).

## License

This project is licensed under the [MIT License](LICENSE).
