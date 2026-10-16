//! `minimina node ...` handlers.

use super::{shutdown_timeout, Context};
use crate::{
    cli::{
        CommandWithNetworkId, CommandWithNodeId, ExecutionMode, NodeCommand, StartNodeCommandArgs,
    },
    directory_manager::NETWORK_KEYPAIRS,
    docker::manager::ContainerState,
    genesis_ledger::{self, REPLAYER_INPUT_JSON},
    graphql::GraphQl,
    output::{self, node},
    runner::check,
    service::ServiceConfig,
};
use anyhow::{bail, Context as _, Result};
use log::{info, warn};
use std::process::Output;

pub fn run(ctx: &Context, cmd: NodeCommand) -> Result<()> {
    match cmd {
        NodeCommand::Start(cmd) => {
            let node_id = cmd.node_args.node_id().to_string();
            let network_id = cmd.node_args.network_id().to_string();

            let stdout = match ctx.mode {
                ExecutionMode::Docker => start_docker(ctx, &cmd, &node_id, &network_id)?,
                ExecutionMode::Native => {
                    start_native(ctx, &cmd, &node_id, &network_id)
                        .with_context(|| format!("Failed to start node '{node_id}'"))?;
                    String::new()
                }
            };

            if cmd.graphql_filtered_logs {
                warn!("Waiting for graphql server to be operational so I can request filtered logs. This can take a moment...");
                let gql = GraphQl::new(ctx.dirs.clone());
                if let Some(gql_ep) = gql.get_endpoint(&node_id, &network_id)? {
                    gql.wait_for_server(&gql_ep)?;
                    gql.request_filtered_logs(&gql_ep)?;
                }
            }

            if cmd.node_args.raw_output {
                println!("Node '{node_id}' on network '{network_id}' has been started. {stdout}");
            } else {
                println!(
                    "{}",
                    node::Start {
                        node_id,
                        network_id,
                    }
                )
            }
            Ok(())
        }

        NodeCommand::Stop(cmd) => {
            let node_id = cmd.node_args.node_id().to_string();
            let network_id = cmd.node_args.network_id().to_string();

            let stdout = match ctx.mode {
                ExecutionMode::Docker => {
                    let container = format!("{node_id}-{network_id}");
                    let out = ctx
                        .docker(&network_id)
                        .compose_stop(vec![&container], cmd.timeout.secs)
                        .with_context(|| format!("Failed to stop node '{node_id}'"))?;
                    if !out.status.success() {
                        bail!(
                            "Failed to stop node '{node_id}': {}",
                            String::from_utf8_lossy(&out.stderr)
                        );
                    }
                    String::from_utf8_lossy(&out.stdout).into_owned()
                }
                ExecutionMode::Native => {
                    ctx.native(&network_id)?
                        .stop_service(&node_id, shutdown_timeout(&cmd.timeout))
                        .with_context(|| format!("Failed to stop node '{node_id}'"))?;
                    String::new()
                }
            };

            if cmd.node_args.raw_output {
                println!("Node '{node_id}' on network '{network_id}' has been stopped. {stdout}");
            } else {
                println!(
                    "{}",
                    node::Stop {
                        node_id,
                        network_id,
                    }
                )
            }
            Ok(())
        }

        NodeCommand::Logs(cmd) => {
            let node_id = cmd.node_id();
            let network_id = cmd.network_id();

            let logs = match ctx.mode {
                ExecutionMode::Docker => {
                    let services = ctx
                        .dirs
                        .get_services_info(network_id)
                        .context("Failed to get services info")?;
                    let output = ctx
                        .docker(network_id)
                        .run_docker_logs(node_id, network_id)
                        .with_context(|| format!("Error while running 'docker logs {node_id}'"))?;
                    if !output.status.success() {
                        bail!(
                            "Failed to get logs for '{node_id}' on '{network_id}': {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    info!("Successfully got logs for '{node_id}' on '{network_id}'");
                    // the uptime service backend logs to stderr
                    let out = if is_uptime_service(&services, node_id) {
                        &output.stderr
                    } else {
                        &output.stdout
                    };
                    String::from_utf8_lossy(out).into_owned()
                }
                ExecutionMode::Native => ctx
                    .native(network_id)?
                    .service_logs(node_id)
                    .with_context(|| format!("Error getting logs for '{node_id}'"))?,
            };

            if cmd.raw_output {
                println!("{logs}");
            } else {
                println!(
                    "{}",
                    output::node::Logs {
                        logs,
                        network_id: network_id.into(),
                        node_id: node_id.into(),
                    }
                )
            }
            Ok(())
        }

        NodeCommand::DumpArchiveData(cmd) => {
            let network_id = cmd.network_id();
            let node_id = cmd.node_id();
            ctx.ensure_network_exists(network_id)?;
            ensure_archive_node(ctx, network_id, node_id)?;

            let context = format!("archive data for node '{node_id}', network '{network_id}'");
            let output = match ctx.mode {
                ExecutionMode::Docker => {
                    ctx.docker(network_id).compose_dump_archive_data(network_id)
                }
                ExecutionMode::Native => {
                    let db_uri = ctx.native(network_id)?.archive_db_uri();
                    ctx.runner
                        .run("pg_dump".as_ref(), &["--insert", &db_uri], &[])
                }
            }
            .with_context(|| format!("Error while dumping {context}"))?;
            let output = check(output, &format!("dumping {context}"))?;

            info!("Successfully dumped {context}");
            if cmd.raw_output {
                println!("{}", String::from_utf8_lossy(&output.stdout));
            } else {
                println!(
                    "{}",
                    output::node::ArchiveData {
                        data: String::from_utf8_lossy(&output.stdout).into(),
                        network_id: network_id.into(),
                        node_id: node_id.into(),
                    }
                )
            }
            Ok(())
        }

        NodeCommand::DumpPrecomputedBlocks(cmd) => {
            let node_id = cmd.node_id();
            let network_id = cmd.network_id();
            ctx.ensure_network_exists(network_id)?;

            let context = format!("precomputed blocks for '{node_id}' on '{network_id}'");
            let blocks = match ctx.mode {
                ExecutionMode::Docker => {
                    let output = ctx
                        .docker(network_id)
                        .compose_dump_precomputed_blocks(node_id, network_id)
                        .with_context(|| format!("Failed to dump {context}"))?;
                    let output = check(output, &format!("dumping {context}"))?;
                    String::from_utf8_lossy(&output.stdout).into_owned()
                }
                ExecutionMode::Native => ctx
                    .native(network_id)?
                    .precomputed_blocks(node_id)
                    .with_context(|| format!("Failed to dump {context}"))?,
            };

            info!("Successfully dumped {context}");
            if cmd.raw_output {
                println!("{blocks}");
            } else {
                println!(
                    "{}",
                    output::node::PrecomputedBlocks {
                        blocks,
                        network_id: network_id.into(),
                        node_id: node_id.into(),
                    }
                )
            }
            Ok(())
        }

        NodeCommand::RunReplayer(cmd) => {
            let start_slot = cmd.start_slot_since_genesis;
            let node_id = cmd.node_args.node_id();
            let network_id = cmd.node_args.network_id();
            ctx.ensure_network_exists(network_id)?;
            ensure_archive_node(ctx, network_id, node_id)?;

            let context = format!(
                "node '{node_id}' on network '{network_id}' and start_slot_since_genesis '{start_slot}'"
            );
            let network_path = ctx.dirs.network_path(network_id);
            genesis_ledger::set_slot_since_genesis(&network_path, start_slot)
                .with_context(|| format!("Failed to set slot since genesis for {context}"))?;

            let output = match ctx.mode {
                ExecutionMode::Docker => ctx
                    .docker(network_id)
                    .compose_run_replayer(&format!("{node_id}-service"), network_id),
                ExecutionMode::Native => run_replayer_native(ctx, network_id),
            }
            .with_context(|| format!("Error while running replayer for {context}"))?;
            let output = check(output, &format!("running replayer for {context}"))?;

            info!("Successfully ran replayer for {context}");
            if cmd.node_args.raw_output {
                println!("{}", String::from_utf8_lossy(&output.stdout));
            } else {
                println!(
                    "{}",
                    output::node::ReplayerLogs {
                        logs: String::from_utf8_lossy(&output.stdout).into(),
                        network_id: network_id.into(),
                        node_id: node_id.into(),
                    }
                )
            }
            Ok(())
        }
    }
}

/// Starts the node's container; returns `docker compose start` stdout.
fn start_docker(
    ctx: &Context,
    cmd: &StartNodeCommandArgs,
    node_id: &str,
    network_id: &str,
) -> Result<String> {
    let container = format!("{node_id}-{network_id}");
    let docker = ctx.docker(network_id);
    let start_error = |e: &dyn std::fmt::Display| format!("Failed to start node '{node_id}': {e}");

    let nodes = docker.compose_ps(None)?;
    match docker.filter_container_by_name(nodes, &container)? {
        Some(node) => match node.state {
            ContainerState::Running => {
                warn!("Node '{node_id}' is already running in network '{network_id}'.")
            }
            ContainerState::Created => {
                info!("Starting node '{node_id}' in network '{network_id}' for the first time.")
            }
            state => info!("Node '{node_id}' is {state} in network '{network_id}'."),
        },
        None => bail!(start_error(&format!(
            "Node '{node_id}' does not exist in network '{network_id}'."
        ))),
    }

    if cmd.fresh_state {
        info!("Starting node '{node_id}' in network '{network_id}' with fresh state.");
        docker.compose_down(Some(container.clone()), true)?;
        docker.compose_create(Some(container.clone()))?;
    }

    if cmd.import_accounts {
        warn!("Importing accounts for node '{node_id}' in network '{network_id}'. This can take a moment...");
        import_all_accounts(ctx, network_id, node_id, |file| {
            docker.compose_import_account(node_id, network_id, file)
        })?;
    }

    let out = docker
        .compose_start(vec![&container])
        .map_err(|e| anyhow::anyhow!(start_error(&e)))?;
    if !out.status.success() {
        bail!(start_error(&String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn start_native(
    ctx: &Context,
    cmd: &StartNodeCommandArgs,
    node_id: &str,
    network_id: &str,
) -> Result<()> {
    ctx.ensure_network_exists(network_id)?;
    let services = ctx.dirs.get_services_info(network_id)?;
    let service = services
        .iter()
        .find(|s| s.service_name == node_id)
        .with_context(|| format!("Node '{node_id}' does not exist in network '{network_id}'."))?;
    let native = ctx.native(network_id)?;

    if cmd.fresh_state {
        info!("Starting node '{node_id}' in network '{network_id}' with fresh state.");
        native.reset_state(node_id)?;
    }

    if cmd.import_accounts {
        warn!("Importing accounts for node '{node_id}' in network '{network_id}'. This can take a moment...");
        let mina = native.bin_path.join("mina");
        let keys_dir = ctx.dirs.network_path(network_id).join(NETWORK_KEYPAIRS);
        let config_dir = native.config_dir_for_service(node_id);
        import_all_accounts(ctx, network_id, node_id, |file| {
            ctx.runner.run(
                mina.as_os_str(),
                &[
                    "accounts",
                    "import",
                    "--privkey-path",
                    &keys_dir.join(file).to_string_lossy(),
                    "--config-directory",
                    &config_dir.to_string_lossy(),
                ],
                &[("MINA_PRIVKEY_PASS", "naughty blue worm")],
            )
        })?;
    }

    Ok(native.start_service(service, network_id)?)
}

fn run_replayer_native(ctx: &Context, network_id: &str) -> std::io::Result<Output> {
    let native = ctx
        .native(network_id)
        .map_err(|e| std::io::Error::other(format!("{e:#}")))?;
    let input = ctx.dirs.network_path(network_id).join(REPLAYER_INPUT_JSON);
    ctx.runner.run(
        native.bin_path.join("mina-replayer").as_os_str(),
        &[
            "--continue-on-error",
            "--input-file",
            &input.to_string_lossy(),
            "--archive-uri",
            &native.archive_db_uri(),
            "--output-file",
            "/dev/null",
        ],
        &[],
    )
}

fn ensure_archive_node(ctx: &Context, network_id: &str, node_id: &str) -> Result<()> {
    let services = ctx
        .dirs
        .get_services_info(network_id)
        .context("Failed to get services info")?;
    let is_archive = ServiceConfig::get_archive_node(&services)
        .is_some_and(|archive| archive.service_name == node_id);
    if !is_archive {
        bail!("Node '{node_id}' is not an archive node in '{network_id}' network.");
    }
    Ok(())
}

fn is_uptime_service(services: &[ServiceConfig], node_id: &str) -> bool {
    ServiceConfig::get_uptime_service_backend(services)
        .is_some_and(|uptime| uptime.service_name == node_id)
}

/// Imports every network keypair into the node with `import`.
fn import_all_accounts(
    ctx: &Context,
    network_id: &str,
    node_id: &str,
    import: impl Fn(&str) -> std::io::Result<Output>,
) -> Result<()> {
    for account_file in ctx.dirs.get_network_keypair_files(network_id)? {
        let failure = || {
            format!(
                "Failed to import account from file '{account_file}' \
                 for node '{node_id}' on network '{network_id}'"
            )
        };
        let output = import(&account_file).with_context(failure)?;
        if !output.status.success() {
            bail!("{}: {}", failure(), String::from_utf8_lossy(&output.stderr));
        }
        info!(
            "Successfully imported account from file '{account_file}' \
             for node '{node_id}' on network '{network_id}'"
        );
    }
    Ok(())
}
