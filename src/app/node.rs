//! `minimina node ...` handlers.

use super::Context;
use crate::{
    cli::{CommandWithNetworkId, CommandWithNodeId, ExecutionMode, NodeCommand},
    docker::manager::{ContainerState, DockerManager},
    genesis_ledger,
    graphql::GraphQl,
    output::{self, node},
    service::ServiceConfig,
};
use anyhow::{bail, Context as _, Result};
use log::{info, warn};

pub fn run(ctx: &Context, cmd: NodeCommand) -> Result<()> {
    match cmd {
        NodeCommand::Start(cmd) => {
            let node_id = cmd.node_args.node_id().to_string();
            let network_id = cmd.node_args.network_id().to_string();
            let container = format!("{node_id}-{network_id}");
            let docker = ctx.docker(&network_id);
            let start_error =
                |e: &dyn std::fmt::Display| format!("Failed to start node '{node_id}': {e}");

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
                docker.compose_down(Some(container.clone()), true, false)?;
                docker.compose_create(Some(container.clone()))?;
            }

            if cmd.import_accounts {
                warn!("Importing accounts for node '{node_id}' in network '{network_id}'. This can take a moment...");
                import_all_accounts(ctx, &docker, &node_id, &network_id)?;
            }

            let out = docker
                .compose_start(vec![&container])
                .map_err(|e| anyhow::anyhow!(start_error(&e)))?;
            if !out.status.success() {
                bail!(start_error(&String::from_utf8_lossy(&out.stderr)));
            }

            if cmd.graphql_filtered_logs {
                warn!("Waiting for graphql server to be operational so I can request filtered logs. This can take a moment...");
                let gql = GraphQl::new(ctx.dirs.clone());
                if let Some(gql_ep) = gql.get_endpoint(&node_id, &network_id)? {
                    gql.wait_for_server(&gql_ep)?;
                    gql.request_filtered_logs(&gql_ep)?;
                }
            }

            if cmd.node_args.raw_output {
                println!(
                    "Node '{node_id}' on network '{network_id}' has been started. {}",
                    String::from_utf8_lossy(&out.stdout)
                );
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
            let node_id = cmd.node_id().to_string();
            let network_id = cmd.network_id().to_string();
            let container = format!("{node_id}-{network_id}");

            let out = ctx
                .docker(&network_id)
                .compose_stop(vec![&container])
                .with_context(|| format!("Failed to stop node '{node_id}'"))?;
            if !out.status.success() {
                bail!(
                    "Failed to stop node '{node_id}': {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }

            if cmd.raw_output {
                println!(
                    "Node '{node_id}' on network '{network_id}' has been stopped. {}",
                    String::from_utf8_lossy(&out.stdout)
                );
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

            let output = ctx
                .docker(network_id)
                .compose_dump_archive_data(network_id)
                .with_context(|| {
                    format!("Error while dumping archive data for node '{node_id}', network_id '{network_id}'")
                })?;
            if !output.status.success() {
                bail!(
                    "Failed to dump archive data for node '{node_id}', network '{network_id}': {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            info!("Successfully dumped archive data for node '{node_id}', network '{network_id}'");
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

            let output = ctx
                .docker(network_id)
                .compose_dump_precomputed_blocks(node_id, network_id)
                .with_context(|| {
                    format!("Failed to dump precomputed blocks for '{node_id}' on '{network_id}'")
                })?;
            if !output.status.success() {
                bail!(
                    "Failed to dump precomputed blocks for '{node_id}' on '{network_id}': {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            info!("Successfully dumped precomputed blocks for '{node_id}' on '{network_id}'");
            if cmd.raw_output {
                println!("{}", String::from_utf8_lossy(&output.stdout));
            } else {
                println!(
                    "{}",
                    output::node::PrecomputedBlocks {
                        blocks: String::from_utf8_lossy(&output.stdout).into(),
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
            genesis_ledger::set_slot_since_genesis(&ctx.dirs.network_path(network_id), start_slot)
                .with_context(|| format!("Failed to set slot since genesis for {context}"))?;

            let archive_service_id = format!("{node_id}-service");
            let output = ctx
                .docker(network_id)
                .compose_run_replayer(&archive_service_id, network_id)
                .with_context(|| format!("Error while running replayer for {context}"))?;
            if !output.status.success() {
                bail!(
                    "Failed to run replayer for {context}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
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

fn import_all_accounts(
    ctx: &Context,
    docker: &DockerManager,
    node_id: &str,
    network_id: &str,
) -> Result<()> {
    for account_file in ctx.dirs.get_network_keypair_files(network_id)? {
        let failure = || {
            format!(
                "Failed to import account from file '{account_file}' \
                 for node '{node_id}' on network '{network_id}'"
            )
        };
        let output = docker
            .compose_import_account(node_id, network_id, &account_file)
            .with_context(failure)?;
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
