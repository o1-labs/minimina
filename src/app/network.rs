//! `minimina network ...` handlers.

use super::{setup, Context};
use crate::{
    cli::{CommandWithNetworkId, ExecutionMode, NetworkCommand},
    docker::manager::{ContainerState, DockerManager},
    genesis_ledger::default,
    output::{self, network},
    service::ServiceConfig,
    utils::{fetch_schema, TIMEOUT_IN_SECS},
};
use anyhow::{bail, Context as _, Result};
use log::{error, info, warn};
use std::path::{Path, PathBuf};

pub fn run(ctx: &Context, cmd: NetworkCommand) -> Result<()> {
    match cmd {
        NetworkCommand::Create(cmd) => {
            let network_id = cmd.network_id().to_string();
            let docker = ctx.docker(&network_id);

            // custom keys live in the topology and must match the ledger's accounts
            match (&cmd.topology, &cmd.genesis_ledger) {
                (None, Some(_)) => bail!(
                    "Must provide a topology file with a genesis ledger, keys will be incompatible otherwise."
                ),
                (Some(_), None) => bail!(
                    "Must provide a genesis ledger with a topology file, keys will be incompatible otherwise."
                ),
                _ => {}
            }

            check_setup_network(ctx, &docker, &network_id)?;

            // consume the genesis ledger (and generate keys for the default network)
            let keys = setup::handle_genesis_ledger(ctx, &cmd, &network_id)?;

            // build services from topology file
            let services = setup::handle_topology(ctx, &cmd, &network_id, keys)?;

            // copy libp2p + network keys
            ctx.dirs
                .copy_all_network_keys(&network_id, &services)
                .context("Failed to copy keys")?;

            match ctx.mode {
                ExecutionMode::Docker => {
                    docker
                        .compose_generate_file(&services)
                        .context("Failed to generate docker-compose.yaml")?;
                    create_network(ctx, &docker, &network_id, &services)
                }
                ExecutionMode::Native => {
                    let native = ctx.native(&network_id)?;
                    native
                        .generate_config(&services)
                        .context("Failed to generate native config")?;
                    create_network_native(ctx, &network_id, &services)
                }
            }
        }

        NetworkCommand::Info(cmd) => {
            let network_id = cmd.network_id;
            ctx.ensure_network_exists(&network_id)?;
            let json_data = ctx
                .dirs
                .get_network_info(&network_id)
                .with_context(|| format!("Failed to get info for network '{network_id}'"))?;
            println!("{json_data}");
            Ok(())
        }

        NetworkCommand::Status(cmd) => {
            let network_id = cmd.network_id;
            ctx.ensure_network_exists(&network_id)?;
            let network_path = ctx.dirs.network_path(&network_id);
            let docker = ctx.docker(&network_id);

            let ls_out = docker.compose_ls().with_context(|| {
                format!("Failed to get status from docker compose ls for network '{network_id}'")
            })?;
            let ps_out = docker.compose_ps(None).with_context(|| {
                format!("Failed to get status from docker compose ps for network '{network_id}'")
            })?;

            let compose_file_path = docker.compose_path.to_string_lossy();
            let mut status = network::Status::new(&network_id);
            status.update_from_compose_ls(ls_out, &compose_file_path);
            status.update_from_compose_ps(ps_out);
            status.network_dir = network_path.to_string_lossy().into_owned();

            println!("{status}");
            Ok(())
        }

        NetworkCommand::Delete(cmd) => {
            let network_id = cmd.network_id;
            ctx.ensure_network_exists(&network_id)?;

            // Stop processes/containers first
            match ctx.mode {
                ExecutionMode::Docker => {
                    ctx.docker(&network_id)
                        .compose_down(None, true, true)
                        .with_context(|| format!("Failed to delete network '{network_id}'"))?;
                }
                ExecutionMode::Native => {
                    ctx.native(&network_id)?
                        .destroy()
                        .with_context(|| format!("Failed to delete network '{network_id}'"))?;
                }
            }

            ctx.dirs
                .delete_network_directory(&network_id)
                .with_context(|| {
                    format!("Failed to delete network directory for '{network_id}'")
                })?;
            println!("{}", network::Delete { network_id });
            Ok(())
        }

        NetworkCommand::List => {
            let networks = ctx
                .dirs
                .list_network_directories()
                .context("Failed to list networks")?;
            let mut list = network::List::new();
            if !networks.is_empty() {
                list.update(networks, &ctx.dirs.base_path.to_string_lossy());
            }
            println!("{list}");
            Ok(())
        }

        NetworkCommand::Start(cmd) => {
            let network_id = cmd.network_id().to_string();
            ctx.ensure_network_exists(&network_id)?;
            if let Err(e) = ctx.dirs.check_genesis_timestamp(&network_id) {
                warn!("{e} In case network is unstable consider updating by running 'network create' again.");
            }

            match ctx.mode {
                ExecutionMode::Docker => {
                    let output = ctx
                        .docker(&network_id)
                        .compose_start_all()
                        .with_context(|| format!("Failed to start network '{network_id}'"))?;
                    if cmd.verbose {
                        println!("Status: {}", output.status);
                        println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
                        println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
                    }
                }
                ExecutionMode::Native => {
                    let services = ctx.dirs.get_services_info(&network_id)?;
                    ctx.native(&network_id)?
                        .start_all(&services, &network_id)
                        .with_context(|| format!("Failed to start network '{network_id}'"))?;
                }
            }
            println!("{}", network::Start { network_id });
            Ok(())
        }

        NetworkCommand::Stop(cmd) => {
            let network_id = cmd.network_id;
            ctx.ensure_network_exists(&network_id)?;

            match ctx.mode {
                ExecutionMode::Docker => {
                    ctx.docker(&network_id)
                        .compose_stop_all()
                        .with_context(|| format!("Failed to stop network '{network_id}'"))?;
                }
                ExecutionMode::Native => {
                    ctx.native(&network_id)?
                        .stop_all()
                        .with_context(|| format!("Failed to stop network '{network_id}'"))?;
                }
            }
            println!("{}", network::Stop { network_id });
            Ok(())
        }
    }
}

/// If the network exists, its directory is deleted, corresponding docker
/// images are removed, and it is created anew.
/// If the network doesn't exist, the directory structure is created.
fn check_setup_network(ctx: &Context, docker: &DockerManager, network_id: &str) -> Result<()> {
    if ctx.dirs.network_path_exists(network_id) {
        warn!("Network '{network_id}' already exists. Overwriting!");
        docker.compose_down(None, false, false)?;
        ctx.dirs.delete_network_directory(network_id)?;
    }
    // create directory structure for network
    info!("Creating network '{network_id}'.");
    ctx.dirs
        .generate_dir_structure(network_id)
        .with_context(|| {
            format!("Failed to set up network directory structure for '{network_id}'")
        })?;
    Ok(())
}

fn create_network(
    ctx: &Context,
    docker: &DockerManager,
    network_id: &str,
    services: &[ServiceConfig],
) -> Result<()> {
    let output = docker.compose_create(None).with_context(|| {
        format!("Failed to register network '{network_id}' with 'docker compose create'")
    })?;
    if !output.status.success() {
        bail!(
            "Failed to create network '{network_id}' with 'docker compose create': {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    info!("Successfully created docker-compose for network '{network_id}'!");

    // if we have archive node we need to:
    //  - create input file for replayer (for run-replayer command)
    //  - create database and apply schema scripts
    if let Some(archive_node) = ServiceConfig::get_archive_node(services) {
        let network_path = ctx.dirs.network_path(network_id);
        default::LedgerGenerator::generate_replayer_input(&network_path)?;

        // start postgres container
        let postgres_name = format!("postgres-{network_id}");
        let error_message =
            format!("Failed to start postgres container in network '{network_id}'.");
        let out = docker
            .compose_start(vec![&postgres_name])
            .context(error_message.clone())?;
        if !out.status.success() {
            bail!("{error_message}: {}", String::from_utf8_lossy(&out.stderr));
        }
        info!("Successfully started postgres container in network '{network_id}'!");

        // make sure postgres is running
        container_is_running(docker, &postgres_name)?;
        // create database
        docker.exec(&postgres_name, &["createdb", "-U", "postgres", "archive"])?;
        // apply schema scripts
        let scripts = archive_node
            .archive_schema_files
            .as_ref()
            .context("archive node has no schema files")?;
        apply_schema_scripts(docker, &postgres_name, scripts, &network_path)?;
        // stop postgres
        docker.compose_stop(vec![&postgres_name])?;
    }

    save_network_files(ctx, network_id, services);
    Ok(())
}

fn create_network_native(
    ctx: &Context,
    network_id: &str,
    services: &[ServiceConfig],
) -> Result<()> {
    info!("Successfully prepared native network '{network_id}'!");

    // Handle archive node setup with local postgres
    if let Some(archive_node) = ServiceConfig::get_archive_node(services) {
        let network_path = ctx.dirs.network_path(network_id);
        default::LedgerGenerator::generate_replayer_input(&network_path)?;

        // Create database using local psql
        info!("Creating archive database using local postgres...");
        let createdb_out =
            ctx.runner
                .run("createdb".as_ref(), &["-U", "postgres", "archive"], &[])?;
        if !createdb_out.status.success() {
            warn!(
                "createdb may have failed (database might already exist): {}",
                String::from_utf8_lossy(&createdb_out.stderr)
            );
        }

        // Apply schema scripts directly via psql
        if let Some(scripts) = &archive_node.archive_schema_files {
            for script in scripts {
                let file_path = fetch_schema(script, network_path.clone())?;
                info!("Applying schema script: {}", file_path.display());
                let psql_out = ctx.runner.run(
                    "psql".as_ref(),
                    &["-U", "postgres", "-d", "archive", "-f", utf8(&file_path)?],
                    &[],
                )?;
                if !psql_out.status.success() {
                    warn!(
                        "psql schema application may have failed: {}",
                        String::from_utf8_lossy(&psql_out.stderr)
                    );
                }
            }
        }
    }

    save_network_files(ctx, network_id, services);
    Ok(())
}

/// Writes network.json and services.json and prints the network info.
fn save_network_files(ctx: &Context, network_id: &str, services: &[ServiceConfig]) {
    if let Err(e) = ctx.dirs.save_network_info(network_id, services) {
        error!("Error generating network.json: {e}")
    }
    if let Err(e) = ctx.dirs.save_services_info(network_id, services) {
        error!("Error generating services.json: {e}")
    }
    println!("{}", output::generate_network_info(services, network_id));
}

fn container_is_running(docker: &DockerManager, container_name: &str) -> Result<()> {
    for _ in 0..TIMEOUT_IN_SECS {
        let containers = docker.compose_ps(None)?;
        if let Some(container) = docker.filter_container_by_name(containers, container_name)? {
            if container.state == ContainerState::Running {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    bail!("Failed to start container '{container_name}' within {TIMEOUT_IN_SECS}s")
}

/// Applies provided schema `scripts` to the postgres db, `postgres_name`
fn apply_schema_scripts(
    docker: &DockerManager,
    postgres_name: &str,
    scripts: &[String],
    network_path: &Path,
) -> Result<()> {
    // fetch and copy scripts first
    let mut in_container: Vec<(String, PathBuf)> = Vec::new();
    for script in scripts {
        let file_path = fetch_schema(script, network_path.to_path_buf())?;
        let file_name = file_path
            .file_name()
            .with_context(|| format!("schema '{script}' has no file name"))?;
        let docker_file_path = Path::new("/tmp").join(file_name);
        info!("Copying schema script: {}", file_name.to_string_lossy());
        docker.cp(postgres_name, &file_path, &docker_file_path)?;
        in_container.push((file_name.to_string_lossy().into_owned(), docker_file_path));
    }
    // then apply scripts 1 by 1
    for (file_name, docker_file_path) in &in_container {
        info!("Applying schema script: {file_name}");
        docker.exec(
            postgres_name,
            &[
                "psql",
                "-U",
                "postgres",
                "-d",
                "archive",
                "-f",
                utf8(docker_file_path)?,
            ],
        )?;
    }
    Ok(())
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path '{}' is not valid UTF-8", path.display()))
}
