//! `minimina network ...` handlers.

use super::{setup, shutdown_timeout, Context};
use crate::{
    cli::{CommandWithNetworkId, ExecutionMode, NetworkCommand, ShutdownTimeout},
    docker::manager::{ContainerState, DockerManager},
    genesis_ledger::default,
    native::{manager::NativeManager, mina_locator},
    network_meta::NetworkMeta,
    output::{self, network},
    runner::check,
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
            ctx.meta()
                .save(&ctx.dirs.network_path(&network_id))
                .context("Failed to record network mode")?;

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
            let mut status = network::Status::new(&network_id);
            status.network_dir = network_path.to_string_lossy().into_owned();

            if ctx.mode == ExecutionMode::Native {
                status.update_from_processes(&ctx.native(&network_id)?.status()?);
                println!("{status}");
                return Ok(());
            }

            let docker = ctx.docker(&network_id);
            let ls_out = docker.compose_ls().with_context(|| {
                format!("Failed to get status from docker compose ls for network '{network_id}'")
            })?;
            let ps_out = docker.compose_ps(None).with_context(|| {
                format!("Failed to get status from docker compose ps for network '{network_id}'")
            })?;

            let compose_file_path = docker.compose_path.to_string_lossy();
            status.update_from_compose_ls(ls_out, &compose_file_path);
            status.update_from_compose_ps(ps_out);

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
                        .compose_down(None, true)
                        .with_context(|| format!("Failed to delete network '{network_id}'"))?;
                }
                ExecutionMode::Native => {
                    ctx.native(&network_id)?
                        .destroy(shutdown_timeout(&ShutdownTimeout::default()))
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
                        .start_all(
                            &services,
                            &network_id,
                            std::time::Duration::from_secs(cmd.seed_timeout),
                        )
                        .with_context(|| format!("Failed to start network '{network_id}'"))?;
                }
            }
            println!("{}", network::Start { network_id });
            Ok(())
        }

        NetworkCommand::Stop(cmd) => {
            let network_id = cmd.network_id.network_id;
            ctx.ensure_network_exists(&network_id)?;

            match ctx.mode {
                ExecutionMode::Docker => {
                    let out = ctx
                        .docker(&network_id)
                        .compose_stop_all(cmd.timeout.secs)
                        .with_context(|| format!("Failed to stop network '{network_id}'"))?;
                    check(out, &format!("stopping network '{network_id}'"))?;
                }
                ExecutionMode::Native => {
                    ctx.native(&network_id)?
                        .stop_all(shutdown_timeout(&cmd.timeout))
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
        let network_path = ctx.dirs.network_path(network_id);
        // tear down with the mode the old network ran in, not the new one
        match NetworkMeta::load(&network_path)? {
            Some(old) if old.mode == ExecutionMode::Native => {
                NativeManager::new(
                    &network_path,
                    old.bin_path.as_deref().unwrap_or(Path::new("")),
                    old.postgres_uri.as_deref().unwrap_or_default(),
                )
                .stop_all(shutdown_timeout(&ShutdownTimeout::default()))?;
            }
            _ => {
                // volumes hold the old chain and archive data
                check(docker.compose_down(None, true)?, "removing the old network")?;
            }
        }
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

        // make sure postgres is running and accepting connections
        container_is_running(docker, &postgres_name)?;
        postgres_is_ready(docker, &postgres_name)?;
        // create database
        check(
            docker.exec(&postgres_name, &["createdb", "-U", "postgres", "archive"])?,
            "creating the archive database",
        )?;
        // apply schema scripts
        let scripts = archive_node
            .archive_schema_files
            .as_ref()
            .context("archive node has no schema files")?;
        apply_schema_scripts(docker, &postgres_name, scripts, &network_path)?;
        // stop postgres
        check(
            docker.compose_stop(vec![&postgres_name], None)?,
            "stopping postgres",
        )?;
    }

    save_network_files(ctx, network_id, services);
    Ok(())
}

fn create_network_native(
    ctx: &Context,
    network_id: &str,
    services: &[ServiceConfig],
) -> Result<()> {
    if let Some(config) =
        mina_locator::installed_network_config(ctx.runner.as_ref(), ctx.bin_path()?)
    {
        warn!(
            "{} is merged into every config this mina runs with: its fork point, peers and \
             constants override the local network. Use a generic mina build for a clean network.",
            config.display()
        );
    }
    info!("Successfully prepared native network '{network_id}'!");

    // Handle archive node setup with local postgres
    if let Some(archive_node) = ServiceConfig::get_archive_node(services) {
        let network_path = ctx.dirs.network_path(network_id);
        default::LedgerGenerator::generate_replayer_input(&network_path)?;

        // the database belongs to this network, so `create` starts it fresh
        let native = ctx.native(network_id)?;
        let db = native.archive_db_name();
        info!("Creating archive database '{db}' on {}", ctx.postgres_uri);
        let admin = native.maintenance_db_uri();
        for sql in [
            format!("DROP DATABASE IF EXISTS {db}"),
            format!("CREATE DATABASE {db}"),
        ] {
            let out = ctx.runner.run(
                "psql".as_ref(),
                &[&admin, "-v", "ON_ERROR_STOP=1", "-c", &sql],
                &[],
            )?;
            check(out, &sql)?;
        }

        let db_uri = native.archive_db_uri();
        for script in archive_node.archive_schema_files.iter().flatten() {
            let file_path = fetch_schema(script, network_path.clone())?;
            info!("Applying schema script: {}", file_path.display());
            let out = ctx.runner.run(
                "psql".as_ref(),
                &[&db_uri, "-v", "ON_ERROR_STOP=1", "-f", utf8(&file_path)?],
                &[],
            )?;
            check(out, &format!("applying {script}"))?;
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

/// Waits until postgres accepts TCP connections. The image's init phase runs a
/// temporary socket-only server, so a socket check can pass before the restart.
fn postgres_is_ready(docker: &DockerManager, postgres_name: &str) -> Result<()> {
    for _ in 0..TIMEOUT_IN_SECS {
        let out = docker.exec(
            postgres_name,
            &["pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
        )?;
        if out.status.success() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    bail!("postgres '{postgres_name}' not ready within {TIMEOUT_IN_SECS}s")
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
        check(
            docker.cp(postgres_name, &file_path, &docker_file_path)?,
            &format!("copying schema {}", file_name.to_string_lossy()),
        )?;
        in_container.push((file_name.to_string_lossy().into_owned(), docker_file_path));
    }
    // then apply scripts 1 by 1
    for (file_name, docker_file_path) in &in_container {
        info!("Applying schema script: {file_name}");
        let out = docker.exec(
            postgres_name,
            &[
                "psql",
                "-U",
                "postgres",
                "-d",
                "archive",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                utf8(docker_file_path)?,
            ],
        )?;
        check(out, &format!("applying schema {file_name}"))?;
    }
    Ok(())
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path '{}' is not valid UTF-8", path.display()))
}
