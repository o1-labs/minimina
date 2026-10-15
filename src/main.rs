use clap::Parser;
use env_logger::{Builder, Env};
use minimina::cli::{Cli, DefaultLogLevel};
use minimina::{app, output};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    Builder::from_env(Env::default().default_filter_or(cli.command.log_level())).init();

    match app::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let error_message = format!("{e:#}");
            log::error!("{error_message}");
            println!("{}", output::Error { error_message });
            ExitCode::FAILURE
        }
    }
}
