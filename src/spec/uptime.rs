use std::path::PathBuf;

/// The configuration of the uptime service backend, copied to
/// `uptime_service_config/` in the network directory, where the container
/// reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct UptimeFiles {
    /// The backend's app config (`CONFIG_FILE`).
    pub app_config: PathBuf,
    /// Google credentials of its sheets (`GOOGLE_APPLICATION_CREDENTIALS`).
    pub minasheets: PathBuf,
    /// Other files the app config names.
    pub config_files: Vec<PathBuf>,
}
