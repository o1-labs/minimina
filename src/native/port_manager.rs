//! Port checks for native networks, where every node shares the host's ports.

use crate::service::{ServiceConfig, ServiceType};
use std::collections::HashMap;
use std::io;
use std::net::TcpListener;

/// A port a service will listen on.
#[derive(Debug, Clone, PartialEq)]
pub struct PortUse {
    pub port: u16,
    pub service: String,
}

/// Fails if two services claim the same port or a port is already bound on the host.
///
/// mina listens on all interfaces, so the probe binds `0.0.0.0`.
pub fn check_ports_available(ports: &[PortUse]) -> io::Result<()> {
    let mut owners: HashMap<u16, &str> = HashMap::new();
    for PortUse { port, service } in ports {
        if let Some(other) = owners.insert(*port, service) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("Port {port} is used by both '{other}' and '{service}'"),
            ));
        }
    }
    for PortUse { port, service } in ports {
        TcpListener::bind(("0.0.0.0", *port)).map_err(|e| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("Port {port} needed by '{service}' is not available: {e}"),
            )
        })?;
    }
    Ok(())
}

/// Ports used by `services`: five per daemon (client, REST, external, metrics,
/// libp2p metrics) and the archive server port.
pub fn collect_all_ports(services: &[ServiceConfig]) -> io::Result<Vec<PortUse>> {
    let mut ports = Vec::new();
    for service in services {
        let mut add = |port: u16| {
            ports.push(PortUse {
                port,
                service: service.service_name.clone(),
            })
        };
        match service.service_type {
            ServiceType::SnarkWorker | ServiceType::UptimeServiceBackend => {}
            // one port: the API
            ServiceType::Rosetta | ServiceType::ArchiveNodeApi => {
                add(service.client_port.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("'{}' has no client_port", service.service_name),
                    )
                })?)
            }
            _ => {
                let client_port = service.client_port.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("daemon '{}' has no client_port", service.service_name),
                    )
                })?;
                for offset in 0..5 {
                    let port = client_port.checked_add(offset).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "client_port {client_port} of '{}' leaves no room for 5 ports",
                                service.service_name
                            ),
                        )
                    })?;
                    add(port);
                }
            }
        }
        if let Some(archive_port) = service.archive_port {
            add(archive_port);
        }
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(name: &str, ty: ServiceType, client: Option<u16>) -> ServiceConfig {
        ServiceConfig {
            service_name: name.into(),
            service_type: ty,
            client_port: client,
            ..Default::default()
        }
    }

    fn ports(uses: &[PortUse]) -> Vec<u16> {
        uses.iter().map(|u| u.port).collect()
    }

    #[test]
    fn collects_daemon_and_archive_ports() {
        let mut archive = svc("arch", ServiceType::ArchiveNode, Some(5000));
        archive.archive_port = Some(3086);
        let services = vec![
            svc("seed", ServiceType::Seed, Some(3100)),
            archive,
            svc("w", ServiceType::SnarkWorker, None),
        ];
        let uses = collect_all_ports(&services).unwrap();
        assert_eq!(
            ports(&uses),
            vec![3100, 3101, 3102, 3103, 3104, 5000, 5001, 5002, 5003, 5004, 3086]
        );
        assert_eq!(uses[10].service, "arch");
    }

    #[test]
    fn daemon_without_client_port_is_rejected() {
        let err = collect_all_ports(&[svc("bp", ServiceType::BlockProducer, None)]).unwrap_err();
        assert!(err.to_string().contains("'bp' has no client_port"));
        let err =
            collect_all_ports(&[svc("bp", ServiceType::BlockProducer, Some(65534))]).unwrap_err();
        assert!(err.to_string().contains("no room"));
    }

    #[test]
    fn overlapping_services_are_rejected() {
        let services = vec![
            svc("a", ServiceType::Seed, Some(40000)),
            svc("b", ServiceType::BlockProducer, Some(40003)),
        ];
        let err = check_ports_available(&collect_all_ports(&services).unwrap()).unwrap_err();
        assert_eq!(err.to_string(), "Port 40003 is used by both 'a' and 'b'");
    }

    #[test]
    fn reports_port_in_use_on_any_interface() {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let used = [PortUse {
            port,
            service: "x".into(),
        }];
        let err = check_ports_available(&used).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(err.to_string().contains("needed by 'x'"));
        drop(listener);
    }
}
