use crate::service::{ServiceConfig, ServiceType};
use std::io;
use std::net::TcpListener;

pub fn check_ports_available(ports: &[u16]) -> io::Result<()> {
    for &port in ports {
        TcpListener::bind(format!("127.0.0.1:{}", port)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("Port {} is already in use", port),
            )
        })?;
    }
    Ok(())
}

pub fn collect_all_ports(services: &[ServiceConfig]) -> Vec<u16> {
    let mut ports = Vec::new();
    for service in services {
        if let Some(client_port) = service.client_port {
            ports.push(client_port);
            ports.push(client_port + 1);
            ports.push(client_port + 2);
            ports.push(client_port + 3);
            ports.push(client_port + 4);
        }
        if let Some(archive_port) = service.archive_port {
            ports.push(archive_port);
        }
        if service.service_type == ServiceType::ArchiveNode {
            ports.push(5432);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_daemon_archive_and_postgres_ports() {
        let services = vec![
            ServiceConfig {
                service_type: ServiceType::Seed,
                client_port: Some(3100),
                ..Default::default()
            },
            ServiceConfig {
                service_type: ServiceType::ArchiveNode,
                client_port: Some(5000),
                archive_port: Some(3086),
                ..Default::default()
            },
            ServiceConfig {
                service_type: ServiceType::SnarkWorker,
                ..Default::default()
            },
        ];
        assert_eq!(
            collect_all_ports(&services),
            vec![3100, 3101, 3102, 3103, 3104, 5000, 5001, 5002, 5003, 5004, 3086, 5432]
        );
    }

    #[test]
    fn reports_port_in_use() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let err = check_ports_available(&[port]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        drop(listener);
        check_ports_available(&[port]).unwrap();
    }
}
