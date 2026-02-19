use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

pub async fn check_port(addr: SocketAddr, timeout_duration: Duration) -> PortStatus {
    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortStatus::Open,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                PortStatus::Filtered
            }
        }
        Err(_) => PortStatus::Filtered,
    }
}
