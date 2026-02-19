use std::net::AddrParseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum McpmapError {
    #[error("Invalid target: {0}")]
    TargetParse(String),

    #[error("Invalid IP address: {0}")]
    InvalidIp(#[from] AddrParseError),

    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(#[from] ipnetwork::IpNetworkError),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Pin file error: {0}")]
    PinFile(String),
}

pub type Result<T> = std::result::Result<T, McpmapError>;
