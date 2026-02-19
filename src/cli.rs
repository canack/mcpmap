use crate::error::{McpmapError, Result};
use clap::{Parser, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ScanMode {
    /// Scan only known MCP ports (3000, 8000, 8080, etc.)
    #[default]
    Fast,
    /// Scan specified port range (default 1-65535)
    Full,
    /// Slower scan with randomized timing
    Stealth,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum SchemeMode {
    /// Try HTTPS first, fallback to HTTP
    #[default]
    Both,
    /// HTTPS only
    Https,
    /// HTTP only
    Http,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Detailed output with full information (default)
    #[default]
    Normal,
    /// Wide table format (header/footer to stderr, data to stdout for grep/awk)
    Wide,
}

#[derive(Parser, Debug)]
#[command(name = "mcpmap")]
#[command(author = "canack")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Discover MCP (Model Context Protocol) servers on network ranges")]
#[command(long_about = None)]
pub struct Args {
    /// Target IP, CIDR range, or hostname (e.g., 192.168.1.0/24, 10.0.0.1)
    #[arg(required = true)]
    pub target: String,

    /// Scan mode
    #[arg(short, long, value_enum, default_value = "fast")]
    pub mode: ScanMode,

    /// Port range to scan (e.g., "1-1000" or "80,443,8080")
    #[arg(short, long)]
    pub ports: Option<String>,

    /// Number of concurrent threads (minimum 1)
    #[arg(short, long, default_value = "50")]
    pub threads: usize,

    /// Connection timeout in seconds
    #[arg(long, default_value = "5", value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: u64,

    /// Output as JSON
    #[arg(long, conflicts_with_all = ["output", "wide"])]
    pub json: bool,

    /// Verbose output (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Quiet mode - only show results
    #[arg(short, long)]
    pub quiet: bool,

    /// Maximum number of targets (IP:port combinations) to scan
    #[arg(long, default_value = "1000000")]
    pub max_targets: usize,

    /// Rate limit: maximum requests per second (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub rate_limit: u32,

    /// Enumerate tools on confirmed MCP servers (Stage 5)
    #[arg(long)]
    pub enumerate: bool,

    /// Show all results including unlikely ones
    #[arg(long)]
    pub show_all: bool,

    /// Minimum confidence score to include in results (0-100)
    #[arg(long, default_value = "0", value_parser = clap::value_parser!(u8).range(..=100))]
    pub min_confidence: u8,

    /// Deep probe: try additional endpoints (/sse, /api/mcp, /v1/mcp)
    #[arg(long)]
    pub deep_probe: bool,

    /// Accept invalid TLS certificates (insecure, use with caution)
    #[arg(long)]
    pub insecure: bool,

    /// URL scheme to use for connections
    #[arg(long, value_enum, default_value = "both")]
    pub scheme: SchemeMode,

    /// Output format (normal, wide)
    #[arg(short = 'o', long, value_enum, default_value = "normal")]
    pub output: OutputFormat,

    /// Shortcut for --output wide (grep/awk friendly: header to stderr, data to stdout)
    #[arg(short = 'W', long, conflicts_with = "output")]
    pub wide: bool,

    /// Enable active behavioral probing (Tier 1: metadata-only, safe)
    #[arg(long, default_value_t = false, requires = "enumerate")]
    pub active: bool,

    /// Enable Tier 2: call LOW-risk tools with benign test inputs
    #[arg(long, default_value_t = false, requires = "active")]
    pub probe_tools: bool,

    /// Enable Tier 3: also call MEDIUM-risk tools (requires explicit consent)
    #[arg(long, default_value_t = false, requires = "probe_tools")]
    pub probe_medium: bool,

    /// Show what active probing WOULD do without executing
    #[arg(long, default_value_t = false, requires = "active")]
    pub dry_run: bool,

    /// I accept the risks of active tool probing
    #[arg(long, default_value_t = false)]
    pub i_accept_risk: bool,

    /// Save tool/resource hashes to a pin file
    #[arg(long, value_name = "FILE", conflicts_with = "verify")]
    pub pin: Option<PathBuf>,

    /// Verify current state against a previously saved pin file
    #[arg(long, value_name = "FILE")]
    pub verify: Option<PathBuf>,
}

impl Args {
    /// Get the effective output format
    pub fn get_output_format(&self) -> OutputFormat {
        if self.wide {
            OutputFormat::Wide
        } else {
            self.output
        }
    }

    pub fn get_ports(&self) -> Vec<u16> {
        match &self.ports {
            Some(port_spec) => parse_port_spec(port_spec),
            None => match self.mode {
                ScanMode::Fast => known_mcp_ports(),
                ScanMode::Full | ScanMode::Stealth => (1..=65535).collect(),
            },
        }
    }
}

#[must_use]
pub fn known_mcp_ports() -> Vec<u16> {
    vec![
        80, 443,          // Production (reverse proxy / cloud)
        3000, 3001,       // mcp-http-server, MCP everything server, TS SDK
        3232,             // MCP example-remote-server
        5000, 5001,       // Flask/Python MCP servers
        5678,             // n8n MCP server
        6274, 6277,       // MCP Inspector (client UI + proxy)
        7071,             // Azure Functions MCP
        8000,             // FastMCP Python, Supergateway
        8080,             // mcp-framework SSE, Fly.io, Docker MCP Gateway
        8787,             // Cloudflare Workers (wrangler dev)
        8811,             // Docker MCP Gateway (streaming)
    ]
}

#[must_use]
pub fn parse_port_spec(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2
                && let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>())
            {
                ports.extend(start..=end);
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }
    ports.retain(|&p| p > 0);
    ports.sort();
    ports.dedup();
    ports
}

/// Parse a target string into IP addresses.
/// Accepts CIDR notation, single IP, or hostname.
#[must_use = "parsing result should be used"]
pub fn parse_target(target: &str) -> Result<Vec<IpAddr>> {
    use ipnetwork::IpNetwork;
    use std::str::FromStr;

    // Try parsing as CIDR
    if let Ok(network) = IpNetwork::from_str(target) {
        return Ok(network.iter().collect());
    }

    // Try parsing as single IP
    if let Ok(ip) = IpAddr::from_str(target) {
        return Ok(vec![ip]);
    }

    // Try DNS resolution
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = format!("{}:0", target).to_socket_addrs() {
        let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
        if !ips.is_empty() {
            return Ok(ips);
        }
    }

    Err(McpmapError::TargetParse(target.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_spec_single() {
        assert_eq!(parse_port_spec("80"), vec![80]);
    }

    #[test]
    fn test_parse_port_spec_multiple() {
        assert_eq!(parse_port_spec("80,443,8080"), vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_port_spec_range() {
        assert_eq!(parse_port_spec("80-83"), vec![80, 81, 82, 83]);
    }

    #[test]
    fn test_parse_port_spec_mixed() {
        assert_eq!(parse_port_spec("22,80-82,443"), vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_parse_target_single_ip() {
        let result = parse_target("192.168.1.1").unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_target_cidr() {
        let result = parse_target("192.168.1.0/30").unwrap();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_parse_target_ipv6() {
        let result = parse_target("::1").unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_ipv6());
    }

    #[test]
    fn test_parse_target_ipv6_cidr() {
        let result = parse_target("fe80::/126").unwrap();
        assert_eq!(result.len(), 4);
        assert!(result.iter().all(|ip| ip.is_ipv6()));
    }

    // === Edge case tests ===

    #[test]
    fn test_parse_port_spec_empty() {
        assert_eq!(parse_port_spec(""), Vec::<u16>::new());
    }

    #[test]
    fn test_parse_port_spec_invalid() {
        assert_eq!(parse_port_spec("abc"), Vec::<u16>::new());
    }

    #[test]
    fn test_parse_port_spec_overflow() {
        // 65536 overflows u16
        assert_eq!(parse_port_spec("65536"), Vec::<u16>::new());
    }

    #[test]
    fn test_parse_port_spec_zero() {
        // Port 0 is filtered out (invalid for TCP)
        assert_eq!(parse_port_spec("0"), Vec::<u16>::new());
    }

    #[test]
    fn test_parse_port_spec_whitespace() {
        assert_eq!(parse_port_spec(" 80 , 443 "), vec![80, 443]);
    }

    #[test]
    fn test_parse_port_spec_duplicates() {
        assert_eq!(parse_port_spec("80,80,80"), vec![80]);
    }

    #[test]
    fn test_parse_target_empty() {
        assert!(parse_target("").is_err());
    }

    #[test]
    fn test_parse_target_invalid() {
        assert!(parse_target("not-an-ip-or-host-that-exists.invalid").is_err());
    }
}
