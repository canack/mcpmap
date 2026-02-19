use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub ip: IpAddr,
    pub port: u16,
}

impl ScanTarget {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.ip, self.port)
    }

    /// Build HTTP URL for this target with the given path.
    /// Handles IPv6 addresses by wrapping them in brackets.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        self.url_with_scheme("http", path)
    }

    /// Build URL with specified scheme (http or https)
    #[must_use]
    pub fn url_with_scheme(&self, scheme: &str, path: &str) -> String {
        match self.ip {
            IpAddr::V4(v4) => format!("{}://{}:{}{}", scheme, v4, self.port, path),
            IpAddr::V6(v6) => format!("{}://[{}]:{}{}", scheme, v6, self.port, path),
        }
    }

    /// Build HTTPS URL for this target
    #[must_use]
    pub fn https_url(&self, path: &str) -> String {
        self.url_with_scheme("https", path)
    }
}

impl std::fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// Iterator over scan targets - memory efficient for large scans
pub struct TargetIterator<'a> {
    ips: &'a [IpAddr],
    ports: &'a [u16],
    ip_idx: usize,
    port_idx: usize,
}

impl<'a> TargetIterator<'a> {
    pub fn new(ips: &'a [IpAddr], ports: &'a [u16]) -> Self {
        Self {
            ips,
            ports,
            ip_idx: 0,
            port_idx: 0,
        }
    }
}

impl Iterator for TargetIterator<'_> {
    type Item = ScanTarget;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ip_idx >= self.ips.len() {
            return None;
        }

        let target = ScanTarget::new(self.ips[self.ip_idx], self.ports[self.port_idx]);

        self.port_idx += 1;
        if self.port_idx >= self.ports.len() {
            self.port_idx = 0;
            self.ip_idx += 1;
        }

        Some(target)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.ip_idx >= self.ips.len() {
            return (0, Some(0));
        }
        let remaining = (self.ips.len() - self.ip_idx) * self.ports.len() - self.port_idx;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for TargetIterator<'_> {}

/// Generate all scan targets from IP and port lists.
#[must_use]
pub fn generate_targets(ips: &[IpAddr], ports: &[u16]) -> Vec<ScanTarget> {
    TargetIterator::new(ips, ports).collect()
}

pub fn shuffle_targets(targets: &mut [ScanTarget]) {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    targets.shuffle(&mut rng);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_url() {
        let target = ScanTarget::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(target.url("/mcp"), "http://192.168.1.1:8080/mcp");
    }

    #[test]
    fn test_ipv6_url() {
        let target = ScanTarget::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        assert_eq!(target.url("/mcp"), "http://[::1]:8080/mcp");
    }

    #[test]
    fn test_ipv6_full_url() {
        let target = ScanTarget::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            3000,
        );
        assert_eq!(target.url("/"), "http://[2001:db8::1]:3000/");
    }

    #[test]
    fn test_socket_addr() {
        let target = ScanTarget::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);
        let addr = target.socket_addr();
        assert_eq!(addr.to_string(), "127.0.0.1:3000");
    }

    #[test]
    fn test_display() {
        let target = ScanTarget::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        assert_eq!(target.to_string(), "10.0.0.1:443");
    }

    #[test]
    fn test_generate_targets() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        ];
        let ports = vec![80, 443];
        let targets = generate_targets(&ips, &ports);
        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn test_target_iterator_size_hint() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        ];
        let ports = vec![80, 443, 8080];
        let iter = TargetIterator::new(&ips, &ports);
        assert_eq!(iter.len(), 6);
    }
}
