use std::net::IpAddr;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IpFamily {
    IPv4,
    IPv6,
}

impl std::fmt::Display for IpFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpFamily::IPv4 => write!(f, "ipv4"),
            IpFamily::IPv6 => write!(f, "ipv6"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedTarget {
    pub ip: IpAddr,
    pub port: u16,
    pub family: IpFamily,
    pub all_ips: Vec<IpAddr>,
}

impl ResolvedTarget {
    pub fn new(ip: IpAddr, port: u16, all_ips: Vec<IpAddr>) -> Self {
        let family = match ip {
            IpAddr::V4(_) => IpFamily::IPv4,
            IpAddr::V6(_) => IpFamily::IPv6,
        };
        Self { ip, port, family, all_ips }
    }

    pub fn as_socket_str(&self) -> String {
        match self.ip {
            IpAddr::V4(v4) => format!("{}:{}", v4, self.port),
            IpAddr::V6(v6) => format!("[{}]:{}", v6, self.port),
        }
    }

    pub fn ips_short(&self) -> String {
        if self.all_ips.len() <= 1 {
            return self.ip.to_string();
        }
        let extra = self.all_ips.len() - 1;
        format!("{} (+{})", self.ip, extra)
    }
}
