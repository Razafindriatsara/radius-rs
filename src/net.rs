//! IP-Netze in CIDR-Schreibweise (z.B. `10.0.0.0/8`, `2001:db8::/32`) für die
//! Zuordnung von NAS-Clients, wie bei FreeRADIUS (`ipaddr = 10.0.0.0/8`).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ungültige Adresse '{}' (erwartet z.B. 192.168.1.10 oder 192.168.1.0/24)",
            self.0
        )
    }
}

impl std::error::Error for ParseError {}

impl IpNet {
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(*ip) & mask)
            }
            // IPv4-Client über IPv6-Socket (::ffff:a.b.c.d)
            (IpAddr::V4(_), IpAddr::V6(v6)) => v6.to_ipv4_mapped().is_some_and(|v4| self.contains(&IpAddr::V4(v4))),
            _ => false,
        }
    }
}

impl FromStr for IpNet {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseError(s.to_string());
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.trim().parse().map_err(|_| err())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| err())?,
            None => max,
        };
        if prefix > max {
            return Err(err());
        }
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn single_address() {
        let n: IpNet = "192.168.1.10".parse().unwrap();
        assert_eq!(n.prefix(), 32);
        assert!(n.contains(&ip("192.168.1.10")));
        assert!(!n.contains(&ip("192.168.1.11")));
    }

    #[test]
    fn ipv4_networks() {
        let n: IpNet = "172.28.0.0/16".parse().unwrap();
        assert!(n.contains(&ip("172.28.5.3")));
        assert!(!n.contains(&ip("172.29.0.1")));
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(&ip("8.8.8.8")));
    }

    #[test]
    fn ipv6_and_mapped() {
        let n: IpNet = "2001:db8::/32".parse().unwrap();
        assert!(n.contains(&ip("2001:db8:1::5")));
        assert!(!n.contains(&ip("2001:db9::1")));
        let v4: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(v4.contains(&ip("::ffff:10.1.2.3")));
        assert!(!v4.contains(&ip("2001:db8::1")));
    }

    #[test]
    fn rejects_invalid() {
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("kein-ip".parse::<IpNet>().is_err());
        assert!("10.0.0.0/x".parse::<IpNet>().is_err());
    }
}
