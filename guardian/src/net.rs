//! Source-address allowlisting for the UDP receive path.
//!
//! Mirrors the ADR-296 posture the sensing server takes: the receiver binds to
//! loopback unless an operator explicitly widens it, and a routable bind must
//! come with an allowlist so an unauthenticated broadcast on the LAN cannot
//! inject vitals. The packets carry no authentication of any kind, so the
//! source address is the only boundary available.

use std::net::IpAddr;

/// A parsed IP or CIDR entry.
#[derive(Debug, Clone, Copy)]
pub struct AllowEntry {
    network: IpAddr,
    prefix_len: u8,
}

impl AllowEntry {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        let (addr_part, prefix_part) = match spec.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (spec, None),
        };

        let network: IpAddr = addr_part
            .parse()
            .map_err(|_| format!("`{spec}`: not a valid IP address"))?;

        let max_prefix = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_part {
            None => max_prefix,
            Some(p) => {
                let n: u8 = p
                    .parse()
                    .map_err(|_| format!("`{spec}`: prefix length must be a number"))?;
                if n > max_prefix {
                    return Err(format!("`{spec}`: prefix length must be <= {max_prefix}"));
                }
                n
            }
        };

        Ok(Self {
            network,
            prefix_len,
        })
    }

    fn contains(&self, addr: IpAddr) -> bool {
        fn masked(bytes: &[u8], prefix_len: u8) -> Vec<u8> {
            let mut out = bytes.to_vec();
            for (i, byte) in out.iter_mut().enumerate() {
                let bit = (i as u32) * 8;
                let keep = (prefix_len as u32).saturating_sub(bit).min(8);
                *byte &= if keep == 0 {
                    0
                } else {
                    (0xFFu16 << (8 - keep)) as u8
                };
            }
            out
        }

        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                masked(&net.octets(), self.prefix_len) == masked(&a.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                masked(&net.octets(), self.prefix_len) == masked(&a.octets(), self.prefix_len)
            }
            // An IPv4-mapped IPv6 source matches an IPv4 rule; a dual-stack
            // socket reports LAN nodes that way.
            (IpAddr::V4(_), IpAddr::V6(a)) => match a.to_ipv4_mapped() {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

/// The set of sources permitted to send vitals.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    entries: Vec<AllowEntry>,
}

impl Allowlist {
    pub fn parse(specs: &[String]) -> Result<Self, String> {
        let mut entries = Vec::new();
        for spec in specs {
            for part in spec.split(',').filter(|p| !p.trim().is_empty()) {
                entries.push(AllowEntry::parse(part)?);
            }
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `addr` may send us packets. Loopback is always allowed, and an
    /// empty allowlist allows everything — which is only reachable on a
    /// loopback bind or under the explicit insecure-LAN opt-in.
    pub fn permits(&self, addr: IpAddr) -> bool {
        if addr.is_loopback() {
            return true;
        }
        if self.entries.is_empty() {
            return true;
        }
        self.entries.iter().any(|e| e.contains(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_allowlist_permits_everything() {
        let a = Allowlist::default();
        assert!(a.is_empty());
        assert!(a.permits(ip("192.168.1.50")));
    }

    #[test]
    fn loopback_is_always_permitted() {
        let a = Allowlist::parse(&["10.0.0.0/8".into()]).unwrap();
        assert!(a.permits(ip("127.0.0.1")));
        assert!(a.permits(ip("::1")));
    }

    #[test]
    fn cidr_matches_only_inside_the_network() {
        let a = Allowlist::parse(&["192.168.1.0/24".into()]).unwrap();
        assert!(a.permits(ip("192.168.1.1")));
        assert!(a.permits(ip("192.168.1.255")));
        assert!(!a.permits(ip("192.168.2.1")));
        assert!(!a.permits(ip("10.0.0.1")));
    }

    #[test]
    fn non_byte_aligned_prefixes_are_masked_correctly() {
        let a = Allowlist::parse(&["10.1.2.0/23".into()]).unwrap();
        assert!(a.permits(ip("10.1.2.7")));
        assert!(a.permits(ip("10.1.3.200")));
        assert!(!a.permits(ip("10.1.4.1")));

        let b = Allowlist::parse(&["192.168.0.0/12".into()]).unwrap();
        assert!(b.permits(ip("192.160.0.1")));
        assert!(!b.permits(ip("192.176.0.1")));
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let a = Allowlist::parse(&["10.0.0.5".into()]).unwrap();
        assert!(a.permits(ip("10.0.0.5")));
        assert!(!a.permits(ip("10.0.0.6")));
    }

    #[test]
    fn comma_separated_and_repeated_specs_both_work() {
        let a =
            Allowlist::parse(&["10.0.0.5,192.168.1.0/24".into(), "172.16.0.0/16".into()]).unwrap();
        assert!(a.permits(ip("10.0.0.5")));
        assert!(a.permits(ip("192.168.1.9")));
        assert!(a.permits(ip("172.16.5.5")));
        assert!(!a.permits(ip("8.8.8.8")));
    }

    #[test]
    fn ipv4_mapped_sources_match_ipv4_rules() {
        let a = Allowlist::parse(&["192.168.1.0/24".into()]).unwrap();
        assert!(a.permits(ip("::ffff:192.168.1.10")));
        assert!(!a.permits(ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn ipv6_prefixes_work() {
        let a = Allowlist::parse(&["fd00::/8".into()]).unwrap();
        assert!(a.permits(ip("fd12:3456::1")));
        assert!(!a.permits(ip("fe80::1")));
    }

    #[test]
    fn malformed_specs_are_rejected() {
        assert!(Allowlist::parse(&["not-an-ip".into()]).is_err());
        assert!(Allowlist::parse(&["192.168.1.0/33".into()]).is_err());
        assert!(Allowlist::parse(&["192.168.1.0/abc".into()]).is_err());
    }
}
