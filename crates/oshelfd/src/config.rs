//! Bind address policy: oshelfd only listens on LAN, loopback or link-local
//! addresses. Remote access goes through the user's own tunnel.

use std::net::{IpAddr, SocketAddr};

pub const DEFAULT_PORT: u16 = 8740;

/// True for addresses that can't be reached from the public internet
/// directly. `0.0.0.0` / `::` are allowed because a Pi behind a home router
/// usually has only a private address.
pub fn is_lan_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (first & 0xffc0) == 0xfe80 // link local fe80::/10
        }
    }
}

pub fn check_bind(addr: SocketAddr) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_lan_address(addr.ip()),
        "refusing to bind {addr}: oshelfd only listens on LAN addresses. Use a tunnel for remote access."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_only() {
        for ok in [
            "192.168.1.20",
            "10.0.0.2",
            "172.16.4.1",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "::1",
            "fd12::1",
            "fe80::1",
            "::",
        ] {
            assert!(is_lan_address(ok.parse().unwrap()), "{ok}");
        }
        for bad in ["8.8.8.8", "203.0.113.9", "2001:db8::1", "172.32.0.1"] {
            assert!(!is_lan_address(bad.parse().unwrap()), "{bad}");
        }
    }
}
