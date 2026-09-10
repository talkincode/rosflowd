use std::net::Ipv4Addr;

use crate::flow::Flow;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub ssid: Option<String>,
}

pub fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 6 {
        return None;
    }
    Some(format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

/// LAN client key: RFC1918 source, else RFC1918 destination.
/// WAN-only (neither side private) returns None — never invent a client.
/// CGNAT `100.64/10` is intentionally excluded.
pub fn client_ip(src: Ipv4Addr, dst: Ipv4Addr) -> Option<Ipv4Addr> {
    if is_rfc1918(src) {
        Some(src)
    } else if is_rfc1918(dst) {
        Some(dst)
    } else {
        None
    }
}

pub fn client_ip_for_flow(flow: &Flow) -> Option<Ipv4Addr> {
    client_ip(flow.src, flow.dst)
}

pub fn merge_identity(dst: &mut ClientIdentity, src: ClientIdentity) {
    if src.mac.is_some() {
        dst.mac = src.mac;
    }
    if src.hostname.is_some() {
        dst.hostname = src.hostname;
    }
    if src.ssid.is_some() {
        dst.ssid = src.ssid;
    }
}

pub fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16..=31).contains(&o[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_source_wins() {
        let src = Ipv4Addr::new(10, 189, 189, 95);
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        assert_eq!(client_ip(src, dst), Some(src));
    }

    #[test]
    fn lan_destination_when_source_is_wan() {
        let src = Ipv4Addr::new(1, 1, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 10, 199);
        assert_eq!(client_ip(src, dst), Some(dst));
    }

    #[test]
    fn wan_only_has_no_client() {
        let src = Ipv4Addr::new(203, 0, 113, 10);
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        assert_eq!(client_ip(src, dst), None);
    }

    #[test]
    fn cgnat_is_not_lan_client() {
        let src = Ipv4Addr::new(100, 64, 1, 1);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        assert_eq!(client_ip(src, dst), None);
    }
}
