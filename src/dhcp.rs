use std::net::Ipv4Addr;

use crate::identity::{format_mac, ClientIdentity};

/// Parse a DHCP ACK (op=2, option 53=5) from a UDP payload.
pub fn parse_ack(payload: &[u8]) -> Option<(Ipv4Addr, ClientIdentity)> {
    if payload.len() < 240 {
        return None;
    }
    if payload[0] != 2 {
        return None;
    }
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    if yiaddr.is_unspecified() {
        return None;
    }
    let mac = format_mac(&payload[28..44])?;
    if payload[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let mut hostname = None;
    let mut is_ack = false;
    let mut i = 240usize;
    while i < payload.len() {
        let opt = payload[i];
        if opt == 255 {
            break;
        }
        if opt == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= payload.len() {
            break;
        }
        let len = usize::from(payload[i + 1]);
        let val = payload.get(i + 2..i + 2 + len)?;
        match opt {
            53 if !val.is_empty() && val[0] == 5 => is_ack = true,
            12 => {
                if let Ok(s) = std::str::from_utf8(val) {
                    let s = s.trim();
                    if !s.is_empty() {
                        hostname = Some(s.to_string());
                    }
                }
            }
            _ => {}
        }
        i += 2 + len;
    }
    if !is_ack {
        return None;
    }
    Some((
        yiaddr,
        ClientIdentity {
            mac: Some(mac),
            hostname,
            ssid: None,
        },
    ))
}

pub fn encode_ack(ip: Ipv4Addr, mac: [u8; 6], hostname: &str) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 2;
    p[1] = 1;
    p[2] = 6;
    p[16..20].copy_from_slice(&ip.octets());
    p[28..34].copy_from_slice(&mac);
    p[236..240].copy_from_slice(&[99, 130, 83, 99]);
    p.push(53);
    p.push(1);
    p.push(5);
    let hb = hostname.as_bytes();
    p.push(12);
    p.push(hb.len() as u8);
    p.extend_from_slice(hb);
    p.push(255);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_round_trip() {
        let ip = Ipv4Addr::new(10, 0, 0, 95);
        let payload = encode_ack(ip, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], "phone");
        let (got, ident) = parse_ack(&payload).unwrap();
        assert_eq!(got, ip);
        assert_eq!(ident.mac.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(ident.hostname.as_deref(), Some("phone"));
    }
}
