use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct L4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub payload: Vec<u8>,
}

pub fn parse_ipv4_l4(frame: &[u8]) -> Option<L4> {
    if frame.len() < 14 {
        return None;
    }
    let mut etype_off = 12usize;
    let mut etype = u16::from_be_bytes([frame[12], frame[13]]);
    if etype == 0x8100 {
        etype_off = 16;
        etype = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
    }
    if etype != 0x0800 {
        return None;
    }
    let ip = frame.get(etype_off + 2..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let proto = ip[9];
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let l4 = ip.get(ihl..)?;
    match proto {
        6 if l4.len() >= 20 => {
            let doff = ((l4[12] >> 4) as usize) * 4;
            if doff < 20 || l4.len() < doff {
                return None;
            }
            Some(L4 {
                src,
                dst,
                src_port: u16::from_be_bytes([l4[0], l4[1]]),
                dst_port: u16::from_be_bytes([l4[2], l4[3]]),
                proto,
                payload: l4[doff..].to_vec(),
            })
        }
        17 if l4.len() >= 8 => Some(L4 {
            src,
            dst,
            src_port: u16::from_be_bytes([l4[0], l4[1]]),
            dst_port: u16::from_be_bytes([l4[2], l4[3]]),
            proto,
            payload: l4[8..].to_vec(),
        }),
        _ => None,
    }
}

pub fn ethernet_ipv4(
    src_mac: [u8; 6],
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    match proto {
        6 => {
            l4.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // seq ack
            l4.push(0x50); // data offset 5
            l4.push(0x18);
            l4.extend_from_slice(&[0x01, 0x00, 0, 0, 0, 0]);
            l4.extend_from_slice(payload);
        }
        17 => {
            let len = 8 + payload.len();
            l4.extend_from_slice(&(len as u16).to_be_bytes());
            l4.extend_from_slice(&[0, 0]);
            l4.extend_from_slice(payload);
        }
        _ => l4.extend_from_slice(payload),
    }
    let mut ip = vec![0x45, 0];
    let total = 20 + l4.len();
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, proto, 0, 0]);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(&l4);
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp() {
        let frame = ethernet_ipv4(
            [1, 2, 3, 4, 5, 6],
            17,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            68,
            67,
            &[1, 2, 3],
        );
        let l4 = parse_ipv4_l4(&frame).unwrap();
        assert_eq!(l4.proto, 17);
        assert_eq!(l4.src_port, 68);
        assert_eq!(l4.payload, vec![1, 2, 3]);
    }
}
