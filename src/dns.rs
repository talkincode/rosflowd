use std::net::Ipv4Addr;

/// Parse IN A records from a DNS response. Questions without answers yield none.
pub fn a_records(payload: &[u8]) -> Option<Vec<(Ipv4Addr, String)>> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut i = 12usize;
    let mut qname = None;
    for _ in 0..qdcount {
        let (name, n) = read_name(payload, i)?;
        i = n;
        i = i.checked_add(4)?; // qtype + qclass
        if qname.is_none() {
            qname = Some(name);
        }
    }
    let mut out = Vec::new();
    for _ in 0..ancount {
        let (name, n) = read_name(payload, i)?;
        i = n;
        if i + 10 > payload.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([payload[i], payload[i + 1]]);
        let class = u16::from_be_bytes([payload[i + 2], payload[i + 3]]);
        let rdlen = u16::from_be_bytes([payload[i + 8], payload[i + 9]]) as usize;
        i += 10;
        let rdata = payload.get(i..i + rdlen)?;
        i += rdlen;
        if rtype == 1 && class == 1 && rdata.len() == 4 {
            let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            let host = if name.is_empty() {
                qname.clone().unwrap_or_default()
            } else {
                name
            };
            if !host.is_empty() {
                out.push((ip, host));
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn read_name(msg: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end = i;
    let mut hops = 0u8;
    loop {
        if hops > 10 {
            return None;
        }
        let len = *msg.get(i)?;
        if len == 0 {
            if !jumped {
                end = i + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let b2 = *msg.get(i + 1)?;
            let ptr = (((len as usize) & 0x3f) << 8) | b2 as usize;
            if !jumped {
                end = i + 2;
            }
            i = ptr;
            jumped = true;
            hops += 1;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let lab = msg.get(i + 1..i + 1 + len as usize)?;
        labels.push(std::str::from_utf8(lab).ok()?.to_ascii_lowercase());
        i += 1 + len as usize;
        if !jumped {
            end = i;
        }
    }
    Some((labels.join("."), end))
}

pub fn encode_a_response(qname: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut q = Vec::new();
    for lab in qname.split('.') {
        let b = lab.as_bytes();
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0);
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x1234u16.to_be_bytes());
    msg.extend_from_slice(&0x8180u16.to_be_bytes()); // response, rd, ra
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&q);
    msg.extend_from_slice(&1u16.to_be_bytes()); // A
    msg.extend_from_slice(&1u16.to_be_bytes()); // IN
    msg.extend_from_slice(&[0xc0, 0x0c]); // pointer to qname
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&60u32.to_be_bytes());
    msg.extend_from_slice(&4u16.to_be_bytes());
    msg.extend_from_slice(&ip.octets());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_a() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let msg = encode_a_response("example.com", ip);
        let recs = a_records(&msg).unwrap();
        assert_eq!(recs, vec![(ip, "example.com".into())]);
    }

    #[test]
    fn query_is_none() {
        let mut q = encode_a_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        q[2] = 0x01;
        q[3] = 0x00;
        q[6] = 0;
        q[7] = 0;
        assert_eq!(a_records(&q), None);
    }
}
