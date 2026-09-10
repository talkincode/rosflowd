/// Extract SNI from a TLS record that begins a ClientHello.
pub fn client_hello_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 || payload[0] != 0x16 {
        return handshake_sni(payload);
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let hs = payload.get(5..5 + rec_len)?;
    handshake_sni(hs)
}

/// TLS handshake bytes starting at a Handshake message (no record layer).
pub fn handshake_sni(hs: &[u8]) -> Option<String> {
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let body = hs.get(4..4 + hs_len)?;
    parse_client_hello_body(body)
}

fn parse_client_hello_body(mut body: &[u8]) -> Option<String> {
    // version + random
    if body.len() < 34 {
        return None;
    }
    body = &body[34..];
    let sid_len = *body.first()? as usize;
    body = body.get(1 + sid_len..)?;
    if body.len() < 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    body = body.get(2 + cs_len..)?;
    let comp_len = *body.first()? as usize;
    body = body.get(1 + comp_len..)?;
    if body.len() < 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut ext = body.get(2..2 + ext_len)?;
    while ext.len() >= 4 {
        let ty = u16::from_be_bytes([ext[0], ext[1]]);
        let len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        let data = ext.get(4..4 + len)?;
        if ty == 0 {
            return parse_server_name(data);
        }
        ext = ext.get(4 + len..)?;
    }
    None
}

fn parse_server_name(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut list = data.get(2..2 + list_len)?;
    while list.len() >= 3 {
        let name_type = list[0];
        let name_len = u16::from_be_bytes([list[1], list[2]]) as usize;
        let name = list.get(3..3 + name_len)?;
        if name_type == 0 {
            let s = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            if !s.is_empty() && s.len() <= 253 {
                return Some(s);
            }
        }
        list = list.get(3 + name_len..)?;
    }
    None
}

pub fn encode_client_hello(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
    server_name.push(0);
    server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    server_name.extend_from_slice(host);

    let mut ext = Vec::new();
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    ext.extend_from_slice(&server_name);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    body.push(1);
    body.push(0); // compression
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = Vec::new();
    hs.push(0x01);
    let n = body.len();
    hs.push(((n >> 16) & 0xff) as u8);
    hs.push(((n >> 8) & 0xff) as u8);
    hs.push((n & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_sni() {
        let rec = encode_client_hello("example.com");
        assert_eq!(client_hello_sni(&rec).as_deref(), Some("example.com"));
    }

    #[test]
    fn non_tls_is_none() {
        assert_eq!(client_hello_sni(&[0x17, 0x03, 0x03, 0, 1, 0]), None);
    }
}
