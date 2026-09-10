use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::sni::handshake_sni;

const V1: u32 = 0x0000_0001;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub fn client_initial_sni(udp: &[u8]) -> Option<String> {
    let crypto = decrypt_client_initial(udp)?;
    handshake_sni(&crypto)
}

fn decrypt_client_initial(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 7 {
        return None;
    }
    let first = packet[0];
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(packet[1..5].try_into().ok()?);
    if version != V1 {
        return None;
    }
    let mut i = 5usize;
    let dcid_len = *packet.get(i)? as usize;
    i += 1;
    let dcid = packet.get(i..i + dcid_len)?;
    i += dcid_len;
    let scid_len = *packet.get(i)? as usize;
    i += 1;
    i += scid_len;
    let (token_len, n) = varint_at(packet, i)?;
    i += n + token_len as usize;
    let (length, n) = varint_at(packet, i)?;
    i += n;
    let pn_offset = i;
    if packet.len() < pn_offset + 4 + 16 {
        return None;
    }
    let keys = initial_keys(dcid)?;
    let mut unprotected = packet.to_vec();
    apply_header_protection(&mut unprotected, pn_offset, &keys.hp, true)?;
    let pn_len = ((unprotected[0] & 0x03) + 1) as usize;
    if packet.len() < pn_offset + pn_len {
        return None;
    }
    let mut pn = 0u64;
    for b in &unprotected[pn_offset..pn_offset + pn_len] {
        pn = (pn << 8) | u64::from(*b);
    }
    let payload_off = pn_offset + pn_len;
    let payload_len = length as usize;
    if payload_len < pn_len + 16 {
        return None;
    }
    let ct_end = pn_offset + payload_len;
    let ct = unprotected.get(payload_off..ct_end)?;
    let aad = unprotected.get(..payload_off)?;
    let nonce = build_nonce(&keys.iv, pn);
    let gcm = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let plain = gcm
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: ct, aad })
        .ok()?;
    crypto_stream(&plain)
}

struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn initial_keys(dcid: &[u8]) -> Option<Keys> {
    let extracted = hkdf_extract(&SALT_V1, dcid);
    let client = expand_label(&extracted, b"client in", 32)?;
    let key = expand_label(&client, b"quic key", 16)?;
    let iv = expand_label(&client, b"quic iv", 12)?;
    let hp = expand_label(&client, b"quic hp", 16)?;
    Some(Keys {
        key: key.try_into().ok()?,
        iv: iv.try_into().ok()?,
        hp: hp.try_into().ok()?,
    })
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

fn expand_label(secret: &[u8], label: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut full = b"tls13 ".to_vec();
    full.extend_from_slice(label);
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(0);
    let hk = Hkdf::<Sha256>::from_prk(secret).ok()?;
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).ok()?;
    Some(out)
}

fn apply_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    hp: &[u8; 16],
    unprotect: bool,
) -> Option<()> {
    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;
    let cipher = Aes128::new_from_slice(hp).ok()?;
    let mut block = aes::Block::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mask = block;
    if unprotect {
        packet[0] ^= mask[0] & 0x0f;
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    } else {
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet[0] ^= mask[0] & 0x0f;
    }
    Some(())
}

fn build_nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for i in 0..8 {
        nonce[11 - i] ^= ((pn >> (8 * i)) & 0xff) as u8;
    }
    nonce
}

fn crypto_stream(frames: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0usize;
    let mut max = 0usize;
    let mut buf = vec![0u8; frames.len()];
    while i < frames.len() {
        let ty = frames[i];
        i += 1;
        match ty {
            0x00 => continue,
            0x01 => continue,
            0x06 => {
                let (off, n) = varint_at(frames, i)?;
                i += n;
                let (len, n) = varint_at(frames, i)?;
                i += n;
                let data = frames.get(i..i + len as usize)?;
                let start = off as usize;
                let end = start + data.len();
                if end > buf.len() {
                    buf.resize(end, 0);
                }
                buf[start..end].copy_from_slice(data);
                max = max.max(end);
                i += len as usize;
            }
            _ if max > 0 => break,
            _ => return None,
        }
    }
    if max == 0 {
        None
    } else {
        buf.truncate(max);
        Some(buf)
    }
}

fn varint_at(buf: &[u8], i: usize) -> Option<(u64, usize)> {
    let first = *buf.get(i)?;
    let n = 1usize << (first >> 6);
    if i + n > buf.len() {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for b in &buf[i + 1..i + n] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, n))
}

fn write_varint(v: u64) -> Vec<u8> {
    if v < 64 {
        vec![v as u8]
    } else if v < 16384 {
        vec![0x40 | ((v >> 8) as u8), v as u8]
    } else if v < 1_073_741_824 {
        vec![
            0x80 | ((v >> 24) as u8),
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    } else {
        let mut o = vec![0xc0];
        o.extend_from_slice(&v.to_be_bytes());
        o[0] = 0xc0 | ((v >> 56) as u8);
        o
    }
}

pub fn encode_client_initial(sni: &str, dcid: &[u8]) -> Option<Vec<u8>> {
    let hello = crate::sni::encode_client_hello(sni);
    // strip TLS record wrapper: encode_client_hello includes record; CRYPTO wants handshake
    let hs = if hello.len() > 5 && hello[0] == 0x16 {
        hello[5..].to_vec()
    } else {
        hello
    };
    let mut payload = Vec::new();
    payload.push(0x06);
    payload.extend_from_slice(&write_varint(0));
    payload.extend_from_slice(&write_varint(hs.len() as u64));
    payload.extend_from_slice(&hs);
    while payload.len() < 64 {
        payload.push(0);
    }
    let keys = initial_keys(dcid)?;
    let pn = 0u64;
    let pn_len = 1usize;
    let mut header = Vec::new();
    header.push(0xc0); // long Initial, pn_len=1
    header.extend_from_slice(&V1.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0); // scid empty
    header.extend_from_slice(&write_varint(0)); // token
    let gcm = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let nonce = build_nonce(&keys.iv, pn);
    let pn_bytes = vec![pn as u8];
    let length = pn_len + payload.len() + 16;
    let length_bytes = write_varint(length as u64);
    let mut aad = header.clone();
    aad.extend_from_slice(&length_bytes);
    aad.extend_from_slice(&pn_bytes);
    let ct = gcm
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &aad,
            },
        )
        .ok()?;
    let mut packet = header;
    packet.extend_from_slice(&length_bytes);
    let pn_offset = packet.len();
    packet.extend_from_slice(&pn_bytes);
    packet.extend_from_slice(&ct);
    apply_header_protection(&mut packet, pn_offset, &keys.hp, false)?;
    let _ = pn_bytes;
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_quic_sni() {
        let dcid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let pkt = encode_client_initial("quic.example", &dcid).expect("encode");
        assert_eq!(client_initial_sni(&pkt).as_deref(), Some("quic.example"));
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(client_initial_sni(&[0x40, 1, 2, 3]), None);
    }
}
