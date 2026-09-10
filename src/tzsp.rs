use crate::error::{Error, Result};

/// Return the Ethernet frame inside a TZSP datagram (MikroTik sniffer streaming).
pub fn ethernet_payload(datagram: &[u8]) -> Result<&[u8]> {
    if datagram.len() < 5 {
        return Err(Error::Decode("tzsp truncated"));
    }
    if datagram[0] != 1 {
        return Err(Error::Decode("tzsp version"));
    }
    let encap = u16::from_be_bytes([datagram[2], datagram[3]]);
    if encap != 1 {
        return Err(Error::Decode("tzsp not ethernet"));
    }
    let mut i = 4usize;
    while i < datagram.len() {
        let tag = datagram[i];
        if tag == 1 {
            return Ok(&datagram[i + 1..]);
        }
        if tag == 0 {
            i += 1;
            continue;
        }
        if i + 2 > datagram.len() {
            return Err(Error::Decode("tzsp tag truncated"));
        }
        let len = usize::from(datagram[i + 1]);
        i = i
            .checked_add(2)
            .and_then(|n| n.checked_add(len))
            .ok_or(Error::Decode("tzsp tag overflow"))?;
    }
    Err(Error::Decode("tzsp missing end tag"))
}

pub fn encode_ethernet(frame: &[u8]) -> Vec<u8> {
    let mut out = vec![1, 0, 0, 1, 1];
    out.extend_from_slice(frame);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_end_tag() {
        let frame = vec![0u8; 14];
        let pkt = encode_ethernet(&frame);
        assert_eq!(ethernet_payload(&pkt).unwrap(), frame);
    }

    #[test]
    fn garbage_is_error() {
        assert!(ethernet_payload(&[0, 1, 2]).is_err());
    }
}
