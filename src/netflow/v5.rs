use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use crate::flow::Flow;

const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 48;

pub fn decode(datagram: &[u8]) -> Result<Vec<Flow>> {
    if datagram.len() < HEADER_LEN {
        return Err(Error::Decode("v5 header truncated"));
    }
    let version = u16::from_be_bytes([datagram[0], datagram[1]]);
    if version != 5 {
        return Err(Error::UnsupportedVersion(version));
    }
    let count = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let expected = HEADER_LEN + count * RECORD_LEN;
    if datagram.len() < expected {
        return Err(Error::Decode("v5 records truncated"));
    }
    let unix_secs = u32::from_be_bytes(datagram[8..12].try_into().unwrap());
    let mut flows = Vec::with_capacity(count);
    for i in 0..count {
        let off = HEADER_LEN + i * RECORD_LEN;
        let rec = &datagram[off..off + RECORD_LEN];
        flows.push(Flow {
            src: ipv4(&rec[0..4]),
            dst: ipv4(&rec[4..8]),
            src_port: u16::from_be_bytes([rec[32], rec[33]]),
            dst_port: u16::from_be_bytes([rec[34], rec[35]]),
            proto: rec[38],
            packets: u32::from_be_bytes(rec[16..20].try_into().unwrap()) as u64,
            bytes: u32::from_be_bytes(rec[20..24].try_into().unwrap()) as u64,
            tcp_flags: rec[37],
            unix_secs,
        });
    }
    Ok(flows)
}

fn ipv4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

pub fn encode(unix_secs: u32, records: &[Flow]) -> Vec<u8> {
    let count = records.len() as u16;
    let mut out = vec![0u8; HEADER_LEN + records.len() * RECORD_LEN];
    out[0..2].copy_from_slice(&5u16.to_be_bytes());
    out[2..4].copy_from_slice(&count.to_be_bytes());
    out[8..12].copy_from_slice(&unix_secs.to_be_bytes());
    for (i, flow) in records.iter().enumerate() {
        let off = HEADER_LEN + i * RECORD_LEN;
        let rec = &mut out[off..off + RECORD_LEN];
        rec[0..4].copy_from_slice(&flow.src.octets());
        rec[4..8].copy_from_slice(&flow.dst.octets());
        rec[16..20].copy_from_slice(&(flow.packets as u32).to_be_bytes());
        rec[20..24].copy_from_slice(&(flow.bytes as u32).to_be_bytes());
        rec[32..34].copy_from_slice(&flow.src_port.to_be_bytes());
        rec[34..36].copy_from_slice(&flow.dst_port.to_be_bytes());
        rec[37] = flow.tcp_flags;
        rec[38] = flow.proto;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Flow {
        Flow {
            src: Ipv4Addr::new(10, 0, 0, 95),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 50000,
            dst_port: 443,
            proto: 6,
            packets: 10,
            bytes: 1234,
            tcp_flags: 0x18,
            unix_secs: 1_700_000_000,
        }
    }

    #[test]
    fn round_trip() {
        let flow = sample();
        let pkt = encode(flow.unix_secs, std::slice::from_ref(&flow));
        let decoded = decode(&pkt).unwrap();
        assert_eq!(decoded, vec![flow]);
    }

    #[test]
    fn truncated_records() {
        let pkt = encode(0, &[sample()]);
        let err = decode(&pkt[..HEADER_LEN + 10]).unwrap_err();
        assert!(matches!(err, Error::Decode(_)));
    }
}
