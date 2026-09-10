use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::flow::Flow;
use crate::netflow::fields::{pad4, write_record, FieldSpec, Template, EXPORT_FIELDS};
use crate::netflow::v9::{decode_sets, TEMPLATE_ID};

const HEADER_LEN: usize = 16;
const TEMPLATE_SET_ID: u16 = 2;

pub fn decode(templates: &mut HashMap<(u32, u16), Template>, datagram: &[u8]) -> Result<Vec<Flow>> {
    if datagram.len() < HEADER_LEN {
        return Err(Error::Decode("ipfix header truncated"));
    }
    let version = u16::from_be_bytes([datagram[0], datagram[1]]);
    if version != 10 {
        return Err(Error::UnsupportedVersion(version));
    }
    let length = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    if length != datagram.len() {
        return Err(Error::Decode("ipfix length mismatch"));
    }
    let unix_secs = u32::from_be_bytes(datagram[4..8].try_into().unwrap());
    let source_id = u32::from_be_bytes(datagram[12..16].try_into().unwrap());
    decode_sets(
        templates,
        source_id,
        unix_secs,
        datagram,
        HEADER_LEN,
        TEMPLATE_SET_ID,
    )
}

pub fn encode(unix_secs: u32, source_id: u32, flows: &[Flow]) -> Vec<u8> {
    let mut template_body = Vec::new();
    template_body.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    template_body.extend_from_slice(&(EXPORT_FIELDS.len() as u16).to_be_bytes());
    for FieldSpec { ty, len } in EXPORT_FIELDS {
        template_body.extend_from_slice(&ty.to_be_bytes());
        template_body.extend_from_slice(&len.to_be_bytes());
    }
    let template_set_len = 4 + template_body.len();
    let mut data_body = Vec::new();
    for flow in flows {
        write_record(&mut data_body, flow);
    }
    let data_pad = pad4(4 + data_body.len());
    let data_set_len = 4 + data_body.len() + data_pad;
    let total = HEADER_LEN + template_set_len + data_set_len;

    let mut out = vec![0u8; HEADER_LEN];
    out[0..2].copy_from_slice(&10u16.to_be_bytes());
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[4..8].copy_from_slice(&unix_secs.to_be_bytes());
    out[12..16].copy_from_slice(&source_id.to_be_bytes());
    out.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
    out.extend_from_slice(&(template_set_len as u16).to_be_bytes());
    out.extend_from_slice(&template_body);
    out.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    out.extend_from_slice(&(data_set_len as u16).to_be_bytes());
    out.extend_from_slice(&data_body);
    out.extend(std::iter::repeat_n(0u8, data_pad));
    debug_assert_eq!(out.len(), total);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample() -> Flow {
        Flow {
            src: Ipv4Addr::new(192, 168, 10, 199),
            dst: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 51000,
            dst_port: 53,
            proto: 17,
            packets: 2,
            bytes: 180,
            tcp_flags: 0,
            unix_secs: 1_704_067_200,
        }
    }

    #[test]
    fn round_trip() {
        let flow = sample();
        let pkt = encode(flow.unix_secs, 7, std::slice::from_ref(&flow));
        let mut templates = HashMap::new();
        let decoded = decode(&mut templates, &pkt).unwrap();
        assert_eq!(decoded, vec![flow]);
    }

    #[test]
    fn length_mismatch() {
        let flow = sample();
        let mut pkt = encode(flow.unix_secs, 7, &[flow]);
        pkt[3] = pkt[3].wrapping_add(1);
        let err = decode(&mut HashMap::new(), &pkt).unwrap_err();
        assert!(matches!(err, Error::Decode(_)));
    }
}
