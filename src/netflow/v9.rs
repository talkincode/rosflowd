use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::flow::Flow;
use crate::netflow::fields::{
    pad4, parse_record, write_record, FieldSpec, Template, EXPORT_FIELDS,
};

const HEADER_LEN: usize = 20;
pub const TEMPLATE_ID: u16 = 256;

pub fn decode(templates: &mut HashMap<(u32, u16), Template>, datagram: &[u8]) -> Result<Vec<Flow>> {
    if datagram.len() < HEADER_LEN {
        return Err(Error::Decode("v9 header truncated"));
    }
    let version = u16::from_be_bytes([datagram[0], datagram[1]]);
    if version != 9 {
        return Err(Error::UnsupportedVersion(version));
    }
    let unix_secs = u32::from_be_bytes(datagram[8..12].try_into().unwrap());
    let source_id = u32::from_be_bytes(datagram[16..20].try_into().unwrap());
    decode_sets(templates, source_id, unix_secs, datagram, HEADER_LEN, 0)
}

pub(crate) fn decode_sets(
    templates: &mut HashMap<(u32, u16), Template>,
    source_id: u32,
    unix_secs: u32,
    datagram: &[u8],
    mut off: usize,
    template_set_id: u16,
) -> Result<Vec<Flow>> {
    let mut flows = Vec::new();
    while off + 4 <= datagram.len() {
        let set_id = u16::from_be_bytes([datagram[off], datagram[off + 1]]);
        let set_len = u16::from_be_bytes([datagram[off + 2], datagram[off + 3]]) as usize;
        if set_len < 4 || off + set_len > datagram.len() {
            return Err(Error::Decode("flowset length invalid"));
        }
        let body = &datagram[off + 4..off + set_len];
        if set_id == template_set_id {
            parse_templates(templates, source_id, body)?;
        } else if set_id >= 256 {
            if let Some(template) = templates.get(&(source_id, set_id)) {
                let mut rec_off = 0usize;
                while rec_off + template.rec_len <= body.len() {
                    if let Some(flow) = parse_record(
                        template,
                        &body[rec_off..rec_off + template.rec_len],
                        unix_secs,
                    ) {
                        flows.push(flow);
                    }
                    rec_off += template.rec_len;
                }
            }
        }
        off += set_len;
    }
    Ok(flows)
}

fn parse_templates(
    templates: &mut HashMap<(u32, u16), Template>,
    source_id: u32,
    mut body: &[u8],
) -> Result<()> {
    while body.len() >= 4 {
        let template_id = u16::from_be_bytes([body[0], body[1]]);
        let field_count = u16::from_be_bytes([body[2], body[3]]) as usize;
        body = &body[4..];
        let need = field_count.saturating_mul(4);
        if body.len() < need {
            return Err(Error::Decode("v9 template truncated"));
        }
        let mut fields = Vec::with_capacity(field_count);
        for i in 0..field_count {
            let base = i * 4;
            fields.push(FieldSpec {
                ty: u16::from_be_bytes([body[base], body[base + 1]]),
                len: u16::from_be_bytes([body[base + 2], body[base + 3]]),
            });
        }
        body = &body[need..];
        if template_id >= 256 {
            if let Some(template) = Template::from_fields(fields) {
                templates.insert((source_id, template_id), template);
            }
        }
    }
    Ok(())
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
    out[0..2].copy_from_slice(&9u16.to_be_bytes());
    let count = 1u16 + flows.len() as u16;
    out[2..4].copy_from_slice(&count.to_be_bytes());
    out[8..12].copy_from_slice(&unix_secs.to_be_bytes());
    out[16..20].copy_from_slice(&source_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
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
            src: Ipv4Addr::new(10, 0, 0, 95),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 50000,
            dst_port: 443,
            proto: 6,
            packets: 8,
            bytes: 4096,
            tcp_flags: 0x18,
            unix_secs: 1_704_067_200,
        }
    }

    #[test]
    fn round_trip() {
        let flow = sample();
        let pkt = encode(flow.unix_secs, 1, std::slice::from_ref(&flow));
        let mut templates = HashMap::new();
        let decoded = decode(&mut templates, &pkt).unwrap();
        assert_eq!(decoded, vec![flow]);
    }

    #[test]
    fn data_without_template_yields_no_flows() {
        let flow = sample();
        let pkt = encode(flow.unix_secs, 1, &[flow]);
        // strip template set: keep header + skip first flowset
        let set_len = u16::from_be_bytes([pkt[HEADER_LEN + 2], pkt[HEADER_LEN + 3]]) as usize;
        let mut data_only = pkt[..HEADER_LEN].to_vec();
        data_only.extend_from_slice(&pkt[HEADER_LEN + set_len..]);
        let mut templates = HashMap::new();
        let decoded = decode(&mut templates, &data_only).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn truncated_header() {
        let err = decode(&mut HashMap::new(), &[0, 9, 0, 1]).unwrap_err();
        assert!(matches!(err, Error::Decode(_)));
    }
}
