use std::net::Ipv4Addr;

use crate::flow::Flow;

pub const IN_BYTES: u16 = 1;
pub const IN_PKTS: u16 = 2;
pub const PROTOCOL: u16 = 4;
pub const TCP_FLAGS: u16 = 6;
pub const L4_SRC_PORT: u16 = 7;
pub const IPV4_SRC_ADDR: u16 = 8;
pub const L4_DST_PORT: u16 = 11;
pub const IPV4_DST_ADDR: u16 = 12;
pub const OUT_BYTES: u16 = 23;
pub const OUT_PKTS: u16 = 24;

#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub ty: u16,
    pub len: u16,
}

#[derive(Debug, Clone)]
pub struct Template {
    pub fields: Vec<FieldSpec>,
    pub rec_len: usize,
}

impl Template {
    pub fn from_fields(fields: Vec<FieldSpec>) -> Option<Self> {
        let rec_len = fields.iter().map(|f| usize::from(f.len)).sum();
        if rec_len == 0 {
            return None;
        }
        Some(Self { fields, rec_len })
    }
}

pub const EXPORT_FIELDS: [FieldSpec; 8] = [
    FieldSpec {
        ty: IPV4_SRC_ADDR,
        len: 4,
    },
    FieldSpec {
        ty: IPV4_DST_ADDR,
        len: 4,
    },
    FieldSpec {
        ty: L4_SRC_PORT,
        len: 2,
    },
    FieldSpec {
        ty: L4_DST_PORT,
        len: 2,
    },
    FieldSpec {
        ty: PROTOCOL,
        len: 1,
    },
    FieldSpec {
        ty: TCP_FLAGS,
        len: 1,
    },
    FieldSpec {
        ty: IN_BYTES,
        len: 4,
    },
    FieldSpec {
        ty: IN_PKTS,
        len: 4,
    },
];

pub fn parse_record(template: &Template, rec: &[u8], unix_secs: u32) -> Option<Flow> {
    if rec.len() < template.rec_len {
        return None;
    }
    let mut src = None;
    let mut dst = None;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut proto = 0u8;
    let mut tcp_flags = 0u8;
    let mut bytes = 0u64;
    let mut packets = 0u64;
    let mut off = 0usize;
    for field in &template.fields {
        let len = usize::from(field.len);
        if off + len > rec.len() {
            return None;
        }
        let slice = &rec[off..off + len];
        match field.ty {
            IPV4_SRC_ADDR if len == 4 => src = Some(ipv4(slice)),
            IPV4_DST_ADDR if len == 4 => dst = Some(ipv4(slice)),
            L4_SRC_PORT if len == 2 => src_port = u16::from_be_bytes([slice[0], slice[1]]),
            L4_DST_PORT if len == 2 => dst_port = u16::from_be_bytes([slice[0], slice[1]]),
            PROTOCOL if len == 1 => proto = slice[0],
            TCP_FLAGS if len == 1 => tcp_flags = slice[0],
            IN_BYTES | OUT_BYTES => bytes = be_int(slice),
            IN_PKTS | OUT_PKTS => packets = be_int(slice),
            _ => {}
        }
        off += len;
    }
    Some(Flow {
        src: src?,
        dst: dst?,
        src_port,
        dst_port,
        proto,
        packets,
        bytes,
        tcp_flags,
        unix_secs,
    })
}

pub fn write_record(buf: &mut Vec<u8>, flow: &Flow) {
    buf.extend_from_slice(&flow.src.octets());
    buf.extend_from_slice(&flow.dst.octets());
    buf.extend_from_slice(&flow.src_port.to_be_bytes());
    buf.extend_from_slice(&flow.dst_port.to_be_bytes());
    buf.push(flow.proto);
    buf.push(flow.tcp_flags);
    buf.extend_from_slice(&(flow.bytes as u32).to_be_bytes());
    buf.extend_from_slice(&(flow.packets as u32).to_be_bytes());
}

fn ipv4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn be_int(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for b in bytes {
        v = (v << 8) | u64::from(*b);
    }
    v
}

pub fn pad4(len: usize) -> usize {
    (4 - (len % 4)) % 4
}
