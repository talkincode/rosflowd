use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::net::Ipv4Addr;
use std::ptr;

use crate::packet::L4;

const GENERIC: &[&str] = &[
    "Unknown",
    "TLS",
    "HTTP",
    "HTTP2",
    "QUIC",
    "DNS",
    "MDNS",
    "DHCP",
    "SMBv1",
    "SMBv23",
    "GenericProtocolGuess",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpiHit {
    pub app: String,
    pub category: String,
    pub specific: bool,
}

pub struct NdpiEngine {
    ctx: *mut c_void,
    flows: HashMap<FlowKey, *mut c_void>,
}

unsafe impl Send for NdpiEngine {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    proto: u8,
}

impl FlowKey {
    fn from_l4(l4: &L4) -> Self {
        if (l4.src, l4.src_port) <= (l4.dst, l4.dst_port) {
            Self {
                src: l4.src,
                dst: l4.dst,
                sport: l4.src_port,
                dport: l4.dst_port,
                proto: l4.proto,
            }
        } else {
            Self {
                src: l4.dst,
                dst: l4.src,
                sport: l4.dst_port,
                dport: l4.src_port,
                proto: l4.proto,
            }
        }
    }
}

extern "C" {
    fn rs_ndpi_new() -> *mut c_void;
    fn rs_ndpi_free(ctx: *mut c_void);
    fn rs_ndpi_flow_new() -> *mut c_void;
    fn rs_ndpi_flow_free(flow: *mut c_void);
    fn rs_ndpi_inspect(
        ctx: *mut c_void,
        flow: *mut c_void,
        ip: *const u8,
        len: u16,
        time_ms: u64,
        app: *mut c_char,
        app_len: usize,
        category: *mut c_char,
        cat_len: usize,
    ) -> c_int;
}

impl NdpiEngine {
    pub fn new() -> Option<Self> {
        unsafe {
            let ctx = rs_ndpi_new();
            if ctx.is_null() {
                None
            } else {
                Some(Self {
                    ctx,
                    flows: HashMap::new(),
                })
            }
        }
    }

    pub fn inspect(&mut self, ip: &[u8], l4: &L4, time_ms: u64) -> Option<NdpiHit> {
        if self.ctx.is_null() || ip.is_empty() || ip.len() > u16::MAX as usize {
            return None;
        }
        let key = FlowKey::from_l4(l4);
        if self.flows.len() >= 4096 && !self.flows.contains_key(&key) {
            if let Some(k) = self.flows.keys().copied().next() {
                if let Some(ptr) = self.flows.remove(&k) {
                    unsafe { rs_ndpi_flow_free(ptr) };
                }
            }
        }
        let flow = match self.flows.get(&key) {
            Some(p) => *p,
            None => {
                let p = unsafe { rs_ndpi_flow_new() };
                if p.is_null() {
                    return None;
                }
                self.flows.insert(key, p);
                p
            }
        };
        let mut app = [0u8; 64];
        let mut cat = [0u8; 64];
        let ok = unsafe {
            rs_ndpi_inspect(
                self.ctx,
                flow,
                ip.as_ptr(),
                ip.len() as u16,
                time_ms,
                app.as_mut_ptr() as *mut c_char,
                app.len(),
                cat.as_mut_ptr() as *mut c_char,
                cat.len(),
            )
        };
        if ok == 0 {
            return None;
        }
        let app = cstr(&app)?;
        if app.is_empty() {
            return None;
        }
        let category = cstr(&cat).unwrap_or_else(|| "unknown".into());
        let specific = !GENERIC.iter().any(|g| g.eq_ignore_ascii_case(&app));
        Some(NdpiHit {
            app,
            category,
            specific,
        })
    }
}

fn cstr(buf: &[u8]) -> Option<String> {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&buf[..end]).ok().map(str::to_string)
}

impl Drop for NdpiEngine {
    fn drop(&mut self) {
        for (_, flow) in self.flows.drain() {
            unsafe { rs_ndpi_flow_free(flow) };
        }
        if !self.ctx.is_null() {
            unsafe { rs_ndpi_free(self.ctx) };
            self.ctx = ptr::null_mut();
        }
    }
}

impl Default for NdpiEngine {
    fn default() -> Self {
        Self::new().unwrap_or(Self {
            ctx: ptr::null_mut(),
            flows: HashMap::new(),
        })
    }
}
