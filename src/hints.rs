use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::classify::{classify, Classification};
use crate::flow::Flow;
use crate::identity::{client_ip_for_flow, ClientIdentity};

#[derive(Debug, Default)]
pub struct Hints {
    pub identity: HashMap<Ipv4Addr, ClientIdentity>,
    sni: HashMap<(Ipv4Addr, Ipv4Addr, u16), String>,
}

impl Hints {
    pub fn remember_sni(
        &mut self,
        client: Ipv4Addr,
        server: Ipv4Addr,
        server_port: u16,
        sni: String,
    ) {
        self.sni.insert((client, server, server_port), sni);
    }

    pub fn remember_identity(&mut self, ip: Ipv4Addr, ident: ClientIdentity) {
        let entry = self.identity.entry(ip).or_default();
        crate::identity::merge_identity(entry, ident);
    }

    pub fn sni_for(&self, flow: &Flow) -> Option<&str> {
        let client = client_ip_for_flow(flow)?;
        let (server, port) = if flow.src == client {
            (flow.dst, flow.dst_port)
        } else {
            (flow.src, flow.src_port)
        };
        self.sni.get(&(client, server, port)).map(String::as_str)
    }

    pub fn classify_flow(&self, flow: &Flow) -> Classification {
        if let Some(sni) = self.sni_for(flow) {
            return Classification {
                app: sni.to_string(),
                category: "web".to_string(),
                confidence: "sni".to_string(),
                evidence: format!("sni={sni}"),
            };
        }
        classify(flow)
    }

    pub fn identity_for_flow(&self, flow: &Flow) -> Option<&ClientIdentity> {
        let ip = client_ip_for_flow(flow)?;
        self.identity.get(&ip)
    }
}
