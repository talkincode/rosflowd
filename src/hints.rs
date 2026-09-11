use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::classify::{classify, Classification};
use crate::flow::Flow;
use crate::identity::{client_ip_for_flow, ClientIdentity};
use crate::ndpi::{NdpiEngine, NdpiHit};

#[derive(Default)]
pub struct Hints {
    pub identity: HashMap<Ipv4Addr, ClientIdentity>,
    sni: HashMap<(Ipv4Addr, Ipv4Addr, u16), String>,
    dns: HashMap<(Ipv4Addr, Ipv4Addr), String>,
    ndpi_apps: HashMap<(Ipv4Addr, Ipv4Addr, u16), NdpiHit>,
    pub ndpi: NdpiEngine,
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

    pub fn remember_dns(&mut self, client: Ipv4Addr, server: Ipv4Addr, name: String) {
        self.dns.insert((client, server), name);
    }

    pub fn remember_ndpi(&mut self, client: Ipv4Addr, server: Ipv4Addr, port: u16, hit: NdpiHit) {
        self.ndpi_apps.insert((client, server, port), hit);
    }

    pub fn ndpi_for(&self, flow: &Flow) -> Option<&NdpiHit> {
        let client = client_ip_for_flow(flow)?;
        let (server, port) = if flow.src == client {
            (flow.dst, flow.dst_port)
        } else {
            (flow.src, flow.src_port)
        };
        self.ndpi_apps.get(&(client, server, port))
    }

    pub fn dns_for(&self, flow: &Flow) -> Option<&str> {
        let client = client_ip_for_flow(flow)?;
        let server = if flow.src == client {
            flow.dst
        } else {
            flow.src
        };
        self.dns.get(&(client, server)).map(String::as_str)
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
        let ndpi = self.ndpi_for(flow);
        if let Some(hit) = ndpi {
            if hit.specific {
                return Classification {
                    app: hit.app.clone(),
                    category: hit.category.clone(),
                    confidence: "ndpi".to_string(),
                    evidence: format!("ndpi={}", hit.app),
                };
            }
        }
        if let Some(sni) = self.sni_for(flow) {
            return Classification {
                app: sni.to_string(),
                category: "web".to_string(),
                confidence: "sni".to_string(),
                evidence: format!("sni={sni}"),
            };
        }
        if let Some(name) = self.dns_for(flow) {
            return Classification {
                app: name.to_string(),
                category: "web".to_string(),
                confidence: "dns".to_string(),
                evidence: format!("dns={name}"),
            };
        }
        if let Some(hit) = ndpi {
            return Classification {
                app: hit.app.clone(),
                category: hit.category.clone(),
                confidence: "ndpi".to_string(),
                evidence: format!("ndpi={}", hit.app),
            };
        }
        classify(flow)
    }

    pub fn identity_for_flow(&self, flow: &Flow) -> Option<&ClientIdentity> {
        let ip = client_ip_for_flow(flow)?;
        self.identity.get(&ip)
    }
}
