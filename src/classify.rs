use crate::flow::Flow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub app: String,
    pub category: String,
    pub confidence: String,
    pub evidence: String,
}

pub fn classify(flow: &Flow) -> Classification {
    let port = flow.service_port();
    let (app, category) = match (flow.proto, port) {
        (6 | 17, 53) => ("dns", "network"),
        (17, 5353) => ("mdns", "network"),
        (17, 67 | 68) => ("dhcp", "network"),
        (17, 123) => ("ntp", "network"),
        (17, 1900) => ("ssdp", "network"),
        (17, 3478) => ("stun", "realtime"),
        (6, 22) => ("ssh", "remote"),
        (6, 25 | 465 | 587) => ("smtp", "mail"),
        (6, 110 | 995) => ("pop3", "mail"),
        (6, 143 | 993) => ("imap", "mail"),
        (6, 80 | 8080) => ("http", "web"),
        (6 | 17, 443 | 8443) => ("tls", "web"),
        (6, 853) => ("dot", "network"),
        (6, 8728 | 8729) => ("routeros-api", "mgmt"),
        (6, 21) => ("ftp", "file"),
        (17, 161) => ("snmp", "mgmt"),
        _ => {
            return Classification {
                app: "unknown".into(),
                category: "unknown".into(),
                confidence: "unknown".into(),
                evidence: format!("proto={}/port={}", flow.proto, port),
            };
        }
    };
    Classification {
        app: app.into(),
        category: category.into(),
        confidence: "port".into(),
        evidence: format!("proto={}/port={port}", flow.proto),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn flow(proto: u8, sport: u16, dport: u16) -> Flow {
        Flow {
            src: Ipv4Addr::new(10, 0, 0, 2),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            src_port: sport,
            dst_port: dport,
            proto,
            packets: 1,
            bytes: 1,
            tcp_flags: 0,
            unix_secs: 0,
        }
    }

    #[test]
    fn https_is_tls_port() {
        let c = classify(&flow(6, 49152, 443));
        assert_eq!(c.app, "tls");
        assert_eq!(c.confidence, "port");
    }

    #[test]
    fn unknown_port() {
        let c = classify(&flow(6, 49152, 65000));
        assert_eq!(c.app, "unknown");
        assert_eq!(c.confidence, "unknown");
    }
}
