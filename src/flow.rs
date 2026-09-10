use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
    pub tcp_flags: u8,
    pub unix_secs: u32,
}

impl Flow {
    pub fn service_port(&self) -> u16 {
        if well_known(self.src_port) && !well_known(self.dst_port) {
            self.src_port
        } else {
            self.dst_port
        }
    }
}

fn well_known(port: u16) -> bool {
    matches!(
        port,
        20 | 21
            | 22
            | 25
            | 53
            | 67
            | 68
            | 80
            | 110
            | 123
            | 143
            | 161
            | 443
            | 465
            | 587
            | 853
            | 993
            | 995
            | 1900
            | 3478
            | 5353
            | 8080
            | 8443
            | 8728
            | 8729
    )
}
