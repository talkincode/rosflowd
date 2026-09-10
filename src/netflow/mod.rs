pub mod fields;
pub mod ipfix;
pub mod v5;
pub mod v9;

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::flow::Flow;
use crate::netflow::fields::Template;

#[derive(Debug, Default)]
pub struct Decoder {
    templates: HashMap<(u32, u16), Template>,
}

impl Decoder {
    pub fn decode(&mut self, datagram: &[u8]) -> Result<Vec<Flow>> {
        if datagram.len() < 2 {
            return Err(Error::Decode("datagram shorter than version field"));
        }
        let version = u16::from_be_bytes([datagram[0], datagram[1]]);
        match version {
            5 => v5::decode(datagram),
            9 => v9::decode(&mut self.templates, datagram),
            10 => ipfix::decode(&mut self.templates, datagram),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

pub fn decode(datagram: &[u8]) -> Result<Vec<Flow>> {
    Decoder::default().decode(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_other_versions() {
        let mut buf = vec![0u8; 24];
        buf[0] = 0;
        buf[1] = 8;
        match decode(&buf) {
            Err(Error::UnsupportedVersion(8)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_short_datagram() {
        assert!(matches!(decode(&[0, 5]), Err(Error::Decode(_))));
    }
}
