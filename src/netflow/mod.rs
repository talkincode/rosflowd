pub mod v5;

use crate::error::{Error, Result};
use crate::flow::Flow;

pub fn decode(datagram: &[u8]) -> Result<Vec<Flow>> {
    if datagram.len() < 2 {
        return Err(Error::Decode("datagram shorter than version field"));
    }
    let version = u16::from_be_bytes([datagram[0], datagram[1]]);
    match version {
        5 => v5::decode(datagram),
        other => Err(Error::UnsupportedVersion(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_other_versions() {
        let mut buf = vec![0u8; 24];
        buf[0] = 0;
        buf[1] = 9;
        match decode(&buf) {
            Err(Error::UnsupportedVersion(9)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_short_datagram() {
        assert!(matches!(decode(&[0, 5]), Err(Error::Decode(_))));
    }
}
