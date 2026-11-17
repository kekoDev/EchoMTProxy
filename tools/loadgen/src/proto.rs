//! What the fake clients and the fake DC say to each other inside the
//! proxied stream. The proxy relays these bytes without looking at them.

/// First bytes a client sends: who it is and what it wants.
pub const HEADER_LEN: usize = 16;
const MAGIC: [u8; 8] = *b"EMPLGEN1";
/// The DC's answer to a header. A real DC would never send this, which is how
/// a client knows it is not talking to Telegram.
pub const ACK: [u8; 8] = *b"EMPLGACK";
/// A download request: how many bytes the DC should send, little-endian.
pub const REQUEST_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Stay connected and silent.
    Idle = 0,
    /// The DC sends back whatever it receives.
    Echo = 1,
    /// The client asks for N bytes at a time and the DC sends them.
    Download = 2,
    /// The DC reads and discards.
    Upload = 3,
}

impl Op {
    fn from_byte(byte: u8) -> Option<Self> {
        [Self::Idle, Self::Echo, Self::Download, Self::Upload]
            .into_iter()
            .find(|op| *op as u8 == byte)
    }
}

pub fn header(op: Op) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..8].copy_from_slice(&MAGIC);
    out[8] = op as u8;
    out
}

pub fn parse_header(bytes: &[u8; HEADER_LEN]) -> Option<Op> {
    if bytes[..8] != MAGIC || bytes[9..].iter().any(|b| *b != 0) {
        return None;
    }
    Op::from_byte(bytes[8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_for_every_op() {
        for op in [Op::Idle, Op::Echo, Op::Download, Op::Upload] {
            assert_eq!(parse_header(&header(op)), Some(op));
        }
    }

    #[test]
    fn anything_else_is_rejected() {
        assert_eq!(parse_header(&[0; HEADER_LEN]), None);
        let mut bad = header(Op::Echo);
        bad[8] = 9;
        assert_eq!(parse_header(&bad), None);
        let mut bad = header(Op::Echo);
        bad[0] ^= 1;
        assert_eq!(parse_header(&bad), None);
        let mut bad = header(Op::Echo);
        bad[15] = 1;
        assert_eq!(parse_header(&bad), None);
        // A header echoed back is not an acknowledgement.
        assert_ne!(header(Op::Echo)[..8], ACK);
    }
}
