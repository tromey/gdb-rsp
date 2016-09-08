#![deny(missing_docs)]

/// Decode a hex sequence.
pub fn decode_hex(seq: &[u8]) -> Option<u64> {
    let mut result = 0;
    for c in seq {
        let digit = match *c {
            b'0'...b'9' => c - b'0',
            b'a'...b'f' => c - b'a' + 10,
            b'A'...b'F' => c - b'A' + 10,
            _ => { return None; },
        };
        result = result * 16 + digit as u64;
    }
    Some(result)
}

#[cfg(test)]
mod test {
    #[test]
    fn decode_hex() {
        assert_eq!(super::decode_hex(b"000a").unwrap(), 10);
        assert_eq!(super::decode_hex(b"f01").unwrap(), 3841);
        assert_eq!(super::decode_hex(b"hi"), None);
    }
}
