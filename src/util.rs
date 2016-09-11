#![deny(missing_docs)]

/// Decode a hex sequence.
pub fn decode_hex(seq: &[u8]) -> Option<u64> {
    let mut result = 0;
    for c in seq {
        match (*c as char).to_digit(16) {
            Some(v) => result = result << 4 + v,
            None => return None,
        };
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
