//! Base64 as age writes it: the standard alphabet (RFC 4648, section 4)
//! without `=` padding. Decoding is strict: only canonical encodings are
//! accepted, so every value has exactly one spelling and a header can't be
//! altered without changing its MAC.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Unpadded base64 of `data`.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len().div_ceil(3) * 4);
    for group in data.chunks(3) {
        let bits = group.iter().enumerate().fold(0u32, |bits, (i, &byte)| {
            bits | u32::from(byte) << (16 - 8 * i)
        });
        // One input byte gives two characters, two give three, three give four.
        for i in 0..=group.len() {
            let index = (bits >> (18 - 6 * i)) & 0x3f;
            text.push(char::from(ALPHABET[index as usize]));
        }
    }
    text
}

/// The bytes `text` encodes, or `None` unless it is canonical unpadded
/// base64: alphabet characters only, no `=`, a length that some byte string
/// encodes to, and unused trailing bits zero.
pub(crate) fn decode(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut data = Vec::with_capacity(text.len() * 3 / 4);
    for group in text.chunks(4) {
        let mut bits = 0u32;
        for (i, &c) in group.iter().enumerate() {
            bits |= u32::from(value(c)?) << (18 - 6 * i);
        }
        let bytes = group.len() - 1;
        // Bits past the last whole byte must be zero, or two spellings
        // would decode to the same bytes.
        if bits & (0x00ff_ffff >> (8 * bytes)) != 0 {
            return None;
        }
        data.extend_from_slice(&bits.to_be_bytes()[1..=bytes]);
    }
    Some(data)
}

/// Whether `c` is a base64 alphabet character.
pub(crate) fn is_alphabet(c: u8) -> bool {
    value(c).is_some()
}

fn value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors_without_padding() {
        for (data, text) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(data.as_bytes()), text);
            assert_eq!(decode(text.as_bytes()).unwrap(), data.as_bytes());
        }
    }

    #[test]
    fn every_byte_value_round_trips() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(encode(&data).as_bytes()).unwrap(), data);
    }

    #[test]
    fn rejects_padding_bad_lengths_and_strange_characters() {
        for text in [
            "Zg==", "Zm8=", "Z", "Zm9vY", "Zm9v\n", "Zm-v", "Zm_v", "Zm 9",
        ] {
            assert_eq!(decode(text.as_bytes()), None, "{text:?}");
        }
    }

    #[test]
    fn rejects_non_zero_trailing_bits() {
        // "Zh" and "Zm9" with a low bit set spell the same bytes as "Zg"
        // and "Zm8".
        assert_eq!(decode(b"Zh"), None);
        assert_eq!(decode(b"Zm9"), None);
    }
}
