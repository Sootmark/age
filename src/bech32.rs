//! Bech32 (BIP 173) as age uses it for keys: no length limit on the data
//! part, all lowercase or all uppercase, the checksum always computed over
//! the lowercase string.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const SEPARATOR: char = '1';
const CHECKSUM_LENGTH: usize = 6;
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// `data` under the human-readable part `hrp`, in lowercase. `hrp` must be
/// lowercase printable ASCII.
pub(crate) fn encode(hrp: &str, data: &[u8]) -> String {
    encode_groups(hrp, &regroup(data, 8, 5))
}

fn encode_groups(hrp: &str, groups: &[u8]) -> String {
    let checksum = checksum(hrp, groups);
    let mut text = String::with_capacity(hrp.len() + 1 + groups.len() + CHECKSUM_LENGTH);
    text.push_str(hrp);
    text.push(SEPARATOR);
    text.extend(
        groups
            .iter()
            .chain(&checksum)
            .map(|&v| char::from(CHARSET[usize::from(v)])),
    );
    text
}

/// The six checksum groups for `groups` under `hrp`.
fn checksum(hrp: &str, groups: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    let mut checked = expand_hrp(hrp);
    checked.extend_from_slice(groups);
    checked.extend_from_slice(&[0; CHECKSUM_LENGTH]);
    let checksum = polymod(&checked) ^ 1;
    std::array::from_fn(|i| ((checksum >> (5 * (CHECKSUM_LENGTH - 1 - i))) & 31) as u8)
}

/// The human-readable part, in lowercase, and the data of a Bech32 string.
pub(crate) fn decode(text: &str) -> Result<(String, Vec<u8>), &'static str> {
    let has_lower = text.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = text.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err("key mixes uppercase and lowercase");
    }
    let text = text.to_ascii_lowercase();
    let (hrp, data) = text
        .rsplit_once(SEPARATOR)
        .ok_or("key has no separator ('1')")?;
    if hrp.is_empty() || !hrp.bytes().all(|c| (33..=126).contains(&c)) {
        return Err("key has a malformed prefix");
    }
    if data.len() < CHECKSUM_LENGTH {
        return Err("key is too short");
    }
    let values = data
        .bytes()
        .map(|c| CHARSET.iter().position(|&v| v == c).map(|v| v as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or("key has a character outside the Bech32 alphabet")?;
    let mut checked = expand_hrp(hrp);
    checked.extend_from_slice(&values);
    if polymod(&checked) != 1 {
        return Err("key has a wrong checksum");
    }
    let payload = &values[..values.len() - CHECKSUM_LENGTH];
    let bytes = ungroup(payload).ok_or("key has malformed padding")?;
    Ok((hrp.to_owned(), bytes))
}

/// The prefix's characters as the checksum sees them.
fn expand_hrp(hrp: &str) -> Vec<u8> {
    let high = hrp.bytes().map(|c| c >> 5);
    let low = hrp.bytes().map(|c| c & 31);
    high.chain([0]).chain(low).collect()
}

fn polymod(values: &[u8]) -> u32 {
    values.iter().fold(1u32, |checksum, &value| {
        let top = checksum >> 25;
        let next = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
        GENERATOR
            .iter()
            .enumerate()
            .filter(|(i, _)| (top >> i) & 1 == 1)
            .fold(next, |acc, (_, g)| acc ^ g)
    })
}

/// `from`-bit groups as `to`-bit groups, the last one padded with zeros.
fn regroup(data: &[u8], from: u32, to: u32) -> Vec<u8> {
    let mut groups = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &value in data {
        acc = (acc << from) | u32::from(value);
        bits += from;
        while bits >= to {
            bits -= to;
            groups.push(((acc >> bits) & ((1 << to) - 1)) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        groups.push(((acc << (to - bits)) & ((1 << to) - 1)) as u8);
    }
    groups
}

/// 5-bit groups as bytes, or `None` if the padding isn't a short run of
/// zero bits (BIP 173's rule, so each byte string has one encoding).
fn ungroup(values: &[u8]) -> Option<Vec<u8>> {
    let leftover = values.len() * 5 % 8;
    if leftover >= 5 {
        return None;
    }
    let mut bytes = regroup(values, 5, 8);
    if leftover > 0 {
        // `regroup` padded the leftover bits into one more byte: they must
        // all be zero, and that byte isn't data.
        if bytes.pop() != Some(0) {
            return None;
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip_173_valid_strings() {
        for text in [
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        ] {
            decode(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        }
    }

    #[test]
    fn bip_173_invalid_strings() {
        for text in [
            "pzry9x0s0muk",  // no separator
            "1pzry9x0s0muk", // empty prefix
            "x1b4n0q5v",     // invalid data character
            "li1dgmt3",      // too short checksum
            "A1G7SGD8",      // checksum computed over uppercase
            "10a06t8",       // empty prefix
            "1qzzfhee",      // empty prefix
            "a12UEL5L",      // mixed case
        ] {
            assert!(decode(text).is_err(), "{text}");
        }
    }

    #[test]
    fn round_trips_any_length() {
        for length in 0..70 {
            let data: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode("age-secret-key-", &data);
            assert_eq!(decode(&text).unwrap(), ("age-secret-key-".to_owned(), data));
        }
    }

    #[test]
    fn rejects_non_zero_padding() {
        // One byte is two 5-bit groups, the second with two padding bits.
        let [high, low] = regroup(&[0xff], 8, 5)[..] else {
            unreachable!()
        };
        let forged = encode_groups("age", &[high, low | 1]);
        assert_eq!(decode(&forged), Err("key has malformed padding"));
        assert!(decode(&encode_groups("age", &[high, low])).is_ok());
    }
}
