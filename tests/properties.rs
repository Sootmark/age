//! Hostile input: arbitrary bytes, as a whole file or after a valid header,
//! never make decryption panic, and no change to a valid file, anywhere,
//! gets past decryption: the result is an error, and any plaintext released
//! before it is genuine.

use std::io::{Read, Write};
use std::sync::OnceLock;

use age::{decrypt, Encryptor, Identity};
use proptest::prelude::*;

struct Sample {
    identity: Identity,
    plaintext: Vec<u8>,
    file: Vec<u8>,
}

fn sample(size: usize) -> Sample {
    let identity = Identity::generate();
    let other = Identity::generate().to_public();
    let plaintext: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
    let mut encryptor = Encryptor::new(Vec::new(), &[other, identity.to_public()]).unwrap();
    encryptor.write_all(&plaintext).unwrap();
    let file = encryptor.finish().unwrap();
    Sample {
        identity,
        plaintext,
        file,
    }
}

/// A small file: one chunk, two recipients.
fn small() -> &'static Sample {
    static SAMPLE: OnceLock<Sample> = OnceLock::new();
    SAMPLE.get_or_init(|| sample(100))
}

/// Two chunks, the second short.
fn large() -> &'static Sample {
    static SAMPLE: OnceLock<Sample> = OnceLock::new();
    SAMPLE.get_or_init(|| sample(64 * 1024 + 1000))
}

/// Decrypts `file`; `Ok` with the plaintext, or `Err` with what was
/// released before the error.
fn attempt(file: &[u8], identity: &Identity) -> Result<Vec<u8>, Vec<u8>> {
    let Ok(mut decryptor) = decrypt(file, std::slice::from_ref(identity)) else {
        return Err(Vec::new());
    };
    let mut out = Vec::new();
    match decryptor.read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(out),
    }
}

fn assert_rejected(sample: &Sample, file: &[u8], what: &str) {
    match attempt(file, &sample.identity) {
        Ok(_) => panic!("{what}: decrypted"),
        Err(released) => assert!(
            sample.plaintext.starts_with(&released),
            "{what}: released plaintext that isn't genuine"
        ),
    }
}

#[test]
fn the_samples_decrypt() {
    for sample in [small(), large()] {
        assert_eq!(
            attempt(&sample.file, &sample.identity),
            Ok(sample.plaintext.clone())
        );
    }
}

#[test]
fn every_single_bit_flip_in_a_small_file_is_caught() {
    let sample = small();
    for index in 0..sample.file.len() {
        for bit in 0..8 {
            let mut file = sample.file.clone();
            file[index] ^= 1 << bit;
            assert_rejected(sample, &file, &format!("bit {bit} of byte {index}"));
        }
    }
}

#[test]
fn every_truncation_of_a_small_file_is_caught() {
    let sample = small();
    for end in 0..sample.file.len() {
        assert_rejected(sample, &sample.file[..end], &format!("cut at {end}"));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = attempt(&bytes, &small().identity);
    }

    #[test]
    fn arbitrary_payloads_after_a_valid_header_fail(
        payload in proptest::collection::vec(any::<u8>(), 0..70_000),
    ) {
        let sample = small();
        // Header and nonce: everything before the single sealed chunk.
        let mut file = sample.file[..sample.file.len() - (100 + 16)].to_vec();
        file.extend_from_slice(&payload);
        prop_assert!(attempt(&file, &sample.identity).is_err());
    }

    #[test]
    fn arbitrary_header_lines_never_panic(
        lines in proptest::collection::vec("(-> |---|age-encryption.org/)?[ -~]{0,80}", 0..6),
    ) {
        let mut file = b"age-encryption.org/v1\n".to_vec();
        for line in lines {
            file.extend_from_slice(line.as_bytes());
            file.push(b'\n');
        }
        let _ = attempt(&file, &small().identity);
    }

    #[test]
    fn any_change_to_a_two_chunk_file_is_caught(
        index in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let sample = large();
        let mut file = sample.file.clone();
        let index = index.index(file.len());
        file[index] ^= mask;
        assert_rejected(sample, &file, &format!("byte {index} ^ {mask:#04x}"));
    }
}
