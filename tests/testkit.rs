//! The age test vectors from C2SP's CCTV (`tests/fixtures/cctv/`, 0BSD):
//! each file is decrypted with its identities and must end as the vector
//! expects (success, no match, HMAC failure, header failure or payload
//! failure), and all the plaintext released, even before a failure, must
//! hash to the expected value. Vectors for what this crate doesn't do (the
//! ASCII armor, passphrases, post-quantum identities) are skipped, and
//! counted so that new upstream vectors aren't skipped unnoticed.

use std::fmt::Write;
use std::fs;
use std::io::Read;
use std::path::Path;

use age::{Error, Identity};
use sha2::{Digest, Sha256};

/// Vectors this crate runs: 69 of the 147, the others being 37 armored
/// files, 24 for passphrases only and 17 for post-quantum identities only.
const RUN: usize = 69;

struct Vector {
    name: String,
    expect: String,
    payload_hash: Option<String>,
    identities: Vec<Identity>,
    unsupported: Option<&'static str>,
    file: Vec<u8>,
}

fn read_vector(path: &Path) -> Vector {
    let bytes = fs::read(path).unwrap();
    let split = bytes.windows(2).position(|w| w == b"\n\n").unwrap();
    let mut vector = Vector {
        name: path.file_name().unwrap().to_string_lossy().into_owned(),
        expect: String::new(),
        payload_hash: None,
        identities: Vec::new(),
        unsupported: None,
        file: bytes[split + 2..].to_vec(),
    };
    let mut skipped_identity = false;
    for line in std::str::from_utf8(&bytes[..split]).unwrap().lines() {
        let (key, value) = line.split_once(": ").unwrap();
        match key {
            "expect" => value.clone_into(&mut vector.expect),
            "payload" => vector.payload_hash = Some(value.to_owned()),
            "identity" => match value.parse() {
                Ok(identity) => vector.identities.push(identity),
                Err(_) if value.starts_with("AGE-SECRET-KEY-PQ-") => skipped_identity = true,
                Err(error) => panic!("{}: {value}: {error}", vector.name),
            },
            "passphrase" => skipped_identity = true,
            "armored" if value == "yes" => vector.unsupported = Some("armored"),
            "compressed" => {
                assert_eq!(value, "zlib");
                vector.file = miniz_oxide::inflate::decompress_to_vec_zlib(&vector.file).unwrap();
            }
            _ => {}
        }
    }
    if vector.identities.is_empty() && skipped_identity && vector.unsupported.is_none() {
        vector.unsupported = Some("passphrase or post-quantum identity only");
    }
    vector
}

/// How decryption ended, and the plaintext released on the way.
fn decrypt(vector: &Vector) -> (&'static str, Vec<u8>) {
    let mut decryptor = match age::decrypt(vector.file.as_slice(), &vector.identities) {
        Ok(decryptor) => decryptor,
        Err(Error::MalformedHeader(_)) => return ("header failure", Vec::new()),
        Err(Error::NoMatchingIdentity) => return ("no match", Vec::new()),
        Err(Error::HeaderMac) => return ("HMAC failure", Vec::new()),
        Err(Error::Io(error)) => panic!("{}: reading a slice failed: {error}", vector.name),
    };
    let mut plaintext = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        match decryptor.read(&mut buffer) {
            Ok(0) => return ("success", plaintext),
            Ok(count) => plaintext.extend_from_slice(&buffer[..count]),
            Err(_) => return ("payload failure", plaintext),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").expect("writing to a String");
        text
    })
}

#[test]
fn every_vector_ends_as_expected() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cctv");
    let mut paths: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "LICENSE")
        .collect();
    paths.sort();

    let mut run = 0;
    let mut failures = Vec::new();
    for path in &paths {
        let vector = read_vector(path);
        if vector.unsupported.is_some() {
            continue;
        }
        run += 1;
        let (outcome, plaintext) = decrypt(&vector);
        if outcome != vector.expect {
            failures.push(format!(
                "{}: {outcome}, expected {}",
                vector.name, vector.expect
            ));
        } else if let Some(expected) = &vector.payload_hash {
            let hash = hex(&Sha256::digest(&plaintext));
            if &hash != expected {
                failures.push(format!("{}: plaintext hash {hash}", vector.name));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(run, RUN, "vectors run (of {})", paths.len());
}
