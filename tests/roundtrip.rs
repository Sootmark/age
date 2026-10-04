//! Encrypting and decrypting with this crate: sizes around the 64 KiB
//! chunk boundary, several recipients, the wrong identity, files cut short
//! or extended, and the keys' spellings.

use std::io::{self, Read, Write};

use age::{decrypt, parse_identities, Encryptor, Error, Identity, Recipient};

const CHUNK: usize = 64 * 1024;
/// The example keys in the age specification.
const SPEC_IDENTITY: &str =
    "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX";
const SPEC_RECIPIENT: &str = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj";

fn plaintext(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn encrypt(data: &[u8], recipients: &[Recipient]) -> Vec<u8> {
    let mut encryptor = Encryptor::new(Vec::new(), recipients).unwrap();
    encryptor.write_all(data).unwrap();
    encryptor.finish().unwrap()
}

/// The plaintext released, and how reading ended.
fn read_all(file: &[u8], identity: &Identity) -> (Vec<u8>, io::Result<usize>) {
    let mut out = Vec::new();
    let result = decrypt(file, std::slice::from_ref(identity))
        .unwrap()
        .read_to_end(&mut out);
    (out, result)
}

#[test]
fn round_trips_at_every_chunk_boundary() {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    for size in [
        0,
        1,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK,
        3 * CHUNK + 7,
        5 << 20,
    ] {
        let data = plaintext(size);
        let file = encrypt(&data, &[recipient]);
        let chunks = size.div_ceil(CHUNK).max(1);
        assert!(file.len() > size + 16 * chunks, "{size}: chunk count");
        let (out, result) = read_all(&file, &identity);
        result.unwrap();
        assert!(out == data, "{size} bytes");
    }
}

#[test]
fn writes_of_any_size_give_the_same_plaintext() {
    let identity = Identity::generate();
    let data = plaintext(2 * CHUNK + 3);
    for piece in [1, 7, CHUNK - 1, CHUNK, CHUNK + 1] {
        let mut encryptor = Encryptor::new(Vec::new(), &[identity.to_public()]).unwrap();
        for part in data.chunks(piece) {
            encryptor.write_all(part).unwrap();
        }
        encryptor.flush().unwrap();
        let (out, result) = read_all(&encryptor.finish().unwrap(), &identity);
        result.unwrap();
        assert!(out == data, "pieces of {piece}");
    }
}

#[test]
fn every_recipient_can_decrypt_and_no_one_else() {
    let identities: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let recipients: Vec<Recipient> = identities.iter().map(Identity::to_public).collect();
    let data = plaintext(1000);
    let file = encrypt(&data, &recipients);
    for identity in &identities {
        assert_eq!(read_all(&file, identity).0, data);
    }
    let stranger = Identity::generate();
    assert!(matches!(
        decrypt(file.as_slice(), std::slice::from_ref(&stranger)),
        Err(Error::NoMatchingIdentity)
    ));
    assert!(matches!(
        decrypt(file.as_slice(), &[]),
        Err(Error::NoMatchingIdentity)
    ));
    // The right identity among wrong ones is found.
    let mut keyring = vec![stranger];
    keyring.push(identities[2].clone());
    assert!(decrypt(file.as_slice(), &keyring).is_ok());
}

#[test]
fn a_file_cut_short_or_extended_fails() {
    let identity = Identity::generate();
    let data = plaintext(CHUNK + 100);
    let file = encrypt(&data, &[identity.to_public()]);
    let sealed_chunk = CHUNK + 16;
    let final_chunk = 100 + 16;
    let nonce_end = file.len() - sealed_chunk - final_chunk;

    // Cut after the first chunk: that chunk is genuine, then the end is missing.
    let (out, result) = read_all(&file[..nonce_end + sealed_chunk], &identity);
    assert_eq!(out, data[..CHUNK]);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);

    // Cut inside the final chunk, or right after the nonce.
    for end in [
        file.len() - 1,
        file.len() - 50,
        nonce_end + sealed_chunk + 3,
        nonce_end,
    ] {
        let (out, result) = read_all(&file[..end], &identity);
        assert!(data.starts_with(&out));
        assert!(out.len() < data.len());
        result.unwrap_err();
    }

    // Cut inside the nonce: the header promised a payload.
    assert!(matches!(
        decrypt(&file[..nonce_end - 1], std::slice::from_ref(&identity)),
        Err(Error::MalformedHeader(_))
    ));

    // Data after the final chunk.
    let mut extended = file.clone();
    extended.push(0);
    let (_, result) = read_all(&extended, &identity);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_failed_decryptor_keeps_failing() {
    let identity = Identity::generate();
    let mut file = encrypt(&plaintext(10), &[identity.to_public()]);
    *file.last_mut().unwrap() ^= 1;
    let mut decryptor = decrypt(file.as_slice(), &[identity]).unwrap();
    let mut buffer = [0; 64];
    for _ in 0..3 {
        let error = decryptor.read(&mut buffer).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn encryption_needs_a_usable_recipient() {
    let error = Encryptor::new(Vec::new(), &[]).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    // The all-zero point: every shared secret with it is zero.
    let low_order: Recipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z"
        .parse()
        .unwrap();
    let error = Encryptor::new(Vec::new(), &[low_order]).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

/// Accepts `limit` bytes, then fails.
struct FailingWriter {
    limit: usize,
}

impl Write for FailingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.limit == 0 {
            return Err(io::Error::other("disk full"));
        }
        let count = data.len().min(self.limit);
        self.limit -= count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_encryptor_that_failed_refuses_to_go_on() {
    let recipient = Identity::generate().to_public();
    let mut encryptor = Encryptor::new(FailingWriter { limit: 1000 }, &[recipient]).unwrap();
    let error = encryptor.write_all(&plaintext(3 * CHUNK)).unwrap_err();
    assert_eq!(error.to_string(), "disk full");
    encryptor.write_all(b"more").unwrap_err();
    encryptor.finish().err().unwrap();
}

#[test]
fn the_specification_example_keys() {
    let identity: Identity =
        "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
            .parse()
            .unwrap();
    assert_eq!(
        identity.to_public().to_string(),
        "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
    );
    assert_eq!(
        identity.to_string(),
        "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
    );
    let lowercase: Identity = identity.to_string().to_lowercase().parse().unwrap();
    assert_eq!(lowercase.to_public(), identity.to_public());
}

#[test]
fn keys_round_trip_and_debug_hides_the_secret() {
    let identity = Identity::generate();
    let text = identity.to_string();
    assert!(text.starts_with("AGE-SECRET-KEY-1"));
    let again: Identity = text.parse().unwrap();
    assert_eq!(again.to_public(), identity.to_public());
    let recipient = identity.to_public();
    assert_eq!(
        recipient.to_string().parse::<Recipient>().unwrap(),
        recipient
    );

    let debug = format!("{identity:?}");
    assert!(debug.contains(&recipient.to_string()));
    assert!(!debug.contains(&text[16..30]));
}

#[test]
fn malformed_keys_are_refused_with_a_reason() {
    let identity = SPEC_IDENTITY;
    let recipient = SPEC_RECIPIENT;
    // "AGE-SECRET-KEY-1g…": one lowercase letter.
    let mixed = format!("{}g{}", &identity[..16], &identity[17..]);
    // The last checksum character changed ('X' to 'Q').
    let damaged = format!("{}Q", &identity[..identity.len() - 1]);
    for (text, reason) in [
        (mixed.as_str(), "key mixes uppercase and lowercase"),
        (damaged.as_str(), "key has a wrong checksum"),
        ("age1", "key is too short"),
        ("hello", "key has no separator ('1')"),
    ] {
        let error = text.parse::<Identity>().unwrap_err();
        assert_eq!(error.to_string(), reason, "{text}");
    }
    assert_eq!(
        identity.parse::<Recipient>().unwrap_err().to_string(),
        "key is not an X25519 recipient (age1…)"
    );
    assert_eq!(
        recipient.parse::<Identity>().unwrap_err().to_string(),
        "key is not an X25519 identity (AGE-SECRET-KEY-1…)"
    );
    // A valid key of another kind: the specification's tagged recipient.
    assert_eq!(
        "age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e"
            .parse::<Recipient>()
            .unwrap_err()
            .to_string(),
        "key is not an X25519 recipient (age1…)"
    );
}

#[test]
fn identity_files_skip_comments_and_report_lines() {
    let first = Identity::generate();
    let second = Identity::generate();
    let file = format!(
        "# created: 2026-10-04T12:00:00Z\r\n# public key: {}\r\n{first}\r\n\n  {second}  \n",
        first.to_public()
    );
    let identities = parse_identities(&file).unwrap();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[1].to_public(), second.to_public());

    let error = parse_identities(&format!("# comment\n{first}\nnot a key\n")).unwrap_err();
    assert_eq!(error.to_string(), "line 3: key has no separator ('1')");
    let error = parse_identities("# only a comment\n").unwrap_err();
    assert_eq!(error.to_string(), "no identity in the file");
}
