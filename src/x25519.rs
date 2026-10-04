//! The X25519 recipient stanza: the file key wrapped for one public key.
//!
//! ```text
//! -> X25519 <ephemeral share, base64>
//! <file key sealed with ChaCha20-Poly1305, base64>
//! ```

use std::io;

use chacha20poly1305::{AeadInOut, Nonce, Tag};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::crypto::{cipher, hkdf, rng, FileKey, TAG_SIZE};
use crate::header::Stanza;
use crate::{base64, Error, Identity, Recipient};

const KIND: &str = "X25519";
const INFO: &[u8] = b"age-encryption.org/v1/X25519";
const SHARE_SIZE: usize = 32;
const BODY_SIZE: usize = 16 + TAG_SIZE;

/// The stanza that gives `file_key` to `recipient`, under a fresh
/// ephemeral key.
pub(crate) fn wrap(file_key: &FileKey, recipient: &Recipient) -> io::Result<Stanza> {
    let ephemeral = EphemeralSecret::random_from_rng(&mut rng());
    let share = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(recipient.key());
    if !shared.was_contributory() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("recipient {recipient} is a low-order point, not a usable key"),
        ));
    }
    let mut body = file_key.to_vec();
    let tag = cipher(&wrap_key(&shared, &share, recipient.key()))
        .encrypt_inout_detached(&Nonce::default(), &[], body.as_mut_slice().into())
        .expect("a file key is far below ChaCha20-Poly1305's length limit");
    body.extend_from_slice(&tag);
    Ok(Stanza {
        kind: KIND.to_owned(),
        args: vec![base64::encode(share.as_bytes())],
        body,
    })
}

/// The file key, from the first X25519 stanza one of `identities` opens.
/// Other kinds of stanzas are skipped.
pub(crate) fn unwrap(
    stanzas: &[Stanza],
    identities: &[Identity],
) -> Result<Option<FileKey>, Error> {
    for stanza in stanzas.iter().filter(|stanza| stanza.kind == KIND) {
        let (share, body) = parse(stanza)?;
        for identity in identities {
            let shared = identity.secret().diffie_hellman(&share);
            if !shared.was_contributory() {
                return Err(Error::MalformedHeader("X25519 share is a low-order point"));
            }
            let recipient = identity.to_public();
            if let Some(file_key) = open(&wrap_key(&shared, &share, recipient.key()), &body) {
                return Ok(Some(file_key));
            }
        }
    }
    Ok(None)
}

/// The share and sealed file key, checked before any decryption: one
/// canonical 32-byte share and a 32-byte body.
fn parse(stanza: &Stanza) -> Result<(PublicKey, [u8; BODY_SIZE]), Error> {
    let [share] = stanza.args.as_slice() else {
        return Err(Error::MalformedHeader(
            "X25519 stanza must have exactly one share",
        ));
    };
    let share: [u8; SHARE_SIZE] = base64::decode(share.as_bytes())
        .and_then(|share| share.try_into().ok())
        .ok_or(Error::MalformedHeader("X25519 share is not 32 bytes"))?;
    let body = stanza
        .body
        .as_slice()
        .try_into()
        .map_err(|_| Error::MalformedHeader("X25519 stanza body is not 32 bytes"))?;
    Ok((PublicKey::from(share), body))
}

fn wrap_key(shared: &SharedSecret, share: &PublicKey, recipient: &PublicKey) -> [u8; 32] {
    let mut salt = [0; 2 * SHARE_SIZE];
    salt[..SHARE_SIZE].copy_from_slice(share.as_bytes());
    salt[SHARE_SIZE..].copy_from_slice(recipient.as_bytes());
    hkdf(&salt, shared.as_bytes(), INFO)
}

/// The file key in `body`, or `None` if `wrap_key` doesn't open it.
fn open(wrap_key: &[u8; 32], body: &[u8; BODY_SIZE]) -> Option<FileKey> {
    let (sealed, tag) = body.split_at(body.len() - TAG_SIZE);
    let mut file_key: FileKey = sealed.try_into().ok()?;
    cipher(wrap_key)
        .decrypt_inout_detached(
            &Nonce::default(),
            &[],
            file_key.as_mut_slice().into(),
            &Tag::try_from(tag).ok()?,
        )
        .ok()?;
    Some(file_key)
}
