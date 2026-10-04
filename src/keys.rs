//! X25519 keys and their Bech32 spellings: `age1…` recipients and
//! `AGE-SECRET-KEY-1…` identities.

use std::fmt;
use std::str::FromStr;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::bech32;
use crate::crypto::rng;

const RECIPIENT_PREFIX: &str = "age";
const IDENTITY_PREFIX: &str = "age-secret-key-";
const KEY_SIZE: usize = 32;

/// Who a file is encrypted to: an X25519 public key, written `age1…`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Recipient(PublicKey);

impl Recipient {
    pub(crate) fn key(&self) -> &PublicKey {
        &self.0
    }
}

impl FromStr for Recipient {
    type Err = KeyError;

    /// Reads `age1…` (or the same in uppercase).
    fn from_str(text: &str) -> Result<Self, KeyError> {
        let bytes = decode_key(
            text,
            RECIPIENT_PREFIX,
            "key is not an X25519 recipient (age1…)",
        )?;
        Ok(Self(PublicKey::from(bytes)))
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bech32::encode(RECIPIENT_PREFIX, self.0.as_bytes()))
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({self})")
    }
}

/// What decrypts a file: an X25519 secret key, written
/// `AGE-SECRET-KEY-1…`. The key is wiped from memory when dropped; its
/// `Debug` output shows only the matching recipient.
#[derive(Clone)]
pub struct Identity(StaticSecret);

impl Identity {
    /// A new random identity, from the operating system's random source.
    ///
    /// # Panics
    ///
    /// If the operating system's random source fails.
    #[must_use]
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(&mut rng()))
    }

    /// The recipient files for this identity are encrypted to.
    #[must_use]
    pub fn to_public(&self) -> Recipient {
        Recipient(PublicKey::from(&self.0))
    }

    pub(crate) fn secret(&self) -> &StaticSecret {
        &self.0
    }
}

impl FromStr for Identity {
    type Err = KeyError;

    /// Reads `AGE-SECRET-KEY-1…` (or the same in lowercase).
    fn from_str(text: &str) -> Result<Self, KeyError> {
        let bytes = decode_key(
            text,
            IDENTITY_PREFIX,
            "key is not an X25519 identity (AGE-SECRET-KEY-1…)",
        )?;
        Ok(Self(StaticSecret::from(bytes)))
    }
}

impl fmt::Display for Identity {
    /// The secret key, as `AGE-SECRET-KEY-1…`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = bech32::encode(IDENTITY_PREFIX, self.0.as_bytes());
        f.write_str(&text.to_ascii_uppercase())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity(for {})", self.to_public())
    }
}

/// The identities in an identity file, as `age-keygen` writes it: one
/// `AGE-SECRET-KEY-1…` per line; blank lines and `#` comments are skipped.
///
/// # Errors
///
/// If a line is anything else, or there is no identity at all.
pub fn parse_identities(text: &str) -> Result<Vec<Identity>, KeyError> {
    let mut identities = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let identity = line.parse().map_err(|error: KeyError| KeyError {
            line: Some(index + 1),
            ..error
        })?;
        identities.push(identity);
    }
    if identities.is_empty() {
        return Err(KeyError::new("no identity in the file"));
    }
    Ok(identities)
}

fn decode_key(
    text: &str,
    prefix: &str,
    wrong_kind: &'static str,
) -> Result<[u8; KEY_SIZE], KeyError> {
    let (hrp, data) = bech32::decode(text).map_err(KeyError::new)?;
    if hrp != prefix {
        return Err(KeyError::new(wrong_kind));
    }
    data.try_into()
        .map_err(|_| KeyError::new("key is not 32 bytes long"))
}

/// Why a key couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError {
    line: Option<usize>,
    reason: &'static str,
}

impl KeyError {
    fn new(reason: &'static str) -> Self {
        Self { line: None, reason }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.reason),
            None => f.write_str(self.reason),
        }
    }
}

impl std::error::Error for KeyError {}
