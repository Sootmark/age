//! Streaming encryption and decryption in the [age v1 file
//! format](https://c2sp.org/age), for X25519 recipients.
//!
//! An age file is a textual header, which wraps a random 128-bit file key
//! for each recipient and ends with a MAC, then the payload: the plaintext
//! in 64 KiB chunks, each sealed with ChaCha20-Poly1305 (STREAM). Files of
//! any size are encrypted and decrypted in constant memory, and are
//! readable by `age` and `rage`, which read this crate's files too.
//!
//! ```
//! use std::io::{Read, Write};
//!
//! let identity = age::Identity::generate();
//! let recipient: age::Recipient = identity.to_public().to_string().parse()?;
//!
//! let mut encryptor = age::Encryptor::new(Vec::new(), &[recipient])?;
//! encryptor.write_all(b"triage archive")?;
//! let file = encryptor.finish()?;
//!
//! let mut plaintext = Vec::new();
//! age::decrypt(file.as_slice(), &[identity])?.read_to_end(&mut plaintext)?;
//! assert_eq!(plaintext, b"triage archive");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The format (header, stanzas, base64, Bech32 keys, STREAM) is written
//! here; the cryptography comes from RustCrypto (`chacha20poly1305`,
//! `hkdf`, `hmac`, `sha2`) and dalek (`x25519-dalek`).
//!
//! Not supported: passphrase (scrypt), post-quantum and plugin recipients,
//! whose stanzas are skipped when decrypting, and the ASCII-armored form.

mod base64;
mod bech32;
mod crypto;
mod decrypt;
mod encrypt;
mod header;
mod keys;
mod seek;
mod stream;
mod x25519;

use std::{fmt, io};

pub use decrypt::{decrypt, Decryptor};
pub use encrypt::Encryptor;
pub use keys::{parse_identities, Identity, KeyError, Recipient};
pub use seek::{decrypt_seekable, SeekableDecryptor};

/// This crate's version, for records of what encrypted or decrypted a file.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Why an age file couldn't be opened. Errors in the payload come later,
/// from [`Decryptor`]'s reads.
#[derive(Debug)]
pub enum Error {
    /// Not an age v1 file, or a header that breaks the format's rules.
    MalformedHeader(&'static str),
    /// None of the identities opens any of the file's recipient stanzas.
    NoMatchingIdentity,
    /// The header's MAC doesn't match: the header was altered.
    HeaderMac,
    /// Reading the header failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHeader(reason) => write!(f, "malformed age header: {reason}"),
            Self::NoMatchingIdentity => {
                f.write_str("no identity matches any of the age file's recipients")
            }
            Self::HeaderMac => f.write_str("age header MAC doesn't match: the header was altered"),
            Self::Io(error) => write!(f, "reading the age header failed: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
