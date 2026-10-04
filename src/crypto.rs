//! The primitives age is built on, from RustCrypto and dalek, in the shapes
//! age uses them. No cryptography is implemented in this crate.

use std::io;

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use getrandom::rand_core::UnwrapErr;
use getrandom::SysRng;
use hkdf::Hkdf;
use sha2::Sha256;

/// The symmetric key a file is encrypted with.
pub(crate) type FileKey = [u8; 16];

/// A ChaCha20-Poly1305 authentication tag's size.
pub(crate) const TAG_SIZE: usize = 16;

/// HKDF-SHA-256 with a 32-byte output, as every age key is derived.
pub(crate) fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    key
}

/// ChaCha20-Poly1305 keyed with `key`; the key is wiped when dropped.
pub(crate) fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&(*key).into())
}

/// `N` bytes from the operating system's random source.
pub(crate) fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("random source failed: {error}")))?;
    Ok(bytes)
}

/// The operating system's random source, for dalek's key generators, which
/// keep the secret in types that wipe it. Panics if the source fails.
pub(crate) fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}
