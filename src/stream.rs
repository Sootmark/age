//! The payload: STREAM over ChaCha20-Poly1305 in 64 KiB chunks.
//!
//! The payload key is derived from the file key and a 16-byte nonce that
//! starts the payload. Each chunk's nonce is an 11-byte big-endian counter
//! and a byte that is 1 for the final chunk, 0 otherwise, so chunks can't be
//! reordered, dropped or cut short without failing authentication.

use std::io;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, Nonce, Tag};

use crate::crypto::{cipher, hkdf, FileKey, TAG_SIZE};

/// The plaintext in each chunk but the last.
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;
/// A full chunk with its tag.
pub(crate) const SEALED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;
/// The random nonce that starts the payload.
pub(crate) const NONCE_SIZE: usize = 16;

/// The chunk cipher and where it is in the stream.
pub(crate) struct Stream {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Stream {
    pub fn new(file_key: &FileKey, nonce: &[u8; NONCE_SIZE]) -> Self {
        Self {
            cipher: cipher(&hkdf(nonce, file_key, b"payload")),
            counter: 0,
        }
    }

    /// Whether no chunk has been sealed or opened yet.
    pub fn at_start(&self) -> bool {
        self.counter == 0
    }

    /// Encrypts the plaintext in `chunk` in place and appends its tag.
    pub fn seal(&mut self, chunk: &mut Vec<u8>, last: bool) -> io::Result<()> {
        let tag = self
            .cipher
            .encrypt_inout_detached(&self.nonce(last), &[], chunk.as_mut_slice().into())
            .expect("a 64 KiB chunk is far below ChaCha20-Poly1305's length limit");
        chunk.extend_from_slice(&tag);
        self.advance()
    }

    /// Decrypts `sealed` (ciphertext and tag) into `plaintext`, and tells
    /// whether it was the final chunk. On failure `plaintext` is left empty:
    /// unauthenticated plaintext is never kept.
    ///
    /// A short chunk can only be the final one. A full chunk usually isn't,
    /// but may be: it is tried as both, as the reference implementation
    /// does.
    pub fn open(&mut self, sealed: &[u8], plaintext: &mut Vec<u8>) -> io::Result<bool> {
        plaintext.clear();
        let Some(length) = sealed.len().checked_sub(TAG_SIZE) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "age payload is truncated: it ends inside a chunk",
            ));
        };
        if length == 0 && !self.at_start() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "age payload's final chunk is empty",
            ));
        }
        let (ciphertext, tag) = sealed.split_at(length);
        let tag = Tag::try_from(tag).expect("the tag is TAG_SIZE bytes");
        plaintext.resize(length, 0);
        let full = sealed.len() == SEALED_CHUNK_SIZE;
        let candidates: &[bool] = if full { &[false, true] } else { &[true] };
        for &last in candidates {
            let buffer = InOutBuf::new(ciphertext, plaintext).expect("same lengths");
            if self
                .cipher
                .decrypt_inout_detached(&self.nonce(last), &[], buffer, &tag)
                .is_ok()
            {
                self.advance()?;
                return Ok(last);
            }
        }
        plaintext.clear();
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "age payload chunk {} failed authentication: the file is damaged, \
                 truncated or was tampered with",
                self.counter
            ),
        ))
    }

    fn nonce(&self, last: bool) -> Nonce {
        let mut nonce = Nonce::default();
        nonce[3..11].copy_from_slice(&self.counter.to_be_bytes());
        nonce[11] = u8::from(last);
        nonce
    }

    fn advance(&mut self) -> io::Result<()> {
        self.counter = self.counter.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "age payload has too many chunks",
            )
        })?;
        Ok(())
    }
}
