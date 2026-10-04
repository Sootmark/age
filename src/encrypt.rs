//! Streaming encryption.

use std::fmt;
use std::io::{self, Write};

use crate::crypto::{random, FileKey};
use crate::stream::{Stream, CHUNK_SIZE, NONCE_SIZE, SEALED_CHUNK_SIZE};
use crate::{header, x25519, Recipient};

/// Encrypts what is written to it into `W`, as an age file for one or more
/// recipients. Memory use is one 64 KiB chunk, whatever the size of the
/// file.
///
/// Call [`finish`](Self::finish) at the end: it writes the final chunk,
/// without which the file can't be decrypted (it reads as truncated).
/// [`flush`](Write::flush) flushes `W` but can't write a partial chunk.
/// After an error the output is unusable, and so is the encryptor: every
/// later call fails.
pub struct Encryptor<W: Write> {
    out: W,
    stream: Stream,
    /// Plaintext waiting to be sealed, at most one chunk. A full chunk is
    /// sealed only once more data comes: until then it might be the last.
    chunk: Vec<u8>,
    failed: bool,
}

impl<W: Write> Encryptor<W> {
    /// Writes the header for `recipients` to `out` and gets ready for the
    /// plaintext.
    ///
    /// # Errors
    ///
    /// If there are no recipients, a recipient is a low-order point (no
    /// real key is), the random source fails, or writing fails.
    ///
    /// # Panics
    ///
    /// If the operating system's random source fails while making an
    /// ephemeral key (after it has worked for the file key).
    pub fn new(mut out: W, recipients: &[Recipient]) -> io::Result<Self> {
        if recipients.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an age file needs at least one recipient",
            ));
        }
        let file_key: FileKey = random()?;
        let stanzas = recipients
            .iter()
            .map(|recipient| x25519::wrap(&file_key, recipient))
            .collect::<io::Result<Vec<_>>>()?;
        let nonce: [u8; NONCE_SIZE] = random()?;
        out.write_all(&header::write(&stanzas, &file_key))?;
        out.write_all(&nonce)?;
        Ok(Self {
            out,
            stream: Stream::new(&file_key, &nonce),
            chunk: Vec::with_capacity(SEALED_CHUNK_SIZE),
            failed: false,
        })
    }

    /// Writes the final chunk and flushes; gives `W` back.
    ///
    /// # Errors
    ///
    /// If writing fails, or an earlier call failed.
    pub fn finish(mut self) -> io::Result<W> {
        self.usable()?;
        self.seal_chunk(true)?;
        self.out.flush()?;
        Ok(self.out)
    }

    fn seal_chunk(&mut self, last: bool) -> io::Result<()> {
        let result = self
            .stream
            .seal(&mut self.chunk, last)
            .and_then(|()| self.out.write_all(&self.chunk));
        self.chunk.clear();
        self.failed = result.is_err();
        result
    }

    fn usable(&self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other(
                "age encryption failed earlier; the output is incomplete",
            ));
        }
        Ok(())
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.usable()?;
        if data.is_empty() {
            return Ok(0);
        }
        if self.chunk.len() == CHUNK_SIZE {
            self.seal_chunk(false)?;
        }
        let taken = data.len().min(CHUNK_SIZE - self.chunk.len());
        self.chunk.extend_from_slice(&data[..taken]);
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.usable()?;
        self.out.flush()
    }
}

impl<W: Write> fmt::Debug for Encryptor<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("buffered", &self.chunk.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
