//! Streaming decryption.

use std::fmt;
use std::io::{self, BufReader, Read};

use crate::header::Header;
use crate::stream::{Stream, CHUNK_SIZE, NONCE_SIZE, SEALED_CHUNK_SIZE};
use crate::{x25519, Error, Identity};

/// Reads the header of the age file in `input` and opens it with one of
/// `identities`; the plaintext is then read from the [`Decryptor`].
/// `input` is buffered here: no need to wrap it in a `BufReader`.
///
/// # Errors
///
/// - [`Error::MalformedHeader`]: not an age v1 file, or a header that breaks
///   the format's rules (which also covers a payload nonce cut short).
/// - [`Error::NoMatchingIdentity`]: no identity opens any X25519 stanza;
///   stanzas of other kinds (passphrase, post-quantum, plugins) are skipped.
/// - [`Error::HeaderMac`]: the header was altered.
/// - [`Error::Io`]: reading failed.
pub fn decrypt<R: Read>(input: R, identities: &[Identity]) -> Result<Decryptor<R>, Error> {
    let mut reader = BufReader::new(input);
    let header = Header::read(&mut reader)?;
    let file_key = x25519::unwrap(&header.stanzas, identities)?.ok_or(Error::NoMatchingIdentity)?;
    header.verify(&file_key)?;
    let mut nonce = [0; NONCE_SIZE];
    reader.read_exact(&mut nonce).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::MalformedHeader("payload nonce is truncated")
        } else {
            Error::Io(error)
        }
    })?;
    Ok(Decryptor {
        reader,
        stream: Stream::new(&file_key, &nonce),
        sealed: Vec::with_capacity(SEALED_CHUNK_SIZE),
        plaintext: Vec::with_capacity(CHUNK_SIZE),
        position: 0,
        state: State::Reading,
    })
}

/// The plaintext of an age file, one 64 KiB chunk at a time.
///
/// Only authenticated plaintext is returned: a chunk is released once its
/// tag checks. A chunk that fails, or a file cut short, gives an error
/// instead, and so does every later read:
///
/// - [`io::ErrorKind::InvalidData`]: a chunk failed authentication (the file
///   is damaged, tampered with, or cut inside a chunk), the final chunk is
///   empty when it mustn't be, or data follows the final chunk.
/// - [`io::ErrorKind::UnexpectedEof`]: the file ends before its final chunk.
///
/// The plaintext already read is genuine, but until `read` returns `Ok(0)`
/// it may not be all of it. An error from `R` also ends decryption.
pub struct Decryptor<R> {
    reader: BufReader<R>,
    stream: Stream,
    /// The chunk being read: ciphertext and tag.
    sealed: Vec<u8>,
    /// The current chunk's plaintext, from `position` not yet returned.
    plaintext: Vec<u8>,
    position: usize,
    state: State,
}

enum State {
    /// More chunks to come.
    Reading,
    /// The final chunk is open; the input must end with it.
    FinalChunk,
    /// The input ended after the final chunk: all plaintext is out.
    Finished,
    /// Decryption failed; every read says so again.
    Failed(io::ErrorKind, String),
}

impl<R: Read> Decryptor<R> {
    /// Moves to the next state once the current chunk's plaintext is out.
    fn step(&mut self) -> io::Result<()> {
        match &self.state {
            State::Reading => self.next_chunk(),
            State::FinalChunk => self.check_end(),
            State::Finished => Ok(()),
            State::Failed(kind, message) => Err(io::Error::new(*kind, message.clone())),
        }
    }

    fn next_chunk(&mut self) -> io::Result<()> {
        self.sealed.clear();
        self.position = 0;
        (&mut self.reader)
            .take(SEALED_CHUNK_SIZE as u64)
            .read_to_end(&mut self.sealed)?;
        if self.sealed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "age payload is truncated: it ends before the final chunk",
            ));
        }
        if self.stream.open(&self.sealed, &mut self.plaintext)? {
            self.state = State::FinalChunk;
        }
        Ok(())
    }

    fn check_end(&mut self) -> io::Result<()> {
        let mut extra = Vec::new();
        (&mut self.reader).take(1).read_to_end(&mut extra)?;
        if !extra.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "age payload has data after its final chunk",
            ));
        }
        self.state = State::Finished;
        Ok(())
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.position == self.plaintext.len() {
            if matches!(self.state, State::Finished) {
                return Ok(0);
            }
            if let Err(error) = self.step() {
                self.plaintext.clear();
                self.position = 0;
                if !matches!(self.state, State::Failed(..)) {
                    self.state = State::Failed(error.kind(), error.to_string());
                }
                return Err(error);
            }
        }
        let available = &self.plaintext[self.position..];
        let count = available.len().min(out.len());
        out[..count].copy_from_slice(&available[..count]);
        self.position += count;
        Ok(count)
    }
}

impl<R> fmt::Debug for Decryptor<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            State::Reading => "reading",
            State::FinalChunk => "final chunk",
            State::Finished => "finished",
            State::Failed(..) => "failed",
        };
        f.debug_struct("Decryptor")
            .field("state", &state)
            .finish_non_exhaustive()
    }
}
