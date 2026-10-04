//! Decryption with seeking, for files read out of order (an encrypted zip,
//! whose directory is at its end): chunks are sealed independently, so any
//! one can be opened alone. The file's length says how many chunks there
//! are and which is final, so no plaintext ever needs writing out.

use std::fmt;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

use crate::crypto::TAG_SIZE;
use crate::header::Header;
use crate::stream::{Stream, CHUNK_SIZE, NONCE_SIZE, SEALED_CHUNK_SIZE};
use crate::{x25519, Error, Identity};

/// Opens the age file in `input` with one of `identities`, for reading its
/// plaintext in any order. `input` is buffered here.
///
/// # Errors
///
/// As [`crate::decrypt`], and [`Error::MalformedHeader`] when the payload's
/// length can't be a sequence of chunks (cut inside the last one, or ending
/// with an empty chunk after others).
pub fn decrypt_seekable<R: Read + Seek>(
    input: R,
    identities: &[Identity],
) -> Result<SeekableDecryptor<R>, Error> {
    let mut reader = BufReader::new(input);
    let header = Header::read(&mut reader)?;
    let file_key = x25519::unwrap(&header.stanzas, identities)?.ok_or(Error::NoMatchingIdentity)?;
    header.verify(&file_key)?;
    let mut nonce = [0; NONCE_SIZE];
    reader
        .read_exact(&mut nonce)
        .map_err(|_| Error::MalformedHeader("payload nonce is truncated"))?;
    let start = reader.stream_position()?;
    let payload = reader.seek(SeekFrom::End(0))?.saturating_sub(start);
    let chunks = payload.div_ceil(SEALED_CHUNK_SIZE as u64).max(1);
    let last_sealed = payload - (chunks - 1) * SEALED_CHUNK_SIZE as u64;
    if last_sealed < TAG_SIZE as u64 || (chunks > 1 && last_sealed == TAG_SIZE as u64) {
        return Err(Error::MalformedHeader(
            "payload length is not a sequence of chunks",
        ));
    }
    Ok(SeekableDecryptor {
        reader,
        stream: Stream::new(&file_key, &nonce),
        start,
        chunks,
        length: payload - chunks * TAG_SIZE as u64,
        position: 0,
        chunk: None,
        sealed: Vec::with_capacity(SEALED_CHUNK_SIZE),
        plaintext: Vec::with_capacity(CHUNK_SIZE),
    })
}

/// The plaintext of an age file, read in any order. A chunk is released
/// only once its tag checks; one that fails gives
/// [`io::ErrorKind::InvalidData`] for that read.
pub struct SeekableDecryptor<R> {
    reader: BufReader<R>,
    stream: Stream,
    /// Where the first chunk starts in the file.
    start: u64,
    chunks: u64,
    /// The plaintext's length.
    length: u64,
    /// The next plaintext byte to read.
    position: u64,
    /// The chunk held in `plaintext`.
    chunk: Option<u64>,
    sealed: Vec<u8>,
    plaintext: Vec<u8>,
}

impl<R: Read + Seek> SeekableDecryptor<R> {
    /// The plaintext's length.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Whether the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Make `plaintext` hold chunk `index`.
    fn load(&mut self, index: u64) -> io::Result<()> {
        if self.chunk == Some(index) {
            return Ok(());
        }
        self.chunk = None;
        let offset = self.start + index * SEALED_CHUNK_SIZE as u64;
        self.reader.seek(SeekFrom::Start(offset))?;
        self.sealed.clear();
        (&mut self.reader)
            .take(SEALED_CHUNK_SIZE as u64)
            .read_to_end(&mut self.sealed)?;
        let last = index + 1 == self.chunks;
        self.stream
            .open_chunk(index, last, &self.sealed, &mut self.plaintext)?;
        self.chunk = Some(index);
        Ok(())
    }
}

impl<R: Read + Seek> Read for SeekableDecryptor<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.length || out.is_empty() {
            return Ok(0);
        }
        let index = self.position / CHUNK_SIZE as u64;
        self.load(index)?;
        let within = (self.position % CHUNK_SIZE as u64) as usize;
        let available = &self.plaintext[within..];
        let count = available.len().min(out.len());
        out[..count].copy_from_slice(&available[..count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: Read + Seek> Seek for SeekableDecryptor<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::Current(by) => self.position.checked_add_signed(by),
            SeekFrom::End(by) => self.length.checked_add_signed(by),
        };
        self.position = target
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.position)
    }
}

impl<R> fmt::Debug for SeekableDecryptor<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeekableDecryptor")
            .field("length", &self.length)
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}
