//! The textual header: a version line, recipient stanzas, and a MAC.
//!
//! ```text
//! age-encryption.org/v1
//! -> X25519 XEl0dJ6y3C7KZkgmgWUicg63EyXJiwBJW8PdYJ/cYBE
//! qRS0AMjdjPvZ/WT08U2KL4G+PIooA3hy38SvLpvaC1E
//! --- HK2NmOBN9Dpq0Gw6xMCuhFcQlQLvZ/wQUi/2scLG75s
//! ```
//!
//! Reading is strict, as the specification's grammar: LF line ends,
//! arguments of visible ASCII, bodies wrapped at exactly 64 columns and
//! ended by a shorter line, canonical base64 everywhere.

use std::io::{BufRead, Read};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::crypto::{hkdf, FileKey};
use crate::{base64, Error};

const VERSION_LINE: &[u8] = b"age-encryption.org/v1";
const VERSION_PREFIX: &[u8] = b"age-encryption.org/";
const STANZA_PREFIX: &[u8] = b"-> ";
const MAC_PREFIX: &[u8] = b"---";
const COLUMNS: usize = 64;
const MAC_SIZE: usize = 32;
/// The passphrase stanza, which must be alone in a header.
const SCRYPT: &str = "scrypt";
/// Far more than any real header (an X25519 stanza is about 110 bytes):
/// a hostile one can't make the reader buffer without end.
const MAX_SIZE: u64 = 1 << 20;

/// One recipient stanza: `-> kind args…` and a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stanza {
    /// The first argument, which says how to read the rest.
    pub kind: String,
    /// The arguments after the first.
    pub args: Vec<String>,
    /// The decoded body.
    pub body: Vec<u8>,
}

impl Stanza {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(STANZA_PREFIX);
        out.extend_from_slice(self.kind.as_bytes());
        for arg in &self.args {
            out.push(b' ');
            out.extend_from_slice(arg.as_bytes());
        }
        out.push(b'\n');
        let body = base64::encode(&self.body);
        for line in body.as_bytes().chunks(COLUMNS) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        // The body ends with a line shorter than 64 columns, even an empty one.
        if body.len() % COLUMNS == 0 {
            out.push(b'\n');
        }
    }
}

/// A parsed header, its MAC not yet checked (that needs the file key).
#[derive(Debug)]
pub(crate) struct Header {
    pub stanzas: Vec<Stanza>,
    /// The bytes the MAC covers: everything up to and including `---`.
    signed: Vec<u8>,
    mac: [u8; MAC_SIZE],
}

impl Header {
    /// Reads the header, leaving `reader` at the first payload byte.
    pub fn read(reader: &mut impl BufRead) -> Result<Self, Error> {
        let mut lines = Lines {
            reader,
            raw: Vec::new(),
        };
        let version = lines.next()?;
        if version != VERSION_LINE {
            return Err(Error::MalformedHeader(
                if version.starts_with(VERSION_PREFIX) {
                    "unsupported age version"
                } else {
                    "not an age file"
                },
            ));
        }
        let mut stanzas = Vec::new();
        loop {
            let start = lines.raw.len();
            let line = lines.next()?;
            if let Some(args) = line.strip_prefix(STANZA_PREFIX) {
                stanzas.push(read_stanza(args, &mut lines)?);
            } else if let Some(mac) = line.strip_prefix(MAC_PREFIX) {
                if stanzas.is_empty() {
                    return Err(Error::MalformedHeader("header has no recipient stanza"));
                }
                if stanzas.len() > 1 && stanzas.iter().any(|stanza| stanza.kind == SCRYPT) {
                    return Err(Error::MalformedHeader(
                        "a passphrase (scrypt) stanza must be alone in the header",
                    ));
                }
                let mac = parse_mac(mac)?;
                let mut signed = lines.raw;
                signed.truncate(start + MAC_PREFIX.len());
                return Ok(Self {
                    stanzas,
                    signed,
                    mac,
                });
            } else {
                return Err(Error::MalformedHeader(
                    "header line is neither a stanza nor the MAC",
                ));
            }
        }
    }

    /// Checks the MAC with the file key the stanzas gave.
    pub fn verify(&self, file_key: &FileKey) -> Result<(), Error> {
        mac(file_key, &self.signed)
            .verify_slice(&self.mac)
            .map_err(|_| Error::HeaderMac)
    }
}

/// The whole header for `stanzas`, MAC line included.
pub(crate) fn write(stanzas: &[Stanza], file_key: &FileKey) -> Vec<u8> {
    let mut header = VERSION_LINE.to_vec();
    header.push(b'\n');
    for stanza in stanzas {
        stanza.write(&mut header);
    }
    header.extend_from_slice(MAC_PREFIX);
    let mac = mac(file_key, &header).finalize().into_bytes();
    header.push(b' ');
    header.extend_from_slice(base64::encode(&mac).as_bytes());
    header.push(b'\n');
    header
}

fn mac(file_key: &FileKey, signed: &[u8]) -> Hmac<Sha256> {
    let key = hkdf(&[], file_key, b"header");
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("HMAC takes keys of any length");
    mac.update(signed);
    mac
}

/// After `-> `: the arguments, then the body lines.
fn read_stanza<R: BufRead>(args: &[u8], lines: &mut Lines<'_, R>) -> Result<Stanza, Error> {
    let mut args = args
        .split(|&c| c == b' ')
        .map(|arg| {
            if arg.is_empty() || !arg.iter().all(u8::is_ascii_graphic) {
                return Err(Error::MalformedHeader("malformed stanza argument"));
            }
            Ok(arg.iter().map(|&c| char::from(c)).collect::<String>())
        })
        .collect::<Result<Vec<String>, Error>>()?;
    // Splitting gives at least one piece, so there is a first argument.
    let kind = args.remove(0);

    let mut text = Vec::new();
    loop {
        let line = lines.next()?;
        if line.len() > COLUMNS || !line.iter().all(|&c| base64::is_alphabet(c)) {
            return Err(Error::MalformedHeader("malformed stanza body line"));
        }
        text.extend_from_slice(&line);
        if line.len() < COLUMNS {
            break;
        }
    }
    let body = base64::decode(&text).ok_or(Error::MalformedHeader(
        "stanza body is not canonical base64",
    ))?;
    Ok(Stanza { kind, args, body })
}

/// After `---`: a space and the MAC in canonical base64.
fn parse_mac(text: &[u8]) -> Result<[u8; MAC_SIZE], Error> {
    text.strip_prefix(b" ")
        .and_then(base64::decode)
        .and_then(|mac| mac.try_into().ok())
        .ok_or(Error::MalformedHeader("malformed header MAC line"))
}

/// The header's lines, each kept in `raw` for the MAC.
struct Lines<'a, R> {
    reader: &'a mut R,
    raw: Vec<u8>,
}

impl<R: BufRead> Lines<'_, R> {
    /// The next line, without its line feed.
    fn next(&mut self) -> Result<Vec<u8>, Error> {
        let start = self.raw.len();
        let budget = MAX_SIZE - start as u64;
        (&mut *self.reader)
            .take(budget)
            .read_until(b'\n', &mut self.raw)?;
        match self.raw[start..].split_last() {
            Some((b'\n', line)) => Ok(line.to_vec()),
            _ if self.raw.len() as u64 >= MAX_SIZE => {
                Err(Error::MalformedHeader("header is longer than 1 MiB"))
            }
            _ => Err(Error::MalformedHeader("header ends early")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(body: usize) -> Stanza {
        Stanza {
            kind: "example.com/test".to_owned(),
            args: vec!["a".to_owned(), "b".to_owned()],
            body: (0..body).map(|i| i as u8).collect(),
        }
    }

    #[test]
    fn written_headers_read_back() {
        let file_key = [7; 16];
        // 0, 1, exactly one full line (48 bytes) and a bit more.
        let stanzas: Vec<Stanza> = [0, 1, 48, 49, 200].into_iter().map(stanza).collect();
        let mut bytes = write(&stanzas, &file_key);
        bytes.extend_from_slice(b"payload");
        let mut reader = bytes.as_slice();
        let header = Header::read(&mut reader).unwrap();
        assert_eq!(header.stanzas, stanzas);
        header.verify(&file_key).unwrap();
        assert!(matches!(header.verify(&[8; 16]), Err(Error::HeaderMac)));
        assert_eq!(reader, b"payload");
    }

    #[test]
    fn full_body_lines_need_a_short_line_after() {
        let header = write(&[stanza(48)], &[0; 16]);
        let text = String::from_utf8(header).unwrap();
        let body_line = text.lines().nth(2).unwrap();
        assert_eq!(body_line.len(), 64);
        assert_eq!(text.lines().nth(3), Some(""));
    }

    #[test]
    fn a_hostile_header_is_bounded() {
        let mut bytes = b"age-encryption.org/v1\n-> ".to_vec();
        bytes.resize(2 << 20, b'a');
        let error = Header::read(&mut bytes.as_slice()).unwrap_err();
        assert!(matches!(
            error,
            Error::MalformedHeader("header is longer than 1 MiB")
        ));
    }
}
