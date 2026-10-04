//! Reading in any order: the same plaintext as streaming, from any
//! position, for files of every size around the chunk boundaries; and
//! tampering or truncation refused.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use age::{decrypt_seekable, Encryptor, Identity};

const CHUNK: usize = 64 * 1024;

fn sealed(plaintext: &[u8], identity: &Identity) -> Vec<u8> {
    let mut encryptor = Encryptor::new(Vec::new(), &[identity.to_public()]).unwrap();
    encryptor.write_all(plaintext).unwrap();
    encryptor.finish().unwrap()
}

fn plaintext(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 7 % 251) as u8).collect()
}

#[test]
fn every_size_reads_whole_and_from_anywhere() {
    let identity = Identity::generate();
    for length in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 5] {
        let expected = plaintext(length);
        let file = sealed(&expected, &identity);
        let mut reader =
            decrypt_seekable(Cursor::new(file), std::slice::from_ref(&identity)).unwrap();
        assert_eq!(reader.len(), length as u64, "{length}");
        let mut all = Vec::new();
        reader.read_to_end(&mut all).unwrap();
        assert_eq!(all, expected, "{length}");
        for at in [length / 2, length.saturating_sub(3), CHUNK.min(length)] {
            reader.seek(SeekFrom::Start(at as u64)).unwrap();
            let mut rest = Vec::new();
            reader.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, &expected[at..], "{length} from {at}");
        }
    }
}

#[test]
fn the_end_first_as_a_zip_reader_does() {
    let identity = Identity::generate();
    let expected = plaintext(5 * CHUNK + 123);
    let mut reader =
        decrypt_seekable(Cursor::new(sealed(&expected, &identity)), &[identity]).unwrap();
    reader.seek(SeekFrom::End(-22)).unwrap();
    let mut tail = [0; 22];
    reader.read_exact(&mut tail).unwrap();
    assert_eq!(tail, expected[expected.len() - 22..]);
    reader.seek(SeekFrom::Start(10)).unwrap();
    let mut head = [0; 10];
    reader.read_exact(&mut head).unwrap();
    assert_eq!(head, expected[10..20]);
}

#[test]
fn tampering_and_truncation_are_refused() {
    let identity = Identity::generate();
    let file = sealed(&plaintext(3 * CHUNK), &identity);
    // A flipped byte in the second chunk: that chunk fails, the first reads.
    let mut tampered = file.clone();
    let at = tampered.len() - CHUNK - 100;
    tampered[at] ^= 1;
    let mut reader =
        decrypt_seekable(Cursor::new(tampered), std::slice::from_ref(&identity)).unwrap();
    let mut buf = vec![0; 3 * CHUNK];
    assert!(reader.read_exact(&mut buf).is_err());
    // A whole chunk cut off the end: the new last chunk wasn't sealed as
    // final, so it fails.
    let cut = file[..file.len() - (CHUNK + 16)].to_vec();
    let mut reader = decrypt_seekable(Cursor::new(cut), std::slice::from_ref(&identity)).unwrap();
    let mut all = Vec::new();
    assert_eq!(
        reader.read_to_end(&mut all).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    // Cut inside the tag of an empty final chunk: no chunk sequence.
    let header_only = &file[..file.len() - 3 * (CHUNK + 16) + 5];
    assert!(decrypt_seekable(Cursor::new(header_only.to_vec()), &[identity]).is_err());
}
