//! A minimal `age` command, from standard input to standard output, for
//! checking this crate against the reference tools (`scripts/interop.sh`).
//!
//! ```text
//! age -r age1… [-r age1…]   encrypt
//! age -d -i identities.txt  decrypt
//! ```

use std::io::{self, BufWriter, Write};
use std::process::ExitCode;
use std::{env, fs};

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("age: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = BufWriter::new(io::stdout().lock());
    match args {
        [flag, option, path] if flag == "-d" && option == "-i" => {
            let identities = age::parse_identities(&fs::read_to_string(path)?)?;
            let mut plaintext = age::decrypt(io::stdin().lock(), &identities)?;
            copy(&mut plaintext, stdout)?;
        }
        _ => {
            let recipients = args
                .chunks(2)
                .map(|pair| match pair {
                    [flag, recipient] if flag == "-r" => Ok(recipient.parse()?),
                    _ => Err("usage: age -r age1… [-r age1…] | age -d -i identities.txt".into()),
                })
                .collect::<Result<Vec<age::Recipient>, Box<dyn std::error::Error>>>()?;
            let mut encryptor = age::Encryptor::new(stdout, &recipients)?;
            io::copy(&mut io::stdin().lock(), &mut encryptor)?;
            encryptor.finish()?;
        }
    }
    Ok(())
}

fn copy(reader: &mut impl io::Read, mut out: impl Write) -> io::Result<()> {
    io::copy(reader, &mut out)?;
    out.flush()
}
