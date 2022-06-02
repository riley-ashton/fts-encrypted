use std::fmt::{Debug, Formatter};

pub type FtsResult<T> = Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    Sled(sled::Error),
    Decode,
    Encode,
}

impl From<sled::Error> for Error {
    fn from(err: sled::Error) -> Self {
        Self::Sled(err)
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sled(err) => {
                f.write_str("fts-encrypted: An error with sled occurred:\n")
                    .unwrap();
                let sled_msg = err.to_string();
                f.write_str(&sled_msg).unwrap();
            }
            Error::Decode => {
                f.write_str("Could not decode an item\n").unwrap();
            }
            Error::Encode => {
                f.write_str("Could not encode an item\n").unwrap();
            }
        }

        Ok(())
    }
}
