use crate::doc_id::ivec_to_block_128;
use crate::error::Error;
use crate::tokenizer::Token;
use crate::{
    aes_helper::{encrypt_block, Block128},
    symmetric_key::SymmetricKey,
};
use blake2::{digest::consts::U16, Blake2b, Digest};
use secrecy::Secret;

/// 128-bit cryptographically secure hash algorithm
type Blake2b128 = Blake2b<U16>;

/// Takes a token, hashes it using BLAKE2b-128 and encrypts
/// it using AES-128-ECB, producing a 128bit output.
/// This output is suitable for use as the key prefix in the
/// key-value store.
///
/// Tokens and table names are unique in an inverted index.
/// ECB mode is acceptable here because the data being encrypted
/// is almost certainly never repeated, except in the case of
/// a 128-bit hash collision.
pub(crate) fn encrypt_token(
    token: Token,
    table_name: &str,
    key: &Secret<SymmetricKey>,
) -> EncryptedToken {
    let hashed = HashedToken::new(token, table_name);
    hashed.encrypt(key)
}

#[derive(Debug, Clone, PartialEq)]
/// A token that has been hashed and encrypted to 128-bits.
pub(crate) struct EncryptedToken(Block128);

impl EncryptedToken {
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<EncryptedToken> for sled::IVec {
    fn from(token: EncryptedToken) -> Self {
        sled::IVec::from(token.0.to_vec())
    }
}

impl TryFrom<sled::IVec> for EncryptedToken {
    type Error = Error;

    fn try_from(value: sled::IVec) -> Result<Self, Self::Error> {
        if value.len() == 16 {
            let inner = ivec_to_block_128(value)?;
            Ok(EncryptedToken(inner))
        } else {
            Err(Error::Decode)
        }
    }
}

impl AsRef<[u8]> for EncryptedToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A token after it has been hashed to 128-bits.
/// Includes the token table name in the hash to avoid
/// being equal to the same token in another table.
struct HashedToken(Block128);

impl HashedToken {
    fn new(token: Token, table_name: &str) -> Self {
        let mut hasher = Blake2b128::new();
        hasher.update(token.into_string());
        hasher.update(table_name);
        let array = hasher.finalize();
        HashedToken(array)
    }

    /// Encrypt a token using AES-128-ECB with a 128bit key
    fn encrypt(self, key: &Secret<SymmetricKey>) -> EncryptedToken {
        let encrypted = encrypt_block(self.0, key);
        EncryptedToken(encrypted)
    }
}

#[cfg(test)]
pub(crate) fn demo_token() -> EncryptedToken {
    use crate::symmetric_key::demo_key;
    use crate::tokenizer::tokenize;
    use rust_stemmers::{Algorithm, Stemmer};
    use std::collections::HashSet;

    let stemmer = Stemmer::create(Algorithm::English);
    let to_omit = HashSet::new();
    let mut tokens = tokenize("liberty".to_string(), &stemmer, &to_omit);
    let token = tokens.drain().next().unwrap();
    let key = Secret::new(demo_key().into());
    encrypt_token(token, "test", &key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omit_english::default_english_omit_words;
    use crate::tokenizer::tokenize;
    use rust_stemmers::{Algorithm, Stemmer};

    #[test]
    fn token_hashed_and_encrypted() {
        let key = [
            0x75, 0x09, 0x5a, 0x2b, 0xff, 0x1f, 0xf0, 0xbe, 0x45, 0x52, 0x11, 0xf7, 0xaa, 0x7b,
            0x80, 0xff,
        ];
        let key = Secret::new(key.into());
        let stemmer = Stemmer::create(Algorithm::English);
        let to_omit = default_english_omit_words();

        let tokens = tokenize("tomato".to_string(), &stemmer, &to_omit);
        let mut tokens: Vec<_> = tokens.into_iter().collect();
        let token = tokens.pop().unwrap();

        let table_name = "vegetable";
        let encrypted = encrypt_token(token.clone(), table_name, &key);
        assert_ne!("tomato".as_bytes(), encrypted.0.to_vec());

        let tokens2 = tokenize("asparagus".to_string(), &stemmer, &to_omit);
        let mut tokens2: Vec<_> = tokens2.into_iter().collect();
        let token2 = tokens2.pop().unwrap();

        let encrypted2 = encrypt_token(token2, table_name, &key);
        assert_ne!("asparagus".as_bytes(), encrypted2.0.to_vec());
        assert_ne!(encrypted, encrypted2);

        let table2 = "fruit";
        let encrypted3 = encrypt_token(token, table2, &key);
        assert_ne!(encrypted, encrypted3);
    }
}
