use crate::aes_helper::{decrypt_block, encrypt_block, Block128};
use crate::error::{Error, FtsResult};
use crate::symmetric_key::SymmetricKey;
use secrecy::Secret;

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
/// A 128-bit document id
pub struct DocId(Block128);

impl DocId {
    pub fn new<T: Into<Block128>>(id: T) -> Self {
        DocId(id.into())
    }

    /// Encrypt a token using AES-128-ECB with a 128bit key
    pub fn encrypt(self, key: &Secret<SymmetricKey>) -> EncryptedDocId {
        let encrypted = encrypt_block(self.0, key);
        EncryptedDocId(encrypted)
    }
}

#[cfg(feature = "uuids")]
impl TryFrom<DocId> for uuid::Uuid {
    type Error = uuid::Error;

    fn try_from(value: DocId) -> Result<Self, Self::Error> {
        uuid::Uuid::from_slice(value.0.as_slice())
    }
}

#[cfg(feature = "uuids")]
impl From<uuid::Uuid> for DocId {
    fn from(x: uuid::Uuid) -> Self {
        DocId::new(x.as_u128().to_be_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EncryptedDocId(Block128);

impl EncryptedDocId {
    pub fn decrypt(self, key: &Secret<SymmetricKey>) -> DocId {
        let decrypted = decrypt_block(self.0, key);
        DocId(decrypted)
    }
}

pub(crate) fn ivec_to_block_128(ivec: sled::IVec) -> FtsResult<Block128> {
    if ivec.len() != 16 {
        return Err(Error::Decode);
    }

    let mut bytes = [0u8; 16];

    for i in 0..16 {
        bytes[i] = ivec[i];
    }
    Ok(Block128::from(bytes))
}

impl From<EncryptedDocId> for sled::IVec {
    fn from(id: EncryptedDocId) -> Self {
        sled::IVec::from(id.0.to_vec())
    }
}

impl TryFrom<sled::IVec> for EncryptedDocId {
    type Error = Error;

    fn try_from(ivec: sled::IVec) -> Result<Self, Self::Error> {
        let inner = ivec_to_block_128(ivec)?;
        Ok(EncryptedDocId(inner))
    }
}

impl AsRef<[u8]> for EncryptedDocId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hashed_and_encrypted() {
        let key = [
            0x75, 0x09, 0x5a, 0x2b, 0xa1, 0x1f, 0xf0, 0xbe, 0x45, 0x52, 0x11, 0xf7, 0xaa, 0x7b,
            0x80, 0xff,
        ];
        let key = Secret::from(SymmetricKey::from(key));

        let id = [
            0x39, 0xaa, 0xa1, 0x41, 0x88, 0xf8, 0xb6, 0x34, 0x12, 0x99, 0x99, 0x78, 0x3b, 0x33,
            0xbb, 0xa1,
        ];
        let id = DocId::new(id);

        let encrypted_id = id.clone().encrypt(&key);
        let decrypted = encrypted_id.decrypt(&key);
        assert_eq!(decrypted, id);
    }
}
