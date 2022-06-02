use crate::symmetric_key::SymmetricKey;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use blake2::digest::consts::U16;
use secrecy::{ExposeSecret, Secret};

/// A 128-bit block of data
pub type Block128 = GenericArray<u8, U16>;

/// Encrypt a 128-bit block using AES-128-ECB with a 128bit key
pub fn encrypt_block(mut block: Block128, key: &Secret<SymmetricKey>) -> Block128 {
    let cipher = aes::Aes128Enc::new(&key.expose_secret().0);
    cipher.encrypt_block(&mut block);
    block
}

/// Decrypt a 128-bit block using AES-128-ECB with a 128bit key
pub fn decrypt_block(mut block: Block128, key: &Secret<SymmetricKey>) -> Block128 {
    let cipher = aes::Aes128Dec::new(&key.expose_secret().0);
    cipher.decrypt_block(&mut block);
    block
}
