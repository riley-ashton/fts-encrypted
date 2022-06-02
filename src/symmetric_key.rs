use aes::cipher::generic_array::GenericArray;
use blake2::digest::consts::U16;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 128-bit symmetric key.
/// A wrapper around GenericArray<u8, U16> to avoid misuse.
/// (new-type idiom).
pub struct SymmetricKey(pub GenericArray<u8, U16>);

impl From<[u8; 16]> for SymmetricKey {
    fn from(x: [u8; 16]) -> Self {
        Self(GenericArray::from(x))
    }
}

impl Zeroize for SymmetricKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl ZeroizeOnDrop for SymmetricKey {}

#[cfg(test)]
pub(crate) fn demo_key() -> [u8; 16] {
    [
        164, 245, 207, 202, 140, 235, 51, 94, 109, 187, 16, 207, 61, 45, 245, 50,
    ]
}
