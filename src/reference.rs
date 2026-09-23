//! AES-128 ECB outside the circuit, via the `aes` crate.
//!
//! This is the specification: the circuit is correct exactly when it agrees
//! with this function.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

/// Encrypts `message` under `secret_key` in ECB mode.
///
/// # Panics
///
/// If `message` is not a whole number of 16-byte blocks. Padding is a concern
/// of the mode's users, not of the proof, so it is not modelled here.
pub fn encrypt(message: &[u8], secret_key: &[u8; 16]) -> Vec<u8> {
    let (blocks, rest) = message.as_chunks::<16>();
    assert!(
        rest.is_empty(),
        "message must be a whole number of 16-byte blocks"
    );
    let cipher = Aes128::new(GenericArray::from_slice(secret_key));

    blocks
        .iter()
        .flat_map(|block| {
            let mut block = GenericArray::clone_from_slice(block);
            cipher.encrypt_block(&mut block);
            block.to_vec()
        })
        .collect()
}
