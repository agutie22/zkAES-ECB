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
    assert!(
        message.len() % 16 == 0,
        "message must be a whole number of 16-byte blocks"
    );
    let cipher = Aes128::new(GenericArray::from_slice(secret_key));

    message
        .chunks_exact(16)
        .flat_map(|chunk| {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            block.to_vec()
        })
        .collect()
}
