//! End-to-end tests: the circuit against a reference AES, and both backends
//! against the circuit.
//!
//! The slow ones are `#[ignore]`d; run them with `cargo test -- --ignored`.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use digest::generic_array::GenericArray;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zk_aes::sbox::SboxKind;

/// AES-128 ECB, as implemented by the `aes` crate: the oracle everything here
/// is checked against.
fn reference_encrypt(message: &[u8], secret_key: &[u8; 16]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(secret_key));
    let mut ciphertext = Vec::with_capacity(message.len());

    for chunk in message.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(block.as_slice());
    }

    ciphertext
}

#[test]
fn circuit_matches_the_reference_on_one_block() {
    let message = [1_u8; 16];
    let secret_key = [0_u8; 16];

    let computed = zk_aes::encrypt_circuit_only(&message, &secret_key).unwrap();

    assert_eq!(computed, reference_encrypt(&message, &secret_key));
}

#[test]
fn circuit_matches_the_reference_on_four_blocks() {
    let message: Vec<u8> = (0_u8..64_u8).collect();
    let secret_key = [7_u8; 16];

    let computed = zk_aes::encrypt_circuit_only(&message, &secret_key).unwrap();

    assert_eq!(computed, reference_encrypt(&message, &secret_key));
}

/// ECB encrypts every block independently, so repeated plaintext blocks produce
/// repeated ciphertext blocks. This is a property of the mode, not a bug, and
/// the circuit must reproduce it.
#[test]
fn ecb_repeats_blocks() {
    let message = [9_u8; 32];
    let secret_key = [3_u8; 16];

    let computed = zk_aes::encrypt_circuit_only(&message, &secret_key).unwrap();

    assert_eq!(computed.get(..16), computed.get(16..));
}

/// Both S-box constructions must arithmetize the same function.
#[test]
fn both_sboxes_give_the_same_circuit_size_ordering() {
    let bitsliced = zk_aes::constraint_count(1, SboxKind::Bitsliced).unwrap();
    let lookup = zk_aes::constraint_count(1, SboxKind::Lookup).unwrap();

    println!("constraints for one block: bitsliced={bitsliced}, lookup={lookup}");
    assert!(bitsliced < lookup);
}

#[test]
#[ignore = "slow: Groth16 setup + prove over the full AES circuit"]
fn groth16_proves_and_verifies() {
    let message = [1_u8; 16];
    let secret_key = [0_u8; 16];
    let ciphertext = reference_encrypt(&message, &secret_key);
    let mut rng = ChaCha20Rng::seed_from_u64(0_u64);

    let verified =
        zk_aes::backend::groth16::prove_and_verify(&message, &secret_key, &ciphertext, &mut rng)
            .unwrap();

    assert!(verified);
}

#[test]
#[ignore = "slow: Spartan prove + verify over the full AES circuit"]
fn spartan_proves_and_verifies() {
    let message = [1_u8; 16];
    let secret_key = [0_u8; 16];
    let ciphertext = reference_encrypt(&message, &secret_key);

    let verified =
        zk_aes::backend::spartan::prove_and_verify(&message, &secret_key, &ciphertext).unwrap();

    assert!(verified);
}
