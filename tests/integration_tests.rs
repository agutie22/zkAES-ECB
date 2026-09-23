//! End to end: the circuit against the reference AES, and every backend against
//! the circuit. The slow ones are `#[ignore]`d; run them with
//! `cargo test --release -- --ignored`.

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use zk_aes::backend::{groth16::Groth16, spartan::Spartan, Backend};
use zk_aes::circuit::AesEcbCircuit;
use zk_aes::reference;
use zk_aes::sbox::SboxKind;

#[test]
fn circuit_matches_the_reference_on_one_block() {
    let (message, key) = ([1_u8; 16], [0_u8; 16]);
    let computed = zk_aes::encrypt_circuit_only(&message, &key).unwrap();
    assert_eq!(computed, reference::encrypt(&message, &key));
}

#[test]
fn circuit_matches_the_reference_on_four_blocks() {
    let message: Vec<u8> = (0..64).collect();
    let key = [7_u8; 16];
    let computed = zk_aes::encrypt_circuit_only(&message, &key).unwrap();
    assert_eq!(computed, reference::encrypt(&message, &key));
}

/// ECB encrypts blocks independently, so equal plaintext blocks give equal
/// ciphertext blocks. That is the mode's known weakness, and the circuit must
/// reproduce it faithfully.
#[test]
fn ecb_repeats_blocks() {
    let computed = zk_aes::encrypt_circuit_only(&[9_u8; 32], &[3_u8; 16]).unwrap();
    assert_eq!(computed[..16], computed[16..]);
}

/// Pins the circuit's size. A change here means the arithmetization changed.
#[test]
fn constraint_counts() {
    assert_eq!(
        zk_aes::constraint_count(1, SboxKind::Bitsliced).unwrap(),
        30_728
    );
    assert_eq!(
        zk_aes::constraint_count(1, SboxKind::Lookup).unwrap(),
        184_928
    );
}

/// Any backend must accept the real ciphertext and reject any other.
fn proves_and_verifies<B: Backend>() {
    let (message, key) = ([1_u8; 16], [0_u8; 16]);
    let ciphertext = reference::encrypt(&message, &key);
    let mut rng = ChaCha20Rng::seed_from_u64(0);

    let (pk, vk) = B::setup(AesEcbCircuit::setup(1), &mut rng).unwrap();
    let circuit = AesEcbCircuit::prover(&message, &key, &ciphertext).unwrap();
    let proof = B::prove(&pk, circuit, &mut rng).unwrap();

    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;

    assert!(B::verify(&vk, &AesEcbCircuit::public_inputs(&ciphertext), &proof).unwrap());
    assert!(!B::verify(&vk, &AesEcbCircuit::public_inputs(&tampered), &proof).unwrap());
}

#[test]
#[ignore = "slow: Groth16 over the full circuit"]
fn groth16_proves_and_verifies() {
    proves_and_verifies::<Groth16>();
}

#[test]
#[ignore = "slow: Spartan over the full circuit"]
fn spartan_proves_and_verifies() {
    proves_and_verifies::<Spartan>();
}
