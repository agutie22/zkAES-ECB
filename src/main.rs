use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use anyhow::Result;
use digest::generic_array::GenericArray;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

fn main() -> Result<()> {
    let message = [1_u8; 16];
    let secret_key = [0_u8; 16];
    let primitive_secret_key = Aes128::new(GenericArray::from_slice(&secret_key));

    // The ciphertext the verifier will be given, computed with a standard AES.
    let ciphertext = primitive_encrypt(&message, &primitive_secret_key);

    // The circuit computes the same thing.
    let circuit_ciphertext = zk_aes::encrypt_circuit_only(&message, &secret_key)?;
    assert_eq!(ciphertext, circuit_ciphertext);
    println!("circuit output matches the `aes` crate");

    // Groth16: setup once per circuit shape, then prove, then verify.
    // A seeded RNG keeps this demo reproducible; a real setup needs a ceremony.
    let mut rng = ChaCha20Rng::seed_from_u64(0_u64);

    let start = Instant::now();
    let (proving_key, verifying_key) = zk_aes::backend::groth16::setup(1_usize, &mut rng)?;
    println!("groth16 setup:  {:?}", start.elapsed());

    let start = Instant::now();
    let proof = zk_aes::backend::groth16::prove(&proving_key, &message, &secret_key, &ciphertext, &mut rng)?;
    println!("groth16 prove:  {:?}", start.elapsed());

    // The verifier only ever sees these three things.
    let start = Instant::now();
    let verified = zk_aes::backend::groth16::verify(&verifying_key, &ciphertext, &proof)?;
    println!("groth16 verify: {:?} -> {verified}", start.elapsed());
    assert!(verified);

    // The same proof must not verify against a different ciphertext.
    let mut tampered = ciphertext.clone();
    if let Some(byte) = tampered.get_mut(0) {
        *byte ^= 1_u8;
    }
    assert!(!zk_aes::backend::groth16::verify(&verifying_key, &tampered, &proof)?);
    println!("proof correctly rejected for a tampered ciphertext");

    Ok(())
}

fn primitive_encrypt(message: &[u8; 16], primitive_secret_key: &Aes128) -> Vec<u8> {
    let mut encrypted_message = Vec::new();
    let mut block = GenericArray::clone_from_slice(message);
    primitive_secret_key.encrypt_block(&mut block);
    encrypted_message.extend_from_slice(block.as_slice());
    encrypted_message
}
