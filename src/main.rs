//! Proves one AES-128 block with each backend, and times every step.

use anyhow::{ensure, Result};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::time::Instant;
use zk_aes::backend::{groth16::Groth16, spartan::Spartan, Backend};
use zk_aes::circuit::AesEcbCircuit;
use zk_aes::sbox::SboxKind;

fn main() -> Result<()> {
    let message = [1_u8; 16];
    let secret_key = [0_u8; 16];
    let ciphertext = zk_aes::reference::encrypt(&message, &secret_key);

    ensure!(zk_aes::encrypt_circuit_only(&message, &secret_key)? == ciphertext);
    println!(
        "circuit matches the reference AES ({} constraints)",
        zk_aes::constraint_count(1, SboxKind::default())?
    );

    run::<Groth16>("groth16", &message, &secret_key, &ciphertext)?;
    run::<Spartan>("spartan", &message, &secret_key, &ciphertext)?;
    Ok(())
}

/// Setup, prove, verify, then check that a tampered ciphertext is rejected.
fn run<B: Backend>(
    name: &str,
    message: &[u8],
    secret_key: &[u8; 16],
    ciphertext: &[u8],
) -> Result<()> {
    // A seeded RNG keeps the demo reproducible. A real setup needs real entropy.
    let mut rng = ChaCha20Rng::seed_from_u64(0);

    let start = Instant::now();
    let (proving_key, verifying_key) = B::setup(AesEcbCircuit::setup(1), &mut rng)?;
    let setup = start.elapsed();

    let start = Instant::now();
    let circuit = AesEcbCircuit::prover(message, secret_key, ciphertext)?;
    let proof = B::prove(&proving_key, circuit, &mut rng)?;
    let prove = start.elapsed();

    let start = Instant::now();
    let public_inputs = AesEcbCircuit::public_inputs(ciphertext);
    let verified = B::verify(&verifying_key, &public_inputs, &proof)?;
    let verify = start.elapsed();

    let mut tampered = ciphertext.to_vec();
    tampered[0] ^= 1;
    let rejected = !B::verify(
        &verifying_key,
        &AesEcbCircuit::public_inputs(&tampered),
        &proof,
    )?;

    println!(
        "{name:8} setup {setup:>10.2?}   prove {prove:>10.2?}   verify {verify:>10.2?}   \
         verified={verified} tampered-rejected={rejected}"
    );
    ensure!(verified && rejected, "{name} failed");
    Ok(())
}
