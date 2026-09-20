//! Groth16: a pairing-based SNARK with a circuit-specific trusted setup.
//!
//! Groth16 is the maintained, in-tree Arkworks proving system: `ark-groth16`
//! tracks the same release line as the rest of the ecosystem, so nothing here
//! pins an old version of `ark-ff` the way `ark-marlin` does.
//!
//! The trade-off is the setup: the proving and verifying keys are only valid for
//! one circuit shape (here, a fixed number of blocks and a fixed S-box), and
//! whoever runs [`setup`] learns toxic waste. What you get for it is a constant
//! size proof — three group elements — and millisecond verification.
//!
//! For a transparent alternative over the very same circuit, see
//! [`crate::backend::spartan`].

use crate::circuit::AesEcbCircuit;
use crate::Fr;
use anyhow::{anyhow, Result};
use ark_bls12_377::Bls12_377;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

/// The pairing-friendly curve the proofs live on.
pub type Curve = Bls12_377;

/// Runs the circuit-specific trusted setup for a `num_blocks`-block message.
///
/// The keys are bound to that shape: proving a two-block message needs keys
/// generated with `num_blocks == 2`.
pub fn setup<R: RngCore + CryptoRng>(
    num_blocks: usize,
    rng: &mut R,
) -> Result<(ProvingKey<Curve>, VerifyingKey<Curve>)> {
    Groth16::<Curve>::circuit_specific_setup(AesEcbCircuit::<Fr>::setup(num_blocks), rng)
        .map_err(|e| anyhow!("Groth16 setup failed: {e}"))
}

/// Proves that `ciphertext` is the AES-128 ECB encryption of `message` under
/// `secret_key`, revealing only `ciphertext`.
pub fn prove<R: RngCore + CryptoRng>(
    proving_key: &ProvingKey<Curve>,
    message: &[u8],
    secret_key: &[u8; 16],
    ciphertext: &[u8],
    rng: &mut R,
) -> Result<Proof<Curve>> {
    let circuit = AesEcbCircuit::<Fr>::prover(message, secret_key, ciphertext)?;
    Groth16::<Curve>::prove(proving_key, circuit, rng)
        .map_err(|e| anyhow!("Groth16 proving failed: {e}"))
}

/// Checks a proof against a ciphertext.
///
/// This is the whole verifier: a verifying key, the public ciphertext and the
/// proof. It never sees the message, the key, or the circuit.
pub fn verify(
    verifying_key: &VerifyingKey<Curve>,
    ciphertext: &[u8],
    proof: &Proof<Curve>,
) -> Result<bool> {
    let public_inputs = AesEcbCircuit::<Fr>::public_inputs(ciphertext);
    Groth16::<Curve>::verify(verifying_key, &public_inputs, proof)
        .map_err(|e| anyhow!("Groth16 verification failed: {e}"))
}

/// Same as [`verify`], for a verifying key that was prepared once and reused.
pub fn verify_with_prepared_key(
    prepared_verifying_key: &PreparedVerifyingKey<Curve>,
    ciphertext: &[u8],
    proof: &Proof<Curve>,
) -> Result<bool> {
    let public_inputs = AesEcbCircuit::<Fr>::public_inputs(ciphertext);
    Groth16::<Curve>::verify_with_processed_vk(prepared_verifying_key, &public_inputs, proof)
        .map_err(|e| anyhow!("Groth16 verification failed: {e}"))
}

/// Setup, prove and verify in one call. Convenient for tests and demos; a real
/// deployment runs [`setup`] once, offline, under a ceremony, and ships only the
/// keys. The `rng` must be cryptographically secure: setup randomness that leaks
/// is enough to forge proofs.
pub fn prove_and_verify<R: RngCore + CryptoRng>(
    message: &[u8],
    secret_key: &[u8; 16],
    ciphertext: &[u8],
    rng: &mut R,
) -> Result<bool> {
    let num_blocks = AesEcbCircuit::<Fr>::prover(message, secret_key, ciphertext)?.num_blocks;

    let (proving_key, verifying_key) = setup(num_blocks, rng)?;
    let proof = prove(&proving_key, message, secret_key, ciphertext, rng)?;
    verify(&verifying_key, ciphertext, &proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;
    use digest::generic_array::GenericArray;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn reference_encrypt(message: &[u8; 16], secret_key: &[u8; 16]) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(secret_key));
        let mut block = GenericArray::clone_from_slice(message);
        cipher.encrypt_block(&mut block);
        block.to_vec()
    }

    #[test]
    #[ignore = "slow: Groth16 setup + prove over the full AES circuit"]
    fn proves_and_verifies_a_single_block() {
        let message = [1_u8; 16];
        let secret_key = [0_u8; 16];
        let ciphertext = reference_encrypt(&message, &secret_key);

        let mut rng = ChaCha20Rng::seed_from_u64(0_u64);
        assert!(prove_and_verify(&message, &secret_key, &ciphertext, &mut rng).unwrap());
    }

    /// A proof must not verify against a ciphertext other than the one proved.
    #[test]
    #[ignore = "slow: Groth16 setup + prove over the full AES circuit"]
    fn rejects_a_different_ciphertext() {
        let message = [1_u8; 16];
        let secret_key = [0_u8; 16];
        let ciphertext = reference_encrypt(&message, &secret_key);

        let mut rng = ChaCha20Rng::seed_from_u64(0_u64);
        let (proving_key, verifying_key) = setup(1_usize, &mut rng).unwrap();
        let proof = prove(&proving_key, &message, &secret_key, &ciphertext, &mut rng).unwrap();

        let mut tampered = ciphertext.clone();
        *tampered.get_mut(0).unwrap() ^= 1_u8;

        assert!(verify(&verifying_key, &ciphertext, &proof).unwrap());
        assert!(!verify(&verifying_key, &tampered, &proof).unwrap());
    }
}
