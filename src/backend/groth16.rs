//! Groth16: a pairing-based SNARK with a circuit-specific trusted setup.
//!
//! What you get: a constant-size proof — three group elements — and
//! millisecond verification. What you pay: the keys are only valid for one
//! circuit shape, and whoever runs [`Backend::setup`] learns randomness that
//! would let them forge proofs. A real deployment runs it once, as a ceremony.

use super::Backend;
use crate::Fr;
use anyhow::{anyhow, Result};
use ark_bls12_377::Bls12_377;
use ark_groth16::{Groth16 as ArkGroth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

/// Groth16 over BLS12-377, whose scalar field is [`Fr`].
pub struct Groth16;

impl Backend for Groth16 {
    type ProvingKey = ProvingKey<Bls12_377>;
    type VerifyingKey = VerifyingKey<Bls12_377>;
    type Proof = Proof<Bls12_377>;

    fn setup<C, R>(circuit: C, rng: &mut R) -> Result<(Self::ProvingKey, Self::VerifyingKey)>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + CryptoRng,
    {
        ArkGroth16::<Bls12_377>::circuit_specific_setup(circuit, rng)
            .map_err(|e| anyhow!("Groth16 setup failed: {e}"))
    }

    fn prove<C, R>(proving_key: &Self::ProvingKey, circuit: C, rng: &mut R) -> Result<Self::Proof>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + CryptoRng,
    {
        ArkGroth16::<Bls12_377>::prove(proving_key, circuit, rng)
            .map_err(|e| anyhow!("Groth16 proving failed: {e}"))
    }

    fn verify(
        verifying_key: &Self::VerifyingKey,
        public_inputs: &[Fr],
        proof: &Self::Proof,
    ) -> Result<bool> {
        ArkGroth16::<Bls12_377>::verify(verifying_key, public_inputs, proof)
            .map_err(|e| anyhow!("Groth16 verification failed: {e}"))
    }
}
