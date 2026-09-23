//! Proving systems, behind one interface.
//!
//! A backend sees only an R1CS instance — matrices `A`, `B`, `C` and an
//! assignment `z` with `Az ∘ Bz = Cz` — and convinces a verifier such a `z`
//! exists without revealing it. It knows nothing about AES: any
//! [`ConstraintSynthesizer`] works. To add a proving system, implement
//! [`Backend`].
//!
//! # Where PIOPs and polynomial commitments live
//!
//! Modern SNARKs are usually described as an information-theoretic protocol
//! over polynomials (a PIOP) compiled with a polynomial commitment scheme (a
//! PCS). That split is real, but it is not where these two backends draw
//! their boundaries:
//!
//! - [`groth16`] does not decompose this way at all. It compiles the R1CS to a
//!   QAP and checks one pairing equation against a structured reference
//!   string. The trusted setup is the price of a three-element proof.
//! - [`spartan`] does: a sum-check protocol over the multilinear extensions of
//!   `A`, `B`, `C` (the PIOP), compiled with a multilinear polynomial
//!   commitment (the PCS). That is what makes it transparent. `ark-spartan`
//!   ships the two fused behind one type, so the seam is in the papers, not
//!   the API.
//!
//! Arkworks does expose the PCS layer on its own, as `ark-poly-commit` (KZG,
//! IPA, Ligero). Pairing it with a PIOP of your own is how you would get a
//! stack where the two are genuinely interchangeable; `ark-marlin` was that
//! PIOP, and its last release, 0.3.0, is why this project does not use it.

pub mod groth16;
pub mod spartan;

use crate::Fr;
use anyhow::Result;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::{CryptoRng, RngCore};

/// A proving system for R1CS over [`Fr`].
///
/// The three steps mirror `ark_snark::SNARK`, without its requirement that
/// keys be serializable, which Spartan's are not.
pub trait Backend {
    /// What the prover needs besides the circuit.
    type ProvingKey;
    /// What the verifier needs besides the public inputs.
    type VerifyingKey;
    /// The proof itself.
    type Proof;

    /// Derives keys from the circuit's shape. The circuit carries no values
    /// here, only its structure.
    fn setup<C, R>(circuit: C, rng: &mut R) -> Result<(Self::ProvingKey, Self::VerifyingKey)>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + CryptoRng;

    /// Proves that the filled-in circuit is satisfied.
    fn prove<C, R>(proving_key: &Self::ProvingKey, circuit: C, rng: &mut R) -> Result<Self::Proof>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + CryptoRng;

    /// Checks a proof against the public inputs alone.
    fn verify(
        verifying_key: &Self::VerifyingKey,
        public_inputs: &[Fr],
        proof: &Self::Proof,
    ) -> Result<bool>;
}
