//! Proving systems that consume [`crate::circuit::AesEcbCircuit`].
//!
//! Everything below this line is interchangeable. The circuit produces an R1CS
//! instance — matrices `A`, `B`, `C` and an assignment `z` with `Az ∘ Bz = Cz` —
//! and a backend is anything that can convince a verifier such a `z` exists
//! without revealing it.
//!
//! # Where the pieces actually live
//!
//! Modern SNARKs are usually described as an *information-theoretic protocol*
//! (a PIOP: the prover answers queries about polynomials) compiled with a
//! *polynomial commitment scheme* (a PCS: how those polynomials are committed to
//! and opened). That split is real, but it is not where these two backends draw
//! their boundaries:
//!
//! - [`groth16`] does not decompose this way at all. It compiles the R1CS to a
//!   QAP and checks a single pairing equation against a structured reference
//!   string. There is no separable PIOP or PCS inside it; the trusted setup is
//!   the price of that compactness.
//! - [`spartan`] does: it is a sum-check protocol over the multilinear
//!   extensions of `A`, `B`, `C` (the PIOP) compiled with a multilinear
//!   polynomial commitment (the PCS), which is what makes it transparent — no
//!   trusted setup. `ark-spartan` ships the two fused behind one `SNARK` type,
//!   so the seam is visible in the papers, not in its API.
//!
//! Arkworks does expose the PCS layer on its own, as `ark-poly-commit` (KZG,
//! IPA, Ligero, …). Pairing it with a PIOP of your own is how you would get a
//! stack where the two are genuinely swappable; `ark-marlin` was that PIOP, and
//! its last release, 0.3.0, is why this repo no longer uses it.

pub mod groth16;
pub mod spartan;
