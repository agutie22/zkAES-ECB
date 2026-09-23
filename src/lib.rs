//! A zero-knowledge proof that a ciphertext is the AES-128 ECB encryption of a
//! message under a secret key, with only the ciphertext made public.
//!
//! # The layers
//!
//! Each layer is one module and depends only on the ones above it, so any of
//! them can be read, tested or replaced on its own:
//!
//! | Layer | Module | What it does |
//! | --- | --- | --- |
//! | Specification | [`reference`] | AES outside the circuit: what "correct" means |
//! | Field arithmetic | [`gf256`] | GF(2^8), the field AES is defined over |
//! | Non-linear step | [`sbox`] | the S-box, two ways; ~75% of the circuit's cost |
//! | Arithmetization | [`aes_gadget`] | AES-128 ECB as constraints |
//! | Relation | [`circuit`] | private message and key, public ciphertext |
//! | Proving system | [`backend`] | Groth16 or Spartan, behind one trait |
//!
//! Two notions of "field" meet in the middle. AES works in GF(2^8), a field of
//! 256 elements; the proof system works in [`Fr`], a prime field of about
//! 2^253 elements. The circuit does not embed one in the other: it represents
//! each AES byte as eight `Fr` elements constrained to be 0 or 1, and rebuilds
//! GF(2^8) arithmetic out of XOR and AND on those bits. That is why the S-box,
//! AES's one non-linear step, dominates the cost.
//!
//! # Usage
//!
//! ```no_run
//! use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
//! use zk_aes::backend::{groth16::Groth16, Backend};
//! use zk_aes::circuit::AesEcbCircuit;
//!
//! let (message, secret_key) = ([1_u8; 16], [0_u8; 16]);
//! let ciphertext = zk_aes::reference::encrypt(&message, &secret_key);
//! let mut rng = ChaCha20Rng::seed_from_u64(0);
//!
//! let (pk, vk) = Groth16::setup(AesEcbCircuit::setup(1), &mut rng)?;
//! let circuit = AesEcbCircuit::prover(&message, &secret_key, &ciphertext)?;
//! let proof = Groth16::prove(&pk, circuit, &mut rng)?;
//!
//! let public_inputs = AesEcbCircuit::public_inputs(&ciphertext);
//! assert!(Groth16::verify(&vk, &public_inputs, &proof)?);
//! # Ok::<(), anyhow::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod aes_gadget;
pub mod backend;
pub mod circuit;
pub mod gf256;
pub mod reference;
pub mod sbox;

use anyhow::{anyhow, ensure, Result};
use ark_r1cs_std::{alloc::AllocationMode, R1CSVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use circuit::{alloc_state, AesEcbCircuit};
use sbox::SboxKind;

/// The scalar field of BLS12-377, which every constraint is expressed over.
pub use ark_bls12_377::Fr;

/// Runs AES inside the circuit and returns the ciphertext, without proving
/// anything. Useful to check the arithmetization against [`reference::encrypt`].
pub fn encrypt_circuit_only(message: &[u8], secret_key: &[u8; 16]) -> Result<Vec<u8>> {
    let (blocks, rest) = message.as_chunks::<16>();
    ensure!(
        rest.is_empty(),
        "message must be a whole number of 16-byte blocks"
    );
    let cs = ConstraintSystem::<Fr>::new_ref();
    let err = |e| anyhow!("constraint system error: {e}");

    let blocks = blocks
        .iter()
        .map(|block| alloc_state(&cs, Some(block), AllocationMode::Witness))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    let key = alloc_state(&cs, Some(secret_key), AllocationMode::Witness).map_err(err)?;

    let ciphertext = aes_gadget::encrypt(&blocks, &key, SboxKind::default()).map_err(err)?;
    ensure!(cs.is_satisfied().map_err(err)?, "constraints not satisfied");

    Ok(ciphertext.value().map_err(err)?.concat())
}

/// How many R1CS constraints the circuit has for `num_blocks` blocks.
pub fn constraint_count(num_blocks: usize, sbox: SboxKind) -> Result<usize> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    AesEcbCircuit::setup(num_blocks)
        .with_sbox(sbox)
        .generate_constraints(cs.clone())
        .map_err(|e| anyhow!("error generating constraints: {e}"))?;

    Ok(cs.num_constraints())
}
