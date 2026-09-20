//! A zero-knowledge proof that a ciphertext is the AES-128 ECB encryption of a
//! message under a secret key, with only the ciphertext made public.
//!
//! # The layers
//!
//! A SNARK over a circuit is a stack of independent pieces. Each one here is a
//! module, and each can be replaced without touching the others:
//!
//! | Layer | Module | What it does |
//! | --- | --- | --- |
//! | Field arithmetic | `ark-ff`, `ark-bls12-377` | the prime field `Fr` everything is expressed in |
//! | Gadgets | `ark-r1cs-std` | bytes and booleans as field variables, with XOR, AND, select |
//! | Field extension | [`gf256`] | GF(2^8), the field AES itself is defined over |
//! | Non-linear step | [`sbox`] | the S-box, two ways — and ~90% of the circuit's cost |
//! | Arithmetization | [`aes_gadget`] | AES-128 ECB as constraints |
//! | Relation | [`circuit`] | what is being proved: private message and key, public ciphertext |
//! | Proving system | [`backend`] | Groth16 or Spartan over that relation |
//!
//! Two field notions meet in the middle of that table and are easy to confuse.
//! AES is defined over GF(2^8), a 256-element field; the proof system works over
//! `Fr`, a prime field of ~2^253 elements. The circuit does not embed one in the
//! other: it represents each AES byte as eight `Fr` elements constrained to be
//! 0 or 1, and rebuilds GF(2^8) arithmetic out of XOR and AND on those bits.
//! That is why [`sbox`] is expensive and why the bitsliced form of it wins.
//!
//! # Usage
//!
//! ```no_run
//! # use rand::SeedableRng;
//! # let (message, secret_key, ciphertext) = ([1_u8; 16], [0_u8; 16], vec![0_u8; 16]);
//! let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);
//!
//! let (proving_key, verifying_key) = zk_aes::backend::groth16::setup(1, &mut rng)?;
//! let proof = zk_aes::backend::groth16::prove(
//!     &proving_key, &message, &secret_key, &ciphertext, &mut rng,
//! )?;
//! assert!(zk_aes::backend::groth16::verify(&verifying_key, &ciphertext, &proof)?);
//! # Ok::<(), anyhow::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(clippy::indexing_slicing, clippy::as_conversions, missing_docs)]

pub mod aes_gadget;
pub mod backend;
pub mod circuit;
pub mod gf256;
pub mod sbox;

use anyhow::{anyhow, Result};
use ark_r1cs_std::{prelude::AllocVar, uint8::UInt8, R1CSVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use circuit::AesEcbCircuit;
use sbox::SboxKind;

/// The scalar field of BLS12-377, which all constraints are expressed over.
pub use ark_bls12_377::Fr;

/// Encrypts inside the circuit and returns the ciphertext, without proving
/// anything.
///
/// Useful to check the arithmetization against a reference AES, and to count
/// constraints. See [`constraint_count`].
pub fn encrypt_circuit_only(message: &[u8], secret_key: &[u8; 16]) -> Result<Vec<u8>> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let sbox = sbox::Sbox::new(SboxKind::default(), cs.clone());

    let message_gadget: Vec<UInt8<Fr>> = message
        .iter()
        .map(|byte| UInt8::<Fr>::new_witness(cs.clone(), || Ok(*byte)))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("error allocating the message: {e}"))?;
    let key_gadget: Vec<UInt8<Fr>> = secret_key
        .iter()
        .map(|byte| UInt8::<Fr>::new_witness(cs.clone(), || Ok(*byte)))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("error allocating the key: {e}"))?;

    let ciphertext = aes_gadget::encrypt(&message_gadget, &key_gadget, &sbox)
        .map_err(|e| anyhow!("error generating constraints: {e}"))?;

    if !cs
        .is_satisfied()
        .map_err(|e| anyhow!("error checking the constraint system: {e}"))?
    {
        return Err(anyhow!("constraint system is not satisfied"));
    }

    ciphertext
        .value()
        .map_err(|e| anyhow!("error reading the ciphertext: {e}"))
}

/// The number of R1CS constraints the circuit generates for `num_blocks` blocks
/// under the given S-box.
pub fn constraint_count(num_blocks: usize, sbox: SboxKind) -> Result<usize> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    // The circuit carries no assignments here, only its shape.
    cs.set_mode(SynthesisMode::Setup);
    AesEcbCircuit::<Fr>::setup(num_blocks)
        .with_sbox(sbox)
        .generate_constraints(cs.clone())
        .map_err(|e| anyhow!("error generating constraints: {e}"))?;

    Ok(cs.num_constraints())
}
