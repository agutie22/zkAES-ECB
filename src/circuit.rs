//! The AES-128 ECB relation as a self-contained [`ConstraintSynthesizer`].
//!
//! This is the shape every Arkworks SNARK backend expects: a struct holding the
//! witness (plaintext, key) and the instance (ciphertext), plus an impl that
//! writes the constraints. Handing it to a backend is then a one-liner, which is
//! what makes the choice of proof system a swappable detail rather than a rewrite.

use crate::aes_gadget::{self, BLOCK_SIZE, KEY_SIZE};
use crate::sbox::{Sbox, SboxKind};
use anyhow::{ensure, Result};
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, prelude::AllocVar, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;

/// The statement: "I know a message and a key whose AES-128 ECB encryption is
/// `ciphertext`", where `ciphertext` is public and the rest is private.
///
/// The number of blocks is part of the circuit *shape*, so it is fixed at setup
/// time and a proving key is only valid for that many blocks.
#[derive(Clone, Debug)]
pub struct AesEcbCircuit<F: PrimeField> {
    /// Private: the plaintext, `num_blocks * BLOCK_SIZE` bytes.
    pub message: Option<Vec<u8>>,
    /// Private: the AES-128 secret key.
    pub secret_key: Option<[u8; KEY_SIZE]>,
    /// Public: the ciphertext the verifier is checking against.
    pub ciphertext: Option<Vec<u8>>,
    /// The circuit shape: how many 16-byte blocks this instance encrypts.
    pub num_blocks: usize,
    /// Which S-box construction to arithmetize with. Part of the shape: keys
    /// generated for one kind do not verify proofs built with the other.
    pub sbox: SboxKind,
    field: PhantomData<F>,
}

impl<F: PrimeField> AesEcbCircuit<F> {
    /// The circuit with no assignments, for key generation.
    ///
    /// The constraints AES generates do not depend on the values being encrypted,
    /// so this produces exactly the same shape as a populated instance.
    #[must_use]
    pub fn setup(num_blocks: usize) -> Self {
        Self {
            message: None,
            secret_key: None,
            ciphertext: None,
            num_blocks,
            sbox: SboxKind::default(),
            field: PhantomData,
        }
    }

    /// Selects the S-box construction. Both are correct; they differ in cost.
    #[must_use]
    pub fn with_sbox(mut self, kind: SboxKind) -> Self {
        self.sbox = kind;
        self
    }

    /// The fully assigned circuit, for proving.
    ///
    /// `ciphertext` is what the prover claims and the verifier will check; if it
    /// is not the real encryption of `message`, the constraint system simply
    /// won't be satisfiable.
    pub fn prover(message: &[u8], secret_key: &[u8; KEY_SIZE], ciphertext: &[u8]) -> Result<Self> {
        ensure!(
            !message.is_empty() && message.len() % BLOCK_SIZE == 0,
            "message must be a non-empty multiple of {BLOCK_SIZE} bytes, got {}",
            message.len()
        );
        ensure!(
            ciphertext.len() == message.len(),
            "ciphertext must be {} bytes, got {}",
            message.len(),
            ciphertext.len()
        );

        Ok(Self {
            message: Some(message.to_vec()),
            secret_key: Some(*secret_key),
            ciphertext: Some(ciphertext.to_vec()),
            num_blocks: message.len() / BLOCK_SIZE,
            sbox: SboxKind::default(),
            field: PhantomData,
        })
    }

    /// The public input vector a verifier passes to the backend.
    ///
    /// `UInt8` allocates one instance variable per bit, least significant first,
    /// so the ciphertext flattens to `8 * ciphertext.len()` field elements. A
    /// verifier needs only this and the verifying key — never the circuit.
    #[must_use]
    pub fn public_inputs(ciphertext: &[u8]) -> Vec<F> {
        let mut inputs = Vec::with_capacity(ciphertext.len() * 8);
        for byte in ciphertext {
            for i in 0_u32..8_u32 {
                inputs.push(F::from((byte >> i) & 1_u8 == 1_u8));
            }
        }
        inputs
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AesEcbCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let num_bytes = self.num_blocks * BLOCK_SIZE;

        // Private inputs. In setup mode the missing assignments are expected and
        // the gadgets allocate unassigned variables instead.
        let message = (0..num_bytes)
            .map(|i| {
                UInt8::new_witness(cs.clone(), || {
                    self.message
                        .as_ref()
                        .and_then(|m| m.get(i))
                        .copied()
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let secret_key = (0..KEY_SIZE)
            .map(|i| {
                UInt8::new_witness(cs.clone(), || {
                    self.secret_key
                        .as_ref()
                        .and_then(|k| k.get(i))
                        .copied()
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // The relation itself.
        let sbox = Sbox::new(self.sbox, cs.clone());
        let computed = aes_gadget::encrypt(&message, &secret_key, &sbox)?;

        // Public input: the ciphertext, as supplied by the verifier, constrained
        // to equal what the circuit computed from the private inputs.
        for (i, computed_byte) in computed.iter().enumerate() {
            let expected = UInt8::new_input(cs.clone(), || {
                self.ciphertext
                    .as_ref()
                    .and_then(|c| c.get(i))
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            expected.enforce_equal(computed_byte)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fr;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};
    use digest::generic_array::GenericArray;

    fn reference_encrypt(message: &[u8], secret_key: &[u8; KEY_SIZE]) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(secret_key));
        let mut out = Vec::with_capacity(message.len());
        for chunk in message.chunks(BLOCK_SIZE) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(block.as_slice());
        }
        out
    }

    #[test]
    fn satisfied_for_the_correct_ciphertext() {
        let message = [1_u8; BLOCK_SIZE];
        let secret_key = [0_u8; KEY_SIZE];
        let ciphertext = reference_encrypt(&message, &secret_key);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = AesEcbCircuit::<Fr>::prover(&message, &secret_key, &ciphertext).unwrap();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn unsatisfied_for_a_wrong_ciphertext() {
        let message = [1_u8; BLOCK_SIZE];
        let secret_key = [0_u8; KEY_SIZE];
        let mut ciphertext = reference_encrypt(&message, &secret_key);
        // Flip one bit of the claimed ciphertext.
        *ciphertext.get_mut(0).unwrap() ^= 1_u8;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = AesEcbCircuit::<Fr>::prover(&message, &secret_key, &ciphertext).unwrap();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    /// The verifier's `public_inputs` must match, element for element, what the
    /// circuit allocated as instance variables. If these ever disagree, proofs
    /// verify against the wrong statement.
    #[test]
    fn public_inputs_match_the_allocated_instance_variables() {
        let message = [1_u8; BLOCK_SIZE];
        let secret_key = [0_u8; KEY_SIZE];
        let ciphertext = reference_encrypt(&message, &secret_key);

        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        let circuit = AesEcbCircuit::<Fr>::prover(&message, &secret_key, &ciphertext).unwrap();
        circuit.generate_constraints(cs.clone()).unwrap();

        let allocated: Vec<Fr> = cs
            .borrow()
            .unwrap()
            .instance_assignment
            .iter()
            .skip(1) // the constant 1
            .copied()
            .collect();

        assert_eq!(allocated, AesEcbCircuit::<Fr>::public_inputs(&ciphertext));
    }

    /// Setup mode has no assignments; it must still produce the same shape.
    #[test]
    fn setup_mode_produces_the_same_shape() {
        let message = [1_u8; BLOCK_SIZE];
        let secret_key = [0_u8; KEY_SIZE];
        let ciphertext = reference_encrypt(&message, &secret_key);

        let assigned = ConstraintSystem::<Fr>::new_ref();
        AesEcbCircuit::<Fr>::prover(&message, &secret_key, &ciphertext)
            .unwrap()
            .generate_constraints(assigned.clone())
            .unwrap();

        let empty = ConstraintSystem::<Fr>::new_ref();
        empty.set_mode(ark_relations::r1cs::SynthesisMode::Setup);
        AesEcbCircuit::<Fr>::setup(1)
            .generate_constraints(empty.clone())
            .unwrap();

        assert_eq!(empty.num_constraints(), assigned.num_constraints());
        assert_eq!(
            empty.num_instance_variables(),
            assigned.num_instance_variables()
        );
        assert_eq!(
            empty.num_witness_variables(),
            assigned.num_witness_variables()
        );
    }

    #[test]
    fn rejects_a_misaligned_message() {
        assert!(AesEcbCircuit::<Fr>::prover(&[0_u8; 17], &[0_u8; KEY_SIZE], &[0_u8; 17]).is_err());
    }
}
