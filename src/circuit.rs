//! The statement being proved, as a [`ConstraintSynthesizer`].
//!
//! This is the boundary between AES and the proof system. Above it are bytes
//! and rounds; below it is an R1CS instance that any backend can consume.

use crate::aes_gadget::{self, State};
use crate::sbox::SboxKind;
use anyhow::{ensure, Result};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocationMode, eq::EqGadget, prelude::AllocVar, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use core::array;

/// "I know a message and a key whose AES-128 ECB encryption is `ciphertext`."
///
/// The message and the key are private witnesses; the ciphertext is the public
/// input. The number of blocks and the S-box construction are the circuit's
/// *shape*: they are fixed at setup, and keys are only valid for that shape.
#[derive(Clone, Debug)]
pub struct AesEcbCircuit {
    /// Private: the plaintext, 16 bytes per block. `None` during setup.
    pub message: Option<Vec<u8>>,
    /// Private: the AES-128 key. `None` during setup.
    pub secret_key: Option<[u8; 16]>,
    /// Public: the ciphertext the verifier checks against. `None` during setup.
    pub ciphertext: Option<Vec<u8>>,
    /// How many 16-byte blocks the circuit encrypts.
    pub num_blocks: usize,
    /// How the S-box is arithmetized.
    pub sbox: SboxKind,
}

impl AesEcbCircuit {
    /// The circuit's shape with no values, for key generation.
    ///
    /// AES's constraints do not depend on the data being encrypted, so this
    /// produces exactly the same constraints as a filled-in circuit.
    pub fn setup(num_blocks: usize) -> Self {
        Self {
            message: None,
            secret_key: None,
            ciphertext: None,
            num_blocks,
            sbox: SboxKind::default(),
        }
    }

    /// The circuit with every value filled in, for proving.
    ///
    /// If `ciphertext` is not the encryption of `message`, the constraints are
    /// simply unsatisfiable and no valid proof can be produced.
    pub fn prover(message: &[u8], secret_key: &[u8; 16], ciphertext: &[u8]) -> Result<Self> {
        ensure!(
            !message.is_empty() && message.len() % 16 == 0,
            "message must be a non-empty multiple of 16 bytes, got {}",
            message.len()
        );
        ensure!(
            ciphertext.len() == message.len(),
            "ciphertext must be as long as the message"
        );

        Ok(Self {
            message: Some(message.to_vec()),
            secret_key: Some(*secret_key),
            ciphertext: Some(ciphertext.to_vec()),
            num_blocks: message.len() / 16,
            sbox: SboxKind::default(),
        })
    }

    /// Selects the S-box construction. Both are correct; they differ in cost.
    pub fn with_sbox(mut self, kind: SboxKind) -> Self {
        self.sbox = kind;
        self
    }

    /// The public inputs a verifier passes to a backend for `ciphertext`.
    ///
    /// Each byte is allocated as eight bits, least significant first, so this
    /// is the ciphertext flattened into bits. A verifier needs only this, the
    /// verifying key and the proof — never the circuit itself.
    pub fn public_inputs<F: PrimeField>(ciphertext: &[u8]) -> Vec<F> {
        ciphertext
            .iter()
            .flat_map(|byte| (0..8).map(move |i| F::from((byte >> i) & 1 == 1)))
            .collect()
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AesEcbCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let message = self.message.as_deref();
        let ciphertext = self.ciphertext.as_deref();

        // Private inputs.
        let blocks = (0..self.num_blocks)
            .map(|i| alloc_state(&cs, block(message, i), AllocationMode::Witness))
            .collect::<Result<Vec<_>, _>>()?;
        let key = alloc_state(
            &cs,
            self.secret_key.as_ref().map(<[u8; 16]>::as_slice),
            AllocationMode::Witness,
        )?;

        // The relation.
        let computed = aes_gadget::encrypt(&blocks, &key, self.sbox)?;

        // Public input: the claimed ciphertext, which must equal the computed one.
        for (i, computed_block) in computed.iter().enumerate() {
            let claimed = alloc_state(&cs, block(ciphertext, i), AllocationMode::Input)?;
            claimed.enforce_equal(computed_block)?;
        }

        Ok(())
    }
}

/// Allocates one 16-byte state, or 16 unassigned variables when `bytes` is
/// `None` (as during setup).
///
/// This goes byte by byte on purpose: Arkworks' `AllocVar` for arrays fails
/// outright on a missing value instead of allocating unassigned variables.
pub(crate) fn alloc_state<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    bytes: Option<&[u8]>,
    mode: AllocationMode,
) -> Result<State<F>, SynthesisError> {
    let mut state: State<F> = array::from_fn(|_| UInt8::constant(0));
    for (i, byte) in state.iter_mut().enumerate() {
        *byte = UInt8::new_variable(
            cs.clone(),
            || {
                bytes
                    .and_then(|b| b.get(i))
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            },
            mode,
        )?;
    }
    Ok(state)
}

fn block(bytes: Option<&[u8]>, index: usize) -> Option<&[u8]> {
    bytes.and_then(|b| b.get(16 * index..16 * (index + 1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference;
    use ark_bls12_377::Fr;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};

    const MESSAGE: [u8; 16] = [1; 16];
    const KEY: [u8; 16] = [0; 16];

    fn synthesize(circuit: AesEcbCircuit) -> ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs
    }

    #[test]
    fn satisfied_by_the_real_ciphertext() {
        let ciphertext = reference::encrypt(&MESSAGE, &KEY);
        let cs = synthesize(AesEcbCircuit::prover(&MESSAGE, &KEY, &ciphertext).unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn unsatisfied_by_any_other_ciphertext() {
        let mut ciphertext = reference::encrypt(&MESSAGE, &KEY);
        ciphertext[0] ^= 1;
        let cs = synthesize(AesEcbCircuit::prover(&MESSAGE, &KEY, &ciphertext).unwrap());
        assert!(!cs.is_satisfied().unwrap());
    }

    /// The verifier's inputs must match, element for element, what the circuit
    /// allocated. If they ever drift, proofs verify against the wrong statement.
    #[test]
    fn public_inputs_match_what_the_circuit_allocates() {
        let ciphertext = reference::encrypt(&MESSAGE, &KEY);
        let cs = synthesize(AesEcbCircuit::prover(&MESSAGE, &KEY, &ciphertext).unwrap());

        let allocated = cs.borrow().unwrap().instance_assignment[1..].to_vec();
        assert_eq!(allocated, AesEcbCircuit::public_inputs::<Fr>(&ciphertext));
    }

    /// Setup has no values; it must still produce exactly the same shape.
    #[test]
    fn setup_and_prover_have_the_same_shape() {
        let ciphertext = reference::encrypt(&MESSAGE, &KEY);
        let filled = synthesize(AesEcbCircuit::prover(&MESSAGE, &KEY, &ciphertext).unwrap());

        let empty = ConstraintSystem::<Fr>::new_ref();
        empty.set_mode(SynthesisMode::Setup);
        AesEcbCircuit::setup(1)
            .generate_constraints(empty.clone())
            .unwrap();

        assert_eq!(empty.num_constraints(), filled.num_constraints());
        assert_eq!(
            empty.num_instance_variables(),
            filled.num_instance_variables()
        );
        assert_eq!(
            empty.num_witness_variables(),
            filled.num_witness_variables()
        );
    }

    #[test]
    fn rejects_a_partial_block() {
        assert!(AesEcbCircuit::prover(&[0; 17], &KEY, &[0; 17]).is_err());
    }
}
