//! Zero-knowledge needs fresh, secret randomness in every proof. If a
//! prover's randomness were fixed, proving the same statement twice would give
//! byte-identical proofs, and the blinding that hides the witness would be
//! public. These tests use a one-constraint circuit, since the property has
//! nothing to do with AES and the full circuit would make them slow.

use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use zk_aes::backend::{spartan::Spartan, Backend};
use zk_aes::Fr;

/// "I know `x` such that `x * x = y`", with `y` public.
#[derive(Clone)]
struct Square {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Square {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = FpVar::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FpVar::new_input(cs, || self.y.ok_or(SynthesisError::AssignmentMissing))?;
        (&x * &x).enforce_equal(&y)
    }
}

#[test]
fn spartan_proofs_of_the_same_statement_differ() {
    let (x, y) = (Fr::from(3_u64), Fr::from(9_u64));
    let shape = Square { x: None, y: None };
    let filled = Square {
        x: Some(x),
        y: Some(y),
    };
    let mut rng = ChaCha20Rng::seed_from_u64(0);

    let (pk, vk) = Spartan::setup(shape, &mut rng).unwrap();
    let first = Spartan::prove(&pk, filled.clone(), &mut rng).unwrap();
    let second = Spartan::prove(&pk, filled, &mut rng).unwrap();

    // Both must still verify.
    assert!(Spartan::verify(&vk, &[y], &first).unwrap());
    assert!(Spartan::verify(&vk, &[y], &second).unwrap());

    let mut first_bytes = Vec::new();
    let mut second_bytes = Vec::new();
    first.serialize_compressed(&mut first_bytes).unwrap();
    second.serialize_compressed(&mut second_bytes).unwrap();

    assert_ne!(
        first_bytes, second_bytes,
        "two proofs of the same statement are identical: the prover's blinding \
         randomness is deterministic, so the proofs are not zero-knowledge"
    );
}
