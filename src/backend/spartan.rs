//! Spartan: a transparent SNARK, via `ark-spartan`.
//!
//! No trusted setup: [`Backend::setup`] only commits to the R1CS matrices, and
//! anyone can recompute that commitment from the circuit. The cost is a larger
//! proof and slower verification than Groth16.
//!
//! Most of this module is layout translation. Arkworks orders a constraint
//! row's variables as `[1, public inputs…, witness…]`; Spartan expects
//! `[witness…, 1, public inputs…]`.

use super::Backend;
use crate::Fr;
use anyhow::{anyhow, Result};
use ark_bls12_377::G1Projective;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_std::rand::{CryptoRng, RngCore};
use libspartan::{
    ComputationCommitment, ComputationDecommitment, InputsAssignment, Instance, SNARKGens,
    VarsAssignment, SNARK,
};
use merlin::Transcript;
use std::sync::Arc;

/// Domain separator for the Fiat-Shamir transcript. Prover and verifier must
/// agree on it.
const TRANSCRIPT_LABEL: &[u8] = b"zk-aes-spartan";

/// Spartan over BLS12-377's G1.
pub struct Spartan;

/// The public parameters and the commitment to the matrices, shared by both
/// keys. Neither is secret.
struct Shared {
    gens: SNARKGens<G1Projective>,
    commitment: ComputationCommitment<G1Projective>,
}

/// Spartan's proving key: the R1CS instance and the opening of its commitment.
pub struct ProvingKey {
    instance: Instance<Fr>,
    decommitment: ComputationDecommitment<Fr>,
    shared: Arc<Shared>,
}

/// Spartan's verifying key: the public parameters and the commitment.
pub struct VerifyingKey {
    shared: Arc<Shared>,
}

impl Backend for Spartan {
    type ProvingKey = ProvingKey;
    type VerifyingKey = VerifyingKey;
    type Proof = SNARK<G1Projective>;

    fn setup<C, R>(circuit: C, _rng: &mut R) -> Result<(Self::ProvingKey, Self::VerifyingKey)>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + CryptoRng,
    {
        // Synthesize the shape only, and read the matrices off it.
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        circuit
            .generate_constraints(cs.clone())
            .map_err(|e| anyhow!("error generating constraints: {e}"))?;
        cs.finalize();
        let matrices = cs
            .to_matrices()
            .ok_or_else(|| anyhow!("constraint matrices unavailable"))?;

        let num_witness = matrices.num_witness_variables;
        let num_public = matrices.num_instance_variables - 1;

        // Arkworks column -> Spartan column.
        let column = |index: usize| {
            if index == 0 {
                num_witness // the constant 1
            } else if index <= num_public {
                num_witness + index // public inputs follow the constant
            } else {
                index - num_public - 1 // witness variables come first
            }
        };
        let to_spartan = |rows: &[Vec<(Fr, usize)>]| -> Vec<(usize, usize, Fr)> {
            rows.iter()
                .enumerate()
                .flat_map(|(row, entries)| {
                    entries
                        .iter()
                        .map(move |(value, index)| (row, column(*index), *value))
                })
                .collect()
        };

        let instance = Instance::new(
            matrices.num_constraints,
            num_witness,
            num_public,
            &to_spartan(&matrices.a),
            &to_spartan(&matrices.b),
            &to_spartan(&matrices.c),
        )
        .map_err(|e| anyhow!("error building the Spartan instance: {e:?}"))?;

        let num_non_zero = matrices
            .a_num_non_zero
            .max(matrices.b_num_non_zero)
            .max(matrices.c_num_non_zero);
        let gens = SNARKGens::new(
            matrices.num_constraints,
            num_witness,
            num_public,
            num_non_zero,
        );
        let (commitment, decommitment) = SNARK::encode(&instance, &gens);

        let shared = Arc::new(Shared { gens, commitment });
        Ok((
            ProvingKey {
                instance,
                decommitment,
                shared: Arc::clone(&shared),
            },
            VerifyingKey { shared },
        ))
    }

    fn prove<C, R>(proving_key: &Self::ProvingKey, circuit: C, _rng: &mut R) -> Result<Self::Proof>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + CryptoRng,
    {
        // Synthesize with values, keeping only the assignment. The matrices
        // were fixed at setup.
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        circuit
            .generate_constraints(cs.clone())
            .map_err(|e| anyhow!("error generating constraints: {e}"))?;

        let (witness, public) = {
            let cs = cs
                .borrow()
                .ok_or_else(|| anyhow!("error reading the assignment"))?;
            (
                cs.witness_assignment.clone(),
                cs.instance_assignment[1..].to_vec(),
            )
        };
        let witness = VarsAssignment::new(&witness).map_err(|e| anyhow!("{e:?}"))?;
        let public = InputsAssignment::new(&public).map_err(|e| anyhow!("{e:?}"))?;

        Ok(SNARK::prove(
            &proving_key.instance,
            &proving_key.shared.commitment,
            &proving_key.decommitment,
            witness,
            &public,
            &proving_key.shared.gens,
            &mut Transcript::new(TRANSCRIPT_LABEL),
        ))
    }

    fn verify(
        verifying_key: &Self::VerifyingKey,
        public_inputs: &[Fr],
        proof: &Self::Proof,
    ) -> Result<bool> {
        let public = InputsAssignment::new(public_inputs).map_err(|e| anyhow!("{e:?}"))?;

        Ok(proof
            .verify(
                &verifying_key.shared.commitment,
                &public,
                &mut Transcript::new(TRANSCRIPT_LABEL),
                &verifying_key.shared.gens,
            )
            .is_ok())
    }
}
