//! Spartan: a transparent SNARK, via `ark-spartan`.
//!
//! No trusted setup and no toxic waste; the cost is a proof that is
//! logarithmically sized rather than constant, and slower verification.
//!
//! Internally this is a sum-check protocol over the multilinear extensions of
//! the R1CS matrices, compiled with a multilinear polynomial commitment — but
//! `ark-spartan` exposes the two as one `SNARK`, so all this module does is
//! translate Arkworks' R1CS into the layout Spartan expects.

use crate::circuit::AesEcbCircuit;
use crate::Fr;
use anyhow::{anyhow, Result};
use ark_bls12_377::G1Projective;
use ark_ff::Zero;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;

/// An R1CS instance and assignment, in Spartan's representation.
pub struct SpartanInstance {
    /// The matrices `A`, `B`, `C`.
    pub inst: Instance<Fr>,
    /// The private part of the assignment.
    pub vars: VarsAssignment<Fr>,
    /// The public part of the assignment: the ciphertext, bit by bit.
    pub inputs: InputsAssignment<Fr>,
    /// The largest number of non-zero entries across the three matrices.
    pub num_non_zero: usize,
    /// Number of constraints, i.e. matrix rows.
    pub num_cons: usize,
    /// Number of witness variables.
    pub num_vars: usize,
    /// Number of public inputs.
    pub num_inputs: usize,
}

/// Synthesizes the circuit and translates the result into Spartan's form.
///
/// The translation is all in the column layout: Arkworks orders a row as
/// `[1, public inputs…, witness…]`, Spartan as `[witness…, 1, public inputs…]`.
pub fn build_instance(
    message: &[u8],
    secret_key: &[u8; 16],
    ciphertext: &[u8],
) -> Result<SpartanInstance> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = AesEcbCircuit::<Fr>::prover(message, secret_key, ciphertext)?;
    circuit
        .generate_constraints(cs.clone())
        .map_err(|e| anyhow!("error generating constraints: {e}"))?;

    // Inline symbolic linear combinations so the matrices can be extracted.
    cs.finalize();
    let matrices = cs
        .to_matrices()
        .ok_or_else(|| anyhow!("constraint system matrices unavailable"))?;

    let num_cons = matrices.num_constraints;
    let num_vars = matrices.num_witness_variables;
    let num_inputs = matrices.num_instance_variables.saturating_sub(1);
    let ark_num_instance = matrices.num_instance_variables;

    let to_spartan_column = |index: usize| -> usize {
        if index == 0 {
            num_vars // the constant 1
        } else if index < ark_num_instance {
            num_vars + index // public inputs, after the constant
        } else {
            index - ark_num_instance // witness variables, first
        }
    };

    let convert = |rows: &[Vec<(Fr, usize)>]| -> Vec<(usize, usize, Fr)> {
        let mut out = Vec::new();
        for (row, entries) in rows.iter().enumerate() {
            for (coefficient, index) in entries {
                if !coefficient.is_zero() {
                    out.push((row, to_spartan_column(*index), *coefficient));
                }
            }
        }
        out
    };

    let (mat_a, mat_b, mat_c) = (
        convert(&matrices.a),
        convert(&matrices.b),
        convert(&matrices.c),
    );

    let num_non_zero = matrices
        .a_num_non_zero
        .max(matrices.b_num_non_zero)
        .max(matrices.c_num_non_zero);

    let borrowed = cs
        .borrow()
        .ok_or_else(|| anyhow!("error borrowing constraint system"))?;
    let witness = borrowed.witness_assignment.clone();
    let mut public: Vec<Fr> = borrowed.instance_assignment.iter().skip(1).copied().collect();
    public.resize(num_inputs, Fr::zero());
    drop(borrowed);

    let inst = Instance::new(num_cons, num_vars, num_inputs, &mat_a, &mat_b, &mat_c)
        .map_err(|e| anyhow!(format!("{e:?}")))?;
    let vars = VarsAssignment::new(&witness).map_err(|e| anyhow!(format!("{e:?}")))?;
    let inputs = InputsAssignment::new(&public).map_err(|e| anyhow!(format!("{e:?}")))?;

    if !inst
        .is_sat(&vars, &inputs)
        .map_err(|e| anyhow!(format!("{e:?}")))?
    {
        return Err(anyhow!("constructed Spartan instance is not satisfiable"));
    }

    Ok(SpartanInstance {
        inst,
        vars,
        inputs,
        num_non_zero,
        num_cons,
        num_vars,
        num_inputs,
    })
}

/// Proves and verifies in one call. There is no setup to separate out: the
/// public parameters here depend only on the circuit's size, not on secrets.
pub fn prove_and_verify(
    message: &[u8],
    secret_key: &[u8; 16],
    ciphertext: &[u8],
) -> Result<bool> {
    let instance = build_instance(message, secret_key, ciphertext)?;

    let gens = SNARKGens::<G1Projective>::new(
        instance.num_cons,
        instance.num_vars,
        instance.num_inputs,
        instance.num_non_zero,
    );

    let (comm, decomm) = SNARK::<G1Projective>::encode(&instance.inst, &gens);

    let mut prover_transcript = Transcript::new(b"zk-aes-spartan");
    let proof = SNARK::prove(
        &instance.inst,
        &comm,
        &decomm,
        instance.vars,
        &instance.inputs,
        &gens,
        &mut prover_transcript,
    );

    let mut verifier_transcript = Transcript::new(b"zk-aes-spartan");
    Ok(proof
        .verify(&comm, &instance.inputs, &mut verifier_transcript, &gens)
        .is_ok())
}
