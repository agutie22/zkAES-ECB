use anyhow::{anyhow, Result};
use ark_bls12_377::{Fr, G1Projective};
use ark_ff::Zero;
use ark_r1cs_std::{prelude::AllocVar, uint8::UInt8, R1CSVar};
use ark_relations::r1cs::ConstraintSystem;
use libspartan::{InputsAssignment, Instance, SNARKGens, SNARK, VarsAssignment};
use merlin::Transcript;
use std::{fs::OpenOptions, io::Write};

pub struct SpartanArtifacts {
    pub inst: Instance<Fr>,
    pub vars: VarsAssignment<Fr>,
    pub inputs: InputsAssignment<Fr>,
    pub num_non_zero: usize,
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_inputs: usize,
}

pub fn build_spartan_instance_from_arkworks(
    message: &[u8],
    secret_key: &[u8; 16],
    ciphertext: &[u8],
) -> Result<SpartanArtifacts> {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let message_circuit: Vec<UInt8<Fr>> = message
        .iter()
        .map(|byte| UInt8::<Fr>::new_witness(cs.clone(), || Ok(*byte)))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!(e.to_owned()))?;

    let secret_key_circuit: Vec<UInt8<Fr>> = secret_key
        .iter()
        .map(|byte| UInt8::<Fr>::new_witness(cs.clone(), || Ok(*byte)))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!(e.to_owned()))?;

    let computed = crate::encrypt_and_generate_constraints(
        &message_circuit,
        &secret_key_circuit,
        cs.clone(),
    )?;

    let computed_bytes = computed
        .value()
        .map_err(|e| anyhow!(e.to_owned()))?;

    if computed_bytes.as_slice() != ciphertext {
        return Err(anyhow!(
            "ciphertext mismatch: expected {:?}, got {:?}",
            ciphertext,
            computed_bytes
        ));
    }

    // Finalize (inline symbolic LCs) so matrices can be extracted.
    cs.finalize();
    let matrices = cs
        .to_matrices()
        .ok_or_else(|| anyhow!("constraint system matrices unavailable"))?;

    let num_cons = matrices.num_constraints;
    let num_vars = matrices.num_witness_variables;
    let num_inputs = matrices.num_instance_variables.saturating_sub(1);

    // #region agent log
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(
        "/home/alexguti/projects/zkAES/AES_zero_knowledge_proof_circuit/.cursor/debug-40f02e.log",
    ) {
        let _ = writeln!(
            f,
            "{{\"sessionId\":\"40f02e\",\"runId\":\"spartan-pre\",\"hypothesisId\":\"H_sizes\",\"location\":\"src/spartan.rs:build_spartan_instance_from_arkworks\",\"message\":\"ark matrices sizes\",\"data\":{{\"num_cons\":{},\"num_vars\":{},\"num_inputs\":{},\"ark_num_instance_vars\":{},\"a_nnz\":{},\"b_nnz\":{},\"c_nnz\":{}}},\"timestamp\":{}}}",
            num_cons,
            num_vars,
            num_inputs,
            matrices.num_instance_variables,
            matrices.a_num_non_zero,
            matrices.b_num_non_zero,
            matrices.c_num_non_zero,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
    }
    // #endregion

    let mut mat_a: Vec<(usize, usize, Fr)> = Vec::new();
    let mut mat_b: Vec<(usize, usize, Fr)> = Vec::new();
    let mut mat_c: Vec<(usize, usize, Fr)> = Vec::new();

    let ark_num_instance = matrices.num_instance_variables;

    let push_row = |dst: &mut Vec<(usize, usize, Fr)>, row: usize, entries: &[(Fr, usize)]| {
        for (coeff, idx) in entries {
            if coeff.is_zero() {
                continue;
            }
            let col = if *idx == 0 {
                // constant 1 column is at index `num_vars` in Spartan's z layout
                num_vars
            } else if *idx < ark_num_instance {
                // public input columns (skip constant 1 at index 0)
                let input_idx = idx - 1;
                num_vars + 1 + input_idx
            } else {
                // witness columns
                let w_idx = idx - ark_num_instance;
                w_idx
            };
            dst.push((row, col, *coeff));
        }
    };

    for (r, row) in matrices.a.iter().enumerate() {
        push_row(&mut mat_a, r, row);
    }
    for (r, row) in matrices.b.iter().enumerate() {
        push_row(&mut mat_b, r, row);
    }
    for (r, row) in matrices.c.iter().enumerate() {
        push_row(&mut mat_c, r, row);
    }

    let num_non_zero = matrices
        .a_num_non_zero
        .max(matrices.b_num_non_zero)
        .max(matrices.c_num_non_zero);

    let cs_borrow = cs
        .borrow()
        .ok_or_else(|| anyhow!("error borrowing constraint system"))?;

    let vars_vec = cs_borrow.witness_assignment.clone();
    let mut inputs_vec: Vec<Fr> = cs_borrow
        .instance_assignment
        .iter()
        .skip(1)
        .copied()
        .collect();
    inputs_vec.resize(num_inputs, Fr::zero());

    let inst =
        Instance::new(num_cons, num_vars, num_inputs, &mat_a, &mat_b, &mat_c)
            .map_err(|e| anyhow!(format!("{e:?}")))?;
    let vars = VarsAssignment::new(&vars_vec).map_err(|e| anyhow!(format!("{e:?}")))?;
    let inputs = InputsAssignment::new(&inputs_vec).map_err(|e| anyhow!(format!("{e:?}")))?;

    if !inst
        .is_sat(&vars, &inputs)
        .map_err(|e| anyhow!(format!("{e:?}")))?
    {
        return Err(anyhow!("constructed Spartan instance is not satisfiable"));
    }

    Ok(SpartanArtifacts {
        inst,
        vars,
        inputs,
        num_non_zero,
        num_cons,
        num_vars,
        num_inputs,
    })
}

pub fn prove_and_verify(
    message: &[u8],
    secret_key: &[u8; 16],
    ciphertext: &[u8],
) -> Result<bool> {
    let artifacts = build_spartan_instance_from_arkworks(message, secret_key, ciphertext)?;

    let gens = SNARKGens::<G1Projective>::new(
        artifacts.num_cons,
        artifacts.num_vars,
        artifacts.num_inputs,
        artifacts.num_non_zero,
    );

    let (comm, decomm) = SNARK::<G1Projective>::encode(&artifacts.inst, &gens);
    let mut prover_transcript = Transcript::new(b"zk-aes-spartan");
    let proof = SNARK::prove(
        &artifacts.inst,
        &comm,
        &decomm,
        artifacts.vars,
        &artifacts.inputs,
        &gens,
        &mut prover_transcript,
    );

    let mut verifier_transcript = Transcript::new(b"zk-aes-spartan");
    let verify_res = proof.verify(&comm, &artifacts.inputs, &mut verifier_transcript, &gens);

    // #region agent log
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(
        "/home/alexguti/projects/zkAES/AES_zero_knowledge_proof_circuit/.cursor/debug-40f02e.log",
    ) {
        let ok = verify_res.is_ok();
        let err = verify_res.as_ref().err().map(|e| format!("{e:?}"));
        let err_json = err
            .as_ref()
            .map(|s| {
                let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{}\"", escaped)
            })
            .unwrap_or_else(|| "null".to_string());
        let _ = writeln!(
            f,
            "{{\"sessionId\":\"40f02e\",\"runId\":\"spartan-pre\",\"hypothesisId\":\"H_verify\",\"location\":\"src/spartan.rs:prove_and_verify\",\"message\":\"spartan verify result\",\"data\":{{\"ok\":{},\"err\":{}}},\"timestamp\":{}}}",
            ok,
            err_json,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
    }
    // #endregion

    Ok(verify_res.is_ok())
}
