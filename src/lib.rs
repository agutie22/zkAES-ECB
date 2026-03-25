#![warn(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![warn(
    clippy::allow_attributes_without_reason,
    clippy::as_conversions,
    clippy::as_ptr_cast_mut,
    clippy::unnecessary_cast,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::default_numeric_fallback,
    clippy::deref_by_slicing,
    clippy::empty_structs_with_brackets,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::indexing_slicing,
    clippy::iter_kv_map,
    clippy::manual_clamp,
    clippy::manual_filter,
    clippy::map_err_ignore,
    clippy::uninlined_format_args,
    clippy::unseparated_literal_suffix,
    clippy::unused_format_specs,
    clippy::single_char_lifetime_names,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_slice,
    clippy::string_to_string,
    clippy::todo,
    clippy::try_err
)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::let_underscore_must_use
)]

pub mod aes;
pub mod aes_circuit;
pub mod helpers;
pub mod ops;

use anyhow::{anyhow, Result};
pub use ark_bls12_377::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, prelude::AllocVar, uint8::UInt8, R1CSVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use helpers::traits::ToAnyhow;

/// Circuit-only AES encryption.
///
/// Builds the constraint system, generates AES constraints, and returns the computed ciphertext bytes.
pub fn encrypt_circuit_only(message: &[u8], secret_key: &[u8; 16]) -> Result<Vec<u8>> {
    let constraint_system = ConstraintSystem::<Fr>::new_ref();

    let message_circuit: Vec<UInt8<Fr>> = message
        .iter()
        .map(|byte| UInt8::<Fr>::new_witness(constraint_system.clone(), || Ok(*byte)))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!(e.to_owned()))?;

    let secret_key_circuit: Vec<UInt8<Fr>> = secret_key
        .iter()
        .map(|byte| UInt8::<Fr>::new_witness(constraint_system.clone(), || Ok(*byte)))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!(e.to_owned()))?;

    let computed = encrypt_and_generate_constraints(
        &message_circuit,
        &secret_key_circuit,
        constraint_system.clone(),
    )?;

    let out = computed
        .value()
        .map_err(|e| anyhow!(e.to_owned()))?
        .to_vec();

    if !constraint_system
        .is_satisfied()
        .map_err(|e| anyhow!(e.to_owned()))?
    {
        return Err(anyhow!("Constraint system is not satisfied"));
    }

    Ok(out)
}

pub fn encrypt_and_generate_constraints<F: PrimeField>(
    message: &[UInt8<F>],
    secret_key: &[UInt8<F>],
    constraint_system: ConstraintSystemRef<F>,
) -> Result<Vec<UInt8<F>>> {
    let mut computed_ciphertext: Vec<UInt8<F>> = Vec::new();
    let lookup_table = aes_circuit::lookup_table(constraint_system.clone())?;
    helpers::debug_constraint_system_status(
        "After generating the lookup table",
        constraint_system.clone(),
    )?;
    let round_keys =
        aes_circuit::derive_keys(secret_key, &lookup_table, constraint_system.clone())?;
    helpers::debug_constraint_system_status(
        "After deriving the round keys",
        constraint_system.clone(),
    )?;

    for block in message.chunks(16) {
        // Round 0
        let mut after_add_round_key = aes_circuit::add_round_key(block, secret_key)?;
        helpers::debug_constraint_system_status(
            "After adding round key in round 0",
            constraint_system.clone(),
        )?;
        // Rounds 1 to 9
        // Starting at 1 will skip the first round key which is the same as
        // the secret key.
        for round in 1_usize..=9_usize {
            // Step 1
            let after_substitute_bytes =
                aes_circuit::substitute_bytes(&after_add_round_key, &lookup_table)?;
            helpers::debug_constraint_system_status(
                &format!("After substituting bytes in round {round}"),
                constraint_system.clone(),
            )?;
            // Step 2
            let after_shift_rows =
                aes_circuit::shift_rows(&after_substitute_bytes, constraint_system.clone())
                    .to_anyhow("Error shifting rows")?;
            helpers::debug_constraint_system_status(
                &format!("After shifting rows in round {round}"),
                constraint_system.clone(),
            )?;
            // Step 3
            let after_mix_columns =
                aes_circuit::mix_columns(&after_shift_rows, constraint_system.clone())
                    .to_anyhow("Error mixing columns when encrypting")?;
            helpers::debug_constraint_system_status(
                &format!("After mixing columns in round {round}"),
                constraint_system.clone(),
            )?;
            // Step 4
            after_add_round_key = aes_circuit::add_round_key(
                &after_mix_columns,
                round_keys
                    .get(round)
                    .to_anyhow(&format!("Error getting round key in round {round}"))?,
            )?;
            helpers::debug_constraint_system_status(
                &format!("After adding round key in round {round}"),
                constraint_system.clone(),
            )?;
        }

        // Round 10
        // We are hardcoding round 10 because in AES there is no need to mix
        // columns in the last round. Besides this way we are generating less
        // constraints.
        // Step 1
        let after_substitute_bytes =
            aes_circuit::substitute_bytes(&after_add_round_key, &lookup_table)?;
        helpers::debug_constraint_system_status(
            "After substituting bytes in round 10",
            constraint_system.clone(),
        )?;
        // Step 2
        let after_shift_rows =
            aes_circuit::shift_rows(&after_substitute_bytes, constraint_system.clone())
                .to_anyhow("Error shifting rows")?;
        helpers::debug_constraint_system_status(
            "After shifting rows in round 10",
            constraint_system.clone(),
        )?;
        // Step 3
        after_add_round_key = aes_circuit::add_round_key(
            &after_shift_rows,
            round_keys
                .get(10)
                .to_anyhow("Error getting round key in round 10")?,
        )?;
        helpers::debug_constraint_system_status(
            "After adding round key in round 10",
            constraint_system.clone(),
        )?;

        let mut ciphertext_chunk = vec![];

        for u8_gadget in after_add_round_key {
            ciphertext_chunk.push(u8_gadget);
        }

        computed_ciphertext.extend_from_slice(&ciphertext_chunk);
    }

    // finally, we insert the computed ciphertext as a public input of the circuit
    for byte in &computed_ciphertext {
        let value = byte.value().map_err(|e| anyhow!(e.to_owned()))?;
        let public_input = UInt8::<F>::new_input(constraint_system.clone(), || Ok(value))?;
        public_input.enforce_equal(byte)?;
    }
    helpers::debug_constraint_system_status(
        "After enforcing that the obtained ciphertext is equal to the given one",
        constraint_system,
    )?;

    Ok(computed_ciphertext)
}
