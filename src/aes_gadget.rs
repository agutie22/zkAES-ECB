//! AES-128 ECB, written against constraint-system bytes.
//!
//! This is the arithmetization: it turns the AES specification into R1CS
//! constraints via `ark-r1cs-std`'s gadgets, and knows nothing about proving.
//! Each function is one step of FIPS-197 on the same 4x4 byte [`State`].
//!
//! Three of the four round steps are nearly free — `ShiftRows` only rewires
//! variables, `AddRoundKey` is XOR, `MixColumns` is XOR plus [`xtime`] — so
//! essentially all of the cost is the S-box, the only step that can fail.

use crate::gf256::xtime;
use crate::sbox::SboxKind;
use ark_ff::PrimeField;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;
use core::array;

/// AES-128 runs ten rounds, and so needs eleven round keys.
pub const ROUNDS: usize = 10;

/// The AES state: 16 bytes, stored column by column.
pub type State<F> = [UInt8<F>; 16];

/// The output of the key schedule: one key per round, plus the initial one.
pub type RoundKeys<F> = [State<F>; ROUNDS + 1];

/// The key schedule's round constants, `x^(i-1)` in GF(2^8).
const ROUND_CONSTANTS: [u8; ROUNDS] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Where each byte of the state comes from after `ShiftRows`: rotating row `r`
/// left by `r`, expressed as a permutation of the column-major state.
const SHIFT_ROWS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

/// Encrypts each block independently under the same key: ECB mode.
pub fn encrypt<F: PrimeField>(
    blocks: &[State<F>],
    key: &State<F>,
    sbox: SboxKind,
) -> Result<Vec<State<F>>, SynthesisError> {
    let round_keys = key_schedule(key, sbox)?;

    blocks
        .iter()
        .map(|block| encrypt_block(block, &round_keys, sbox))
        .collect()
}

/// Encrypts one block: an initial key addition, nine full rounds, and a final
/// round without `MixColumns`.
pub fn encrypt_block<F: PrimeField>(
    block: &State<F>,
    round_keys: &RoundKeys<F>,
    sbox: SboxKind,
) -> Result<State<F>, SynthesisError> {
    let [first_key, middle_keys @ .., last_key] = round_keys;

    let mut state = add_round_key(block, first_key);

    for round_key in middle_keys {
        state = sub_bytes(&state, sbox)?;
        state = shift_rows(&state);
        state = mix_columns(&state);
        state = add_round_key(&state, round_key);
    }

    state = sub_bytes(&state, sbox)?;
    state = shift_rows(&state);
    Ok(add_round_key(&state, last_key))
}

/// Expands the key into the eleven round keys.
///
/// The schedule works in 4-byte words: four copied from the key, forty derived.
/// Every fourth word goes through the S-box, which is where 40 of the 200 S-box
/// applications per block come from.
pub fn key_schedule<F: PrimeField>(
    key: &State<F>,
    sbox: SboxKind,
) -> Result<RoundKeys<F>, SynthesisError> {
    let mut words: Vec<[UInt8<F>; 4]> = key
        .chunks_exact(4)
        .map(|word| array::from_fn(|i| word[i].clone()))
        .collect();

    for i in 4..4 * (ROUNDS + 1) {
        let mut word = words[i - 1].clone();

        if i % 4 == 0 {
            word.rotate_left(1); // RotWord
            for byte in &mut word {
                *byte = sbox.apply(byte)?; // SubWord
            }
            word[0] = &word[0] ^ ROUND_CONSTANTS[i / 4 - 1]; // Rcon
        }

        let next = array::from_fn(|j| &words[i - 4][j] ^ &word[j]);
        words.push(next);
    }

    Ok(array::from_fn(|round| {
        array::from_fn(|j| words[4 * round + j / 4][j % 4].clone())
    }))
}

/// Replaces every byte of the state with its S-box image.
pub fn sub_bytes<F: PrimeField>(
    state: &State<F>,
    sbox: SboxKind,
) -> Result<State<F>, SynthesisError> {
    let mut substituted = state.clone();
    for byte in &mut substituted {
        *byte = sbox.apply(byte)?;
    }
    Ok(substituted)
}

/// Rotates the rows of the state. Free: it only moves variables around.
pub fn shift_rows<F: PrimeField>(state: &State<F>) -> State<F> {
    array::from_fn(|i| state[SHIFT_ROWS[i]].clone())
}

/// Multiplies each column by the MixColumns matrix over GF(2^8).
///
/// The matrix rows are rotations of `[2 3 1 1]`. With `b = 2·a` computed by
/// [`xtime`] and `3·a = 2·a ⊕ a`, each output byte is a five-way XOR.
pub fn mix_columns<F: PrimeField>(state: &State<F>) -> State<F> {
    let mut mixed = state.clone();

    for column in 0..4 {
        let a: [UInt8<F>; 4] = array::from_fn(|row| state[4 * column + row].clone());
        let b = a.each_ref().map(xtime);

        mixed[4 * column] = xor([&b[0], &b[1], &a[1], &a[2], &a[3]]); // [2 3 1 1]
        mixed[4 * column + 1] = xor([&a[0], &b[1], &b[2], &a[2], &a[3]]); // [1 2 3 1]
        mixed[4 * column + 2] = xor([&a[0], &a[1], &b[2], &b[3], &a[3]]); // [1 1 2 3]
        mixed[4 * column + 3] = xor([&b[0], &a[0], &a[1], &a[2], &b[3]]); // [3 1 1 2]
    }

    mixed
}

/// XORs the state with a round key.
pub fn add_round_key<F: PrimeField>(state: &State<F>, round_key: &State<F>) -> State<F> {
    array::from_fn(|i| &state[i] ^ &round_key[i])
}

fn xor<F: PrimeField>(bytes: [&UInt8<F>; 5]) -> UInt8<F> {
    let [first, rest @ ..] = bytes;
    rest.iter().fold(first.clone(), |acc, byte| acc ^ *byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    // All vectors are from FIPS-197, Appendix B.
    const PLAINTEXT: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];
    const KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const AFTER_ADD_ROUND_KEY: [u8; 16] = [
        0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48,
        0x08,
    ];
    const AFTER_SUB_BYTES: [u8; 16] = [
        0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52,
        0x30,
    ];
    const AFTER_SHIFT_ROWS: [u8; 16] = [
        0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98,
        0xe5,
    ];
    const AFTER_MIX_COLUMNS: [u8; 16] = [
        0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26,
        0x4c,
    ];
    const LAST_ROUND_KEY: [u8; 16] = [
        0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c,
        0xa6,
    ];
    const CIPHERTEXT: [u8; 16] = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b,
        0x32,
    ];

    fn witness(cs: &ConstraintSystemRef<Fr>, bytes: [u8; 16]) -> State<Fr> {
        array::from_fn(|i| UInt8::new_witness(cs.clone(), || Ok(bytes[i])).unwrap())
    }

    #[test]
    fn add_round_key_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = add_round_key(&witness(&cs, PLAINTEXT), &witness(&cs, KEY));
        assert_eq!(result.value().unwrap(), AFTER_ADD_ROUND_KEY);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn sub_bytes_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let state = witness(&cs, AFTER_ADD_ROUND_KEY);
        for kind in [SboxKind::Bitsliced, SboxKind::Lookup] {
            let result = sub_bytes(&state, kind).unwrap();
            assert_eq!(result.value().unwrap(), AFTER_SUB_BYTES, "{kind:?}");
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn shift_rows_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = shift_rows(&witness(&cs, AFTER_SUB_BYTES));
        assert_eq!(result.value().unwrap(), AFTER_SHIFT_ROWS);
    }

    #[test]
    fn mix_columns_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = mix_columns(&witness(&cs, AFTER_SHIFT_ROWS));
        assert_eq!(result.value().unwrap(), AFTER_MIX_COLUMNS);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn key_schedule_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let round_keys = key_schedule(&witness(&cs, KEY), SboxKind::default()).unwrap();
        assert_eq!(round_keys[0].value().unwrap(), KEY);
        assert_eq!(round_keys[ROUNDS].value().unwrap(), LAST_ROUND_KEY);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn encrypts_the_fips_197_block() {
        for kind in [SboxKind::Bitsliced, SboxKind::Lookup] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let blocks = [witness(&cs, PLAINTEXT)];
            let ciphertext = encrypt(&blocks, &witness(&cs, KEY), kind).unwrap();
            assert_eq!(ciphertext[0].value().unwrap(), CIPHERTEXT, "{kind:?}");
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
