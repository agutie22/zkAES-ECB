//! AES-128 ECB, written against constraint-system bytes.
//!
//! This is the arithmetization layer: it turns the AES specification into R1CS
//! constraints via `ark-r1cs-std`'s gadgets, and knows nothing about proving.
//! Three of the four round steps are nearly free — `ShiftRows` is a permutation
//! of existing variables, `AddRoundKey` is XOR, `MixColumns` is XOR plus
//! [`gf256::xtime`] — and essentially all of the cost is [`crate::sbox`].

use crate::gf256::xtime;
use crate::sbox::Sbox;
use ark_ff::PrimeField;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;

/// AES block size, in bytes.
pub const BLOCK_SIZE: usize = 16;
/// AES-128 key size, in bytes.
pub const KEY_SIZE: usize = 16;
/// AES-128 runs ten rounds, against eleven round keys.
pub const ROUNDS: usize = 10;

/// The round constants of the AES-128 key schedule, `x^(i-1)` in GF(2^8).
const ROUND_CONSTANTS: [u8; ROUNDS] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// Where each byte of the state comes from after `ShiftRows`.
///
/// The state is held column-major, so rotating row `r` left by `r` is this fixed
/// permutation. It rewires existing variables and costs nothing.
const SHIFT_ROWS: [usize; BLOCK_SIZE] = [
    0, 5, 10, 15, //
    4, 9, 14, 3, //
    8, 13, 2, 7, //
    12, 1, 6, 11,
];

/// Encrypts `message` under `secret_key` in ECB mode.
///
/// `message` must be a whole number of 16-byte blocks. ECB encrypts each block
/// independently under the same key schedule, which is why identical plaintext
/// blocks produce identical ciphertext blocks.
pub fn encrypt<F: PrimeField>(
    message: &[UInt8<F>],
    secret_key: &[UInt8<F>],
    sbox: &Sbox<F>,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let round_keys = key_schedule(secret_key, sbox)?;

    let mut ciphertext = Vec::with_capacity(message.len());
    for block in message.chunks(BLOCK_SIZE) {
        ciphertext.extend(encrypt_block(block, &round_keys, sbox)?);
    }

    Ok(ciphertext)
}

/// Encrypts a single 16-byte block, given the eleven round keys.
pub fn encrypt_block<F: PrimeField>(
    block: &[UInt8<F>],
    round_keys: &[Vec<UInt8<F>>],
    sbox: &Sbox<F>,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let mut state = add_round_key(block, round_key(round_keys, 0)?)?;

    for round in 1..ROUNDS {
        state = sbox.substitute_bytes(&state)?;
        state = shift_rows(&state);
        state = mix_columns(&state)?;
        state = add_round_key(&state, round_key(round_keys, round)?)?;
    }

    // The last round skips MixColumns: it would be undone by the inverse cipher
    // anyway, and leaving it out saves constraints.
    state = sbox.substitute_bytes(&state)?;
    state = shift_rows(&state);
    add_round_key(&state, round_key(round_keys, ROUNDS)?)
}

/// Expands the 16-byte key into the eleven 16-byte round keys.
///
/// This is where 40 of the 200 S-box applications live: one per word, on every
/// fourth word of the expansion.
pub fn key_schedule<F: PrimeField>(
    secret_key: &[UInt8<F>],
    sbox: &Sbox<F>,
) -> Result<Vec<Vec<UInt8<F>>>, SynthesisError> {
    if secret_key.len() != KEY_SIZE {
        return Err(SynthesisError::Unsatisfiable);
    }

    // The expansion works on 4-byte words: 4 from the key, 40 derived.
    let mut words: Vec<Vec<UInt8<F>>> = secret_key.chunks(4).map(<[_]>::to_vec).collect();

    for i in 4..(4 * (ROUNDS + 1)) {
        let previous = words.get(i - 1).ok_or(SynthesisError::Unsatisfiable)?.clone();

        let transformed = if i % 4 == 0 {
            // RotWord, then SubWord, then XOR in the round constant.
            let mut rotated = previous;
            rotated.rotate_left(1);
            let mut substituted = sbox.substitute_bytes(&rotated)?;

            let constant = ROUND_CONSTANTS
                .get(i / 4 - 1)
                .ok_or(SynthesisError::Unsatisfiable)?;
            let first = substituted.first().ok_or(SynthesisError::Unsatisfiable)?;
            let with_constant = first ^ &UInt8::constant(*constant);
            *substituted
                .first_mut()
                .ok_or(SynthesisError::Unsatisfiable)? = with_constant;

            substituted
        } else {
            previous
        };

        let four_back = words.get(i - 4).ok_or(SynthesisError::Unsatisfiable)?;
        let word = four_back
            .iter()
            .zip(&transformed)
            .map(|(a, b)| a ^ b)
            .collect();

        words.push(word);
    }

    Ok(words.chunks(4).map(|key| key.concat()).collect())
}

/// XORs the state with a round key.
pub fn add_round_key<F: PrimeField>(
    state: &[UInt8<F>],
    round_key: &[UInt8<F>],
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    if state.len() != BLOCK_SIZE || round_key.len() != BLOCK_SIZE {
        return Err(SynthesisError::Unsatisfiable);
    }

    Ok(state.iter().zip(round_key).map(|(s, k)| s ^ k).collect())
}

/// Rotates the rows of the state matrix. Free: it only moves variables around.
pub fn shift_rows<F: PrimeField>(state: &[UInt8<F>]) -> Vec<UInt8<F>> {
    SHIFT_ROWS
        .iter()
        .filter_map(|&i| state.get(i).cloned())
        .collect()
}

/// Multiplies each column of the state by the fixed MixColumns matrix.
///
/// Every entry of that matrix is 1, 2 or 3, so each output byte is a handful of
/// XORs over the column and its [`xtime`] doublings.
pub fn mix_columns<F: PrimeField>(state: &[UInt8<F>]) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let mut mixed = Vec::with_capacity(state.len());

    for column in state.chunks(4) {
        let a: Vec<&UInt8<F>> = column.iter().collect();
        let b: Vec<UInt8<F>> = column.iter().map(xtime).collect::<Result<_, _>>()?;

        let get = |v: &[UInt8<F>], i: usize| -> Result<UInt8<F>, SynthesisError> {
            v.get(i).cloned().ok_or(SynthesisError::Unsatisfiable)
        };
        let at = |v: &[&UInt8<F>], i: usize| -> Result<UInt8<F>, SynthesisError> {
            v.get(i).map(|x| (*x).clone()).ok_or(SynthesisError::Unsatisfiable)
        };

        // out_i = 2*a_i XOR 3*a_(i+1) XOR a_(i+2) XOR a_(i+3), with 3*x = 2*x XOR x.
        mixed.push(&(&(&get(&b, 0)? ^ &at(&a, 3)?) ^ &at(&a, 2)?) ^ &(&get(&b, 1)? ^ &at(&a, 1)?));
        mixed.push(&(&(&get(&b, 1)? ^ &at(&a, 0)?) ^ &at(&a, 3)?) ^ &(&get(&b, 2)? ^ &at(&a, 2)?));
        mixed.push(&(&(&get(&b, 2)? ^ &at(&a, 1)?) ^ &at(&a, 0)?) ^ &(&get(&b, 3)? ^ &at(&a, 3)?));
        mixed.push(&(&(&get(&b, 3)? ^ &at(&a, 2)?) ^ &at(&a, 1)?) ^ &(&get(&b, 0)? ^ &at(&a, 0)?));
    }

    Ok(mixed)
}

fn round_key<F: PrimeField>(
    round_keys: &[Vec<UInt8<F>>],
    round: usize,
) -> Result<&[UInt8<F>], SynthesisError> {
    round_keys
        .get(round)
        .map(Vec::as_slice)
        .ok_or(SynthesisError::Unsatisfiable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbox::SboxKind;
    use ark_bls12_377::Fr;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    // All vectors below are from FIPS-197, Appendix B.
    const PLAINTEXT: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];
    const KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    fn witness(cs: &ConstraintSystemRef<Fr>, bytes: &[u8]) -> Vec<UInt8<Fr>> {
        bytes
            .iter()
            .map(|b| UInt8::<Fr>::new_witness(cs.clone(), || Ok(b)).unwrap())
            .collect()
    }

    #[test]
    fn add_round_key_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let state = witness(&cs, &PLAINTEXT);
        let key = witness(&cs, &KEY);

        let result = add_round_key(&state, &key).unwrap();

        assert_eq!(
            result.value().unwrap(),
            [
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ]
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn sub_bytes_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let sbox = Sbox::new(SboxKind::default(), cs.clone());
        let state = witness(
            &cs,
            &[
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ],
        );

        let result = sbox.substitute_bytes(&state).unwrap();

        assert_eq!(
            result.value().unwrap(),
            [
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
                0x52, 0x30,
            ]
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn shift_rows_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let state = witness(
            &cs,
            &[
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
                0x52, 0x30,
            ],
        );

        let result = shift_rows(&state);

        assert_eq!(
            result.value().unwrap(),
            [
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5,
            ]
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn mix_columns_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let state = witness(
            &cs,
            &[
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5,
            ],
        );

        let result = mix_columns(&state).unwrap();

        assert_eq!(
            result.value().unwrap(),
            [
                0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
                0x26, 0x4c,
            ]
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn key_schedule_matches_fips_197() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let sbox = Sbox::new(SboxKind::default(), cs.clone());
        let key = witness(&cs, &KEY);

        let round_keys = key_schedule(&key, &sbox).unwrap();

        assert_eq!(round_keys.len(), ROUNDS + 1);
        assert_eq!(round_keys.first().unwrap().value().unwrap(), KEY);
        assert_eq!(
            round_keys.get(10).unwrap().value().unwrap(),
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
                0x0c, 0xa6,
            ]
        );
        assert!(cs.is_satisfied().unwrap());
    }

    /// The full cipher, against the FIPS-197 Appendix B vector.
    #[test]
    fn encrypts_the_fips_197_block() {
        for kind in [SboxKind::Bitsliced, SboxKind::Lookup] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let sbox = Sbox::new(kind, cs.clone());
            let message = witness(&cs, &PLAINTEXT);
            let key = witness(&cs, &KEY);

            let ciphertext = encrypt(&message, &key, &sbox).unwrap();

            assert_eq!(
                ciphertext.value().unwrap(),
                [
                    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19,
                    0x6a, 0x0b, 0x32,
                ],
                "{kind:?}"
            );
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
