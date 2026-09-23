//! Arithmetic in GF(2^8), Rijndael's field, on circuit bytes.
//!
//! AES only ever multiplies by the constants 1, 2 and 3, and all three reduce to
//! [`xtime`] plus XOR, so this is the whole of the field arithmetic the circuit
//! needs.

use ark_ff::PrimeField;
use ark_r1cs_std::uint8::UInt8;

/// Multiplies by 2 in GF(2^8): shift left by one, then reduce modulo the
/// Rijndael polynomial `x^8 + x^4 + x^3 + x + 1` if the top bit fell off.
///
/// Reducing means XORing in `0x1b = 0b0001_1011`, i.e. flipping bits 0, 1, 3
/// and 4 when the high bit was set. So the whole operation is three XORs with
/// the high bit, plus some rewiring.
pub fn xtime<F: PrimeField>(byte: &UInt8<F>) -> UInt8<F> {
    let [b0, b1, b2, b3, b4, b5, b6, high] = byte.bits.clone();

    UInt8::from_bits_le(&[
        high.clone(),
        &b0 ^ &high,
        b1,
        &b2 ^ &high,
        &b3 ^ &high,
        b4,
        b5,
        b6,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn matches_native_xtime_on_every_byte() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        for byte in 0_u8..=255 {
            let expected = if byte & 0x80 == 0 {
                byte << 1
            } else {
                (byte << 1) ^ 0x1b
            };
            let gadget = UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap();

            assert_eq!(xtime(&gadget).value().unwrap(), expected, "{byte:#04x}");
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
