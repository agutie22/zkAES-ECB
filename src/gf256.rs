//! Arithmetic in GF(2^8), Rijndael's field, on circuit bytes.
//!
//! AES only ever multiplies by the constants 1, 2 and 3, and all three reduce to
//! [`xtime`] plus XOR, so this is the whole of the field arithmetic the circuit
//! needs.

use ark_ff::PrimeField;
use ark_r1cs_std::{convert::ToBitsGadget, prelude::Boolean, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

/// Multiplies by 2 in GF(2^8): shift left by one, then reduce modulo the
/// Rijndael polynomial `x^8 + x^4 + x^3 + x + 1` (`0x1b`) if the top bit was set.
///
/// The reduction is free of multiplications: the conditional `0x1b` is just the
/// high bit placed in the positions where `0x1b` has a one, so the whole thing is
/// four XORs.
pub fn xtime<F: PrimeField>(byte: &UInt8<F>) -> Result<UInt8<F>, SynthesisError> {
    let bits: [Boolean<F>; 8] = byte
        .to_bits_le()?
        .try_into()
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    let [b0, b1, b2, b3, b4, b5, b6, high_bit] = bits;

    // Shift left by one, then XOR in 0x1b = 0b0001_1011 wherever the high bit
    // that fell off says to: bits 0, 1, 3 and 4.
    Ok(UInt8::from_bits_le(&[
        high_bit.clone(),
        &b0 ^ &high_bit,
        b1,
        &b2 ^ &high_bit,
        &b3 ^ &high_bit,
        b4,
        b5,
        b6,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    /// The same reduction, written the obvious way on a plain `u8`.
    fn native_xtime(byte: u8) -> u8 {
        if byte & 0x80 == 0 {
            byte << 1
        } else {
            (byte << 1) ^ 0x1b
        }
    }

    #[test]
    fn matches_native_xtime_on_every_byte() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        for byte in 0_u8..=255_u8 {
            let gadget = UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap();
            let doubled = xtime(&gadget).unwrap();

            assert_eq!(doubled.value().unwrap(), native_xtime(byte), "xtime({byte:#04x})");
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
