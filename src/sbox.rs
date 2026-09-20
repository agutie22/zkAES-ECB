//! The AES S-box, the one non-linear step of AES — and the dominant cost of the
//! whole circuit, since `SubBytes` runs 200 times per block (160 in the rounds,
//! 40 in the key schedule).
//!
//! Two implementations are available, and they are interchangeable: see
//! [`SboxKind`]. Everything else in the circuit is independent of this choice.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    convert::ToBitsGadget, prelude::Boolean, select::CondSelectGadget, uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// The Rijndael S-box, as a plain table.
pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Which S-box construction the circuit should use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SboxKind {
    /// The Boyar-Peralta circuit: 32 AND and 81 XOR gates, each one constraint.
    #[default]
    Bitsliced,
    /// A 256-entry table walked with a conditional-select tree. Costs roughly an
    /// order of magnitude more constraints; kept for comparison.
    Lookup,
}

/// An S-box ready to be applied to bytes.
///
/// [`SboxKind::Lookup`] needs the table allocated as circuit constants once, up
/// front, which is why this is a value and not a free function.
pub struct Sbox<F: PrimeField> {
    kind: SboxKind,
    table: Vec<UInt8<F>>,
}

impl<F: PrimeField> Sbox<F> {
    /// Prepares an S-box of the given kind.
    pub fn new(kind: SboxKind, cs: ConstraintSystemRef<F>) -> Self {
        let _ = cs;
        let table = match kind {
            SboxKind::Lookup => UInt8::constant_vec(&SBOX),
            SboxKind::Bitsliced => Vec::new(),
        };
        Self { kind, table }
    }

    /// Applies the S-box to one byte.
    pub fn substitute(&self, byte: &UInt8<F>) -> Result<UInt8<F>, SynthesisError> {
        match self.kind {
            SboxKind::Bitsliced => {
                let bits: [Boolean<F>; 8] = byte
                    .to_bits_le()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;
                Ok(UInt8::from_bits_le(&bitsliced(&bits)))
            },
            SboxKind::Lookup => UInt8::conditionally_select_power_of_two_vector(
                &byte.to_bits_be()?,
                &self.table,
            ),
        }
    }

    /// Applies the S-box to each byte of a state.
    pub fn substitute_bytes(&self, bytes: &[UInt8<F>]) -> Result<Vec<UInt8<F>>, SynthesisError> {
        bytes.iter().map(|byte| self.substitute(byte)).collect()
    }
}

/// The Boyar-Peralta depth-16 S-box circuit, evaluated on the eight bits of one
/// byte (`bits[i]` is bit `i`, least significant first).
///
/// This is the straight-line program from "A depth-16 circuit for the AES S-box"
/// (Boyar and Peralta), in the form used by the `aes` crate's fixsliced software
/// backend. It is pure AND/XOR: 32 ANDs and 81 XORs, one R1CS constraint each,
/// against roughly 900 for the equivalent table lookup.
///
/// The four output negations that the bitsliced formulation factors out into a
/// separate pass are applied here directly, since negating a `Boolean` is free.
fn bitsliced<F: PrimeField>(bits: &[Boolean<F>; 8]) -> [Boolean<F>; 8] {
    // The `u7..u0` naming comes from the published circuit, where `u7` is the
    // *first* bit-plane, i.e. the least significant bit of the byte.
    let [u7, u6, u5, u4, u3, u2, u1, u0] = bits.clone();

    let y14 = &u3 ^ &u5;
    let y13 = &u0 ^ &u6;
    let y12 = &y13 ^ &y14;
    let t1 = &u4 ^ &y12;
    let y15 = &t1 ^ &u5;
    let t2 = &y12 & &y15;
    let y6 = &y15 ^ &u7;
    let y20 = &t1 ^ &u1;
    let y9 = &u0 ^ &u3;
    let y11 = &y20 ^ &y9;
    let t12 = &y9 & &y11;
    let y7 = &u7 ^ &y11;
    let y8 = &u0 ^ &u5;
    let t0 = &u1 ^ &u2;
    let y10 = &y15 ^ &t0;
    let y17 = &y10 ^ &y11;
    let t13 = &y14 & &y17;
    let t14 = &t13 ^ &t12;
    let y19 = &y10 ^ &y8;
    let t15 = &y8 & &y10;
    let t16 = &t15 ^ &t12;
    let y16 = &t0 ^ &y11;
    let y21 = &y13 ^ &y16;
    let t7 = &y13 & &y16;
    let y18 = &u0 ^ &y16;
    let y1 = &t0 ^ &u7;
    let y4 = &y1 ^ &u3;
    let t5 = &y4 & &u7;
    let t6 = &t5 ^ &t2;
    let t18 = &t6 ^ &t16;
    let t22 = &t18 ^ &y19;
    let y2 = &y1 ^ &u0;
    let t10 = &y2 & &y7;
    let t11 = &t10 ^ &t7;
    let t20 = &t11 ^ &t16;
    let t24 = &t20 ^ &y18;
    let y5 = &y1 ^ &u6;
    let t8 = &y5 & &y1;
    let t9 = &t8 ^ &t7;
    let t19 = &t9 ^ &t14;
    let t23 = &t19 ^ &y21;
    let y3 = &y5 ^ &y8;
    let t3 = &y3 & &y6;
    let t4 = &t3 ^ &t2;
    let t17 = &t4 ^ &y20;
    let t21 = &t17 ^ &t14;
    let t26 = &t21 & &t23;
    let t27 = &t24 ^ &t26;
    let t31 = &t22 ^ &t26;
    let t25 = &t21 ^ &t22;
    let t28 = &t25 & &t27;
    let t29 = &t28 ^ &t22;
    let z14 = &t29 & &y2;
    let z5 = &t29 & &y7;
    let t30 = &t23 ^ &t24;
    let t32 = &t31 & &t30;
    let t33 = &t32 ^ &t24;
    let t35 = &t27 ^ &t33;
    let t36 = &t24 & &t35;
    let t38 = &t27 ^ &t36;
    let t39 = &t29 & &t38;
    let t40 = &t25 ^ &t39;
    let t43 = &t29 ^ &t40;
    let z3 = &t43 & &y16;
    let tc12 = &z3 ^ &z5;
    let z12 = &t43 & &y13;
    let z13 = &t40 & &y5;
    let z4 = &t40 & &y1;
    let tc6 = &z3 ^ &z4;
    let t34 = &t23 ^ &t33;
    let t37 = &t36 ^ &t34;
    let t41 = &t40 ^ &t37;
    let z8 = &t41 & &y10;
    let z17 = &t41 & &y8;
    let t44 = &t33 ^ &t37;
    let z0 = &t44 & &y15;
    let z9 = &t44 & &y12;
    let z10 = &t37 & &y3;
    let z1 = &t37 & &y6;
    let tc5 = &z1 ^ &z0;
    let tc11 = &tc6 ^ &tc5;
    let z11 = &t33 & &y4;
    let t42 = &t29 ^ &t33;
    let t45 = &t42 ^ &t41;
    let z7 = &t45 & &y17;
    let tc8 = &z7 ^ &tc6;
    let z16 = &t45 & &y14;
    let z6 = &t42 & &y11;
    let tc16 = &z6 ^ &tc8;
    let z15 = &t42 & &y9;
    let tc20 = &z15 ^ &tc16;
    let tc1 = &z15 ^ &z16;
    let tc2 = &z10 ^ &tc1;
    let tc21 = &tc2 ^ &z11;
    let tc3 = &z9 ^ &tc2;
    let s0 = &tc3 ^ &tc16;
    let s3 = &tc3 ^ &tc11;
    let s1 = &s3 ^ &tc16;
    let tc13 = &z13 ^ &tc1;
    let z2 = &t33 & &u7;
    let tc4 = &z0 ^ &z2;
    let tc7 = &z12 ^ &tc4;
    let tc9 = &z8 ^ &tc7;
    let tc10 = &tc8 ^ &tc9;
    let tc17 = &z14 ^ &tc10;
    let s5 = &tc21 ^ &tc17;
    let tc26 = &tc17 ^ &tc20;
    let s2 = &tc26 ^ &z17;
    let tc14 = &tc4 ^ &tc12;
    let tc18 = &tc13 ^ &tc14;
    let s6 = &tc10 ^ &tc18;
    let s7 = &z12 ^ &tc18;
    let s4 = &tc14 ^ &s3;

    // Same reversal on the way out, with the four complemented outputs applied.
    [!&s7, !&s6, s5, s4, s3, !&s2, !&s1, s0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    /// Both implementations must agree with the Rijndael table on every input.
    fn agrees_with_the_table(kind: SboxKind) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let sbox = Sbox::new(kind, cs.clone());

        for (input, expected) in SBOX.iter().enumerate() {
            let byte = u8::try_from(input).unwrap();
            let gadget = UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap();
            let substituted = sbox.substitute(&gadget).unwrap();

            assert_eq!(substituted.value().unwrap(), *expected, "S-box({byte:#04x})");
        }

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn bitsliced_agrees_with_the_table_on_every_byte() {
        agrees_with_the_table(SboxKind::Bitsliced);
    }

    #[test]
    fn lookup_agrees_with_the_table_on_every_byte() {
        agrees_with_the_table(SboxKind::Lookup);
    }

    /// Records the per-byte cost of each construction, and asserts the bitsliced
    /// one is the cheaper of the two by a wide margin.
    #[test]
    fn bitsliced_is_far_cheaper_than_the_lookup() {
        let cost = |kind| {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let sbox = Sbox::<Fr>::new(kind, cs.clone());
            let byte = UInt8::new_witness(cs.clone(), || Ok(0x53_u8)).unwrap();
            let before = cs.num_constraints();
            sbox.substitute(&byte).unwrap();
            cs.num_constraints() - before
        };

        let bitsliced = cost(SboxKind::Bitsliced);
        let lookup = cost(SboxKind::Lookup);
        println!("constraints per S-box: bitsliced={bitsliced}, lookup={lookup}");

        assert!(
            bitsliced * 4 < lookup,
            "expected the bitsliced S-box to be much cheaper, got {bitsliced} vs {lookup}"
        );
    }
}
