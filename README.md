# AES Encryption circuit

A zero-knowledge proof that a given ciphertext is the correct `AES-128` ECB encryption of a message under a secret key. The message and the key stay private; only the ciphertext is public.

Built on **Arkworks 0.5**. No `simpleworks`, and no `ark-marlin` — whose last release, 0.3.0, pins the whole dependency tree to a 2021 version of `ark-ff`.

## The layers

Each layer is one module and depends only on the ones above it, so any of them can be read, tested or replaced on its own. Reading top to bottom is the intended order:

| Layer | Module | What it does |
| ----- | ------ | ------------ |
| Specification | `src/reference.rs` | AES outside the circuit: what "correct" means |
| Field arithmetic | `src/gf256.rs` | GF(2⁸), the field AES is defined over |
| Non-linear step | `src/sbox.rs` | the S-box, two ways; ~75% of the circuit's cost |
| Arithmetization | `src/aes_gadget.rs` | AES-128 ECB as constraints, one function per FIPS-197 step |
| Relation | `src/circuit.rs` | what is proved: private message and key, public ciphertext |
| Proving system | `src/backend/` | Groth16 or Spartan, behind one `Backend` trait |

Two notions of "field" meet in the middle of that table. AES is defined over GF(2⁸), with 256 elements; the proof system works over `Fr`, a prime field of about 2²⁵³ elements. The circuit does not embed one in the other — it represents each AES byte as eight `Fr` elements constrained to be 0 or 1, and rebuilds GF(2⁸) arithmetic out of XOR and AND on those bits. That is exactly why the S-box is expensive.

To add a proving system, implement `Backend` (three methods: `setup`, `prove`, `verify`). Backends see only R1CS; they know nothing about AES.

### On PIOPs and polynomial commitments

SNARKs are usually presented as a *PIOP* (an information-theoretic protocol over polynomials) compiled with a *polynomial commitment scheme*. That split is real, but it is not where these two backends draw their boundaries:

- **Groth16** does not decompose this way at all. It compiles the R1CS to a QAP and checks one pairing equation against a structured reference string. The trusted setup is the price of a three-element proof.
- **Spartan** does: a sum-check protocol over the multilinear extensions of `A`, `B`, `C`, compiled with a multilinear polynomial commitment. That is what makes it transparent. `ark-spartan` ships the two fused behind one type, so the seam is in the papers, not the API.

Arkworks exposes the commitment layer on its own as `ark-poly-commit` (KZG, IPA, Ligero). Pairing it with a PIOP of your own is how you would get a stack where the two are genuinely interchangeable.

## Circuit Inputs

### Private

- `message`: The message to encrypt.
- `secret_key`: The secret key used for the AES encryption.

### Public
- `ciphertext`: The encrypted message. This is public as the entire point of the circuit is for a verifier to be assured that the ciphertext they were given is the correct one.

## Usage

`cargo run --release` proves one block with each backend and times every step; see `src/main.rs`.

```rust
use zk_aes::backend::{groth16::Groth16, Backend};
use zk_aes::circuit::AesEcbCircuit;

let ciphertext = zk_aes::reference::encrypt(&message, &secret_key);

// Once per circuit shape (here, one 16-byte block).
let (pk, vk) = Groth16::setup(AesEcbCircuit::setup(1), &mut rng)?;

// Prover: knows the message and the key.
let circuit = AesEcbCircuit::prover(&message, &secret_key, &ciphertext)?;
let proof = Groth16::prove(&pk, circuit, &mut rng)?;

// Verifier: sees only the verifying key, the ciphertext and the proof.
let public_inputs = AesEcbCircuit::public_inputs(&ciphertext);
assert!(Groth16::verify(&vk, &public_inputs, &proof)?);
```

Swap `Groth16` for `Spartan` and nothing else changes.

- **Circuit only, no proof**: `zk_aes::encrypt_circuit_only(&message, &secret_key)`
- **Constraint count**: `zk_aes::constraint_count(num_blocks, sbox_kind)`

Slow tests are `#[ignore]`d: run them with `cargo test --release -- --ignored`.

## Numbers

One 16-byte block, release build, bitsliced S-box: 30,728 constraints.

| | Setup | Prove | Verify |
| --- | --- | --- | --- |
| Groth16 | ~1 s | ~0.5–0.7 s | ~5 ms |
| Spartan | ~6 s | ~12 s | ~0.4 s |

Groth16 wins on every axis here; what Spartan buys is a setup with no secrets in it.

## The S-box is the circuit

`SubBytes` runs 200 times per block — 160 in the rounds, 40 in the key schedule — and everything else is nearly free: `ShiftRows` is a permutation of existing variables, `AddRoundKey` is XOR, `MixColumns` is XOR plus a doubling in GF(2⁸). So the S-box is not *a* cost, it is essentially the whole cost, and the construction you pick for it decides the size of the circuit.

| S-box | Per byte | One block |
| ----- | -------- | --------- |
| `SboxKind::Lookup` — 256 constants walked by a conditional-select tree | 884 | 184,928 |
| `SboxKind::Bitsliced` — Boyar-Peralta, 32 AND + 81 XOR gates | 113 | 30,728 |

Both are checked against the Rijndael table on all 256 inputs. The bitsliced circuit is the depth-16 construction from Boyar and Peralta, in the form used by the `aes` crate's fixsliced software backend: it computes the GF(2⁸) inverse through a tower of subfields instead of looking it up, and every gate is one R1CS constraint.

## AES Flow

`AES-128` consists of 11 rounds. The secret key is used to derive 11 round keys, one for each round.

Each AES round then takes a message as input and performs the following steps:
- `Add Round Key`
- `Sub Bytes`
- `Shift Rows`
- `Mix Columns`

The last round skips `Mix Columns`.

### Add RoundKey
An XOR of the input against the current round key.

### Sub Bytes
The [Rijndael S-Box](https://en.wikipedia.org/wiki/Rijndael_S-box): inversion in [Rijndael's finite field](https://cryptohack.gitbook.io/cryptobook/symmetric-cryptography/aes/rijndael-finite-field) followed by an affine map. See above for how it is arithmetized.

### Shift Rows
Writes the input as a byte matrix and rotates each row. Free in-circuit: it only renames variables.

### Mix Columns
Multiplies each column by a fixed matrix over Rijndael's field. Every entry is 1, 2 or 3, so it reduces to XORs and `gf256::xtime`.

### Key Derivation
The key schedule combines all of the above, and accounts for 40 of the 200 S-box applications.
