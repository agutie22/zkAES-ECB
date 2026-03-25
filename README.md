# AES Encryption circuit

ZK-Snark circuit to prove that a given ciphertext is the correct `AES-128` encryption using a certain secret key.

This iteration uses ECB as the mode of operation. The circuit is implemented with **Arkworks 0.5** (`ark-relations` / `ark-r1cs-std`). For a **transparent** proof system, the repo includes a bridge from Arkworks’ extracted R1CS matrices to **Spartan** via the **`ark-spartan`** crate (git dependency), see `src/spartan.rs` and `cargo run` in `src/main.rs`.

## Circuit Inputs

### Private

- `message`: The message to encrypt. 
- `secret_key`: The secret key used for the AES encryption.

### Public
- `ciphertext`: The encrypted message. This is public as the entire point of the circuit is for a verifier to be assured that the ciphertext they were given is the correct one.

## Usage
You can find an example usage under `src/main.rs`.

- **Circuit-only encryption (witness synthesis + constraints)**: `zk_aes::encrypt_circuit_only(&message, &secret_key)`
- **Spartan prove + verify (transparent SNARK)**: `zk_aes::spartan::prove_and_verify(&message, &secret_key, &primitive_ciphertext)`

`primitive_ciphertext` should be the output of a standard AES implementation (the example computes it with the `aes` crate).

## AES Flow

`AES-128` consists of 11 rounds. The secret key is used to derive 11 round keys, one for each round. 

Each AES round then takes a message as input and performs the following steps:
- `Add Round Key`
- `Sub Bytes`
- `Shift Rows`
- `Mix Columns`

## Building Blocks Required
Given the above, the building blocks required at the circuit level are the following:

| Building Blocks | Required Primitives |
| --------------- | ------------------- |
| AddRoundKey     | `xor`               |
| SubBytes        | conditional select  |
| ShiftRows       | Row shifting        |
| MixColumns      | `addmany`           |
| KeyDerivation   | All of the above    |

### Add RoundKey
This is just an xor of the input against the current round key.

### Sub Bytes
This is the so called [Rijndael S-Box](https://en.wikipedia.org/wiki/Rijndael_S-box), a lookup table that has a pretty complicated calculation involving [Rijndael's finite field](https://cryptohack.gitbook.io/cryptobook/symmetric-cryptography/aes/rijndael-finite-field). 

Inside the circuit, we implement it by instantiating the precomputed table as 256 constants and then using a conditional select operation to do the lookup.

###  Shift Rows
This step simply writes the input as a byte matrix and then rotates each row.

### Mix Columns
`Mix Columns` is essentially multiplying the input by a matrix, only the multiplication is once again performed in [Rijndael's finite field](https://cryptohack.gitbook.io/cryptobook/symmetric-cryptography/aes/rijndael-finite-field).

### Key Derivation
The key derivation is the most complex step, but it's ultimately just a combination of all the basic operations used in the four steps for every round.
