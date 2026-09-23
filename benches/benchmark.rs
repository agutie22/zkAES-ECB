//! Groth16 proving time by message length. Setup runs outside the measured
//! loop, since it happens once per circuit shape.

use criterion::{criterion_group, criterion_main, Criterion};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use zk_aes::backend::{groth16::Groth16, Backend};
use zk_aes::circuit::AesEcbCircuit;

fn prove(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let key = [0_u8; 16];

    for num_blocks in [1, 2, 4] {
        let message = vec![1_u8; 16 * num_blocks];
        let ciphertext = zk_aes::reference::encrypt(&message, &key);
        let (pk, _) = Groth16::setup(AesEcbCircuit::setup(num_blocks), &mut rng).unwrap();

        c.bench_function(&format!("groth16_prove_{num_blocks}_blocks"), |b| {
            b.iter(|| {
                let circuit = AesEcbCircuit::prover(&message, &key, &ciphertext).unwrap();
                Groth16::prove(&pk, circuit, &mut rng).unwrap()
            })
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = prove
}
criterion_main!(benches);
