//! Benchmarks for cryptographic hot paths in Continuum

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use continuum::{ContinuitySeal, HandoffPacket, Kernel, KeyPair};
use continuum::kernel::RiskAppetite;
use continuum::seal::compute_sha256;

fn create_test_kernel() -> Kernel {
    let mut kernel = Kernel::new("benchmark-kernel");
    kernel.risk_appetite = RiskAppetite::Conservative;
    kernel.spend_ceiling_usd = 100.0;
    kernel.confidence_threshold = 0.9;
    kernel
}

fn bench_sha256_hash(c: &mut Criterion) {
    let data = b"The quick brown fox jumps over the lazy dog";
    
    c.bench_function("sha256_64_bytes", |b| {
        b.iter(|| compute_sha256(black_box(data)))
    });
    
    let large_data = vec![0u8; 4096];
    c.bench_function("sha256_4kb", |b| {
        b.iter(|| compute_sha256(black_box(&large_data)))
    });
}

fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("keypair_generate", |b| {
        b.iter(KeyPair::generate)
    });
}

fn bench_seal_create(c: &mut Criterion) {
    let kernel = create_test_kernel();
    let keypair = KeyPair::generate();
    
    c.bench_function("seal_create", |b| {
        b.iter(|| ContinuitySeal::create(black_box(&kernel), black_box(&keypair)).unwrap())
    });
}

fn bench_seal_verify(c: &mut Criterion) {
    let kernel = create_test_kernel();
    let keypair = KeyPair::generate();
    let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
    
    c.bench_function("seal_verify", |b| {
        b.iter(|| seal.verify(black_box(&kernel)).unwrap())
    });
}

fn bench_kernel_canonical_json(c: &mut Criterion) {
    let kernel = create_test_kernel();
    
    c.bench_function("kernel_canonical_json", |b| {
        b.iter(|| black_box(&kernel).to_canonical_json().unwrap())
    });
}

fn bench_handoff_packet_roundtrip(c: &mut Criterion) {
    let kernel = create_test_kernel();
    let keypair = KeyPair::generate();
    let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
    let packet = HandoffPacket::new(kernel, seal);
    let json = packet.to_json().unwrap();
    
    c.bench_function("handoff_packet_to_json", |b| {
        b.iter(|| black_box(&packet).to_json().unwrap())
    });
    
    c.bench_function("handoff_packet_from_json", |b| {
        b.iter(|| HandoffPacket::from_json(black_box(&json)).unwrap())
    });
    
    c.bench_function("handoff_packet_verify", |b| {
        b.iter(|| black_box(&packet).verify().unwrap())
    });
}

criterion_group!(
    benches,
    bench_sha256_hash,
    bench_keypair_generation,
    bench_seal_create,
    bench_seal_verify,
    bench_kernel_canonical_json,
    bench_handoff_packet_roundtrip,
);

criterion_main!(benches);
