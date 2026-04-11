use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use primitive_types::U256;
use vage_types::{Address, Transaction};

fn make_transfer(nonce: u64) -> Transaction {
    Transaction::new_transfer(
        Address([1u8; 32]),
        Address([2u8; 32]),
        U256::from(1_000u64),
        nonce,
    )
}

fn make_contract_call(data_len: usize) -> Transaction {
    let data = vec![0xAB; data_len];
    Transaction::new_contract_call(
        Address([3u8; 32]),
        Address([4u8; 32]),
        U256::from(123u64),
        1,
        data,
    )
}

fn bench_tx_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_hash");
    let payload_sizes = [0usize, 64, 256, 1024, 4096];

    for size in payload_sizes {
        let tx = if size == 0 {
            make_transfer(1)
        } else {
            make_contract_call(size)
        };

        group.bench_with_input(BenchmarkId::from_parameter(size), &tx, |b, tx| {
            b.iter(|| {
                black_box(tx.hash());
            });
        });
    }

    group.finish();
}

fn bench_tx_serialization(c: &mut Criterion) {
    let tx = make_contract_call(2048);

    c.bench_function("transaction_rlp_encode_2kb", |b| {
        b.iter(|| {
            black_box(tx.rlp_encode());
        });
    });

    c.bench_function("transaction_size_bytes_2kb", |b| {
        b.iter(|| {
            black_box(tx.size_bytes());
        });
    });
}

criterion_group!(types_benches, bench_tx_hash, bench_tx_serialization);
criterion_main!(types_benches);
