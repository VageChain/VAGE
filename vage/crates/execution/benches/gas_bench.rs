use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use primitive_types::U256;
use vage_execution::gas::calculate_intrinsic_gas;
use vage_execution::GasMeter;
use vage_types::{Address, Transaction};

fn make_tx() -> Transaction {
    Transaction::new_transfer(
        Address([9u8; 32]),
        Address([8u8; 32]),
        U256::from(10u64),
        7,
    )
}

fn bench_intrinsic_gas(c: &mut Criterion) {
    let mut group = c.benchmark_group("intrinsic_gas");
    let sizes = [0usize, 64, 256, 1024, 4096, 16384];

    for size in sizes {
        let data = vec![0x11; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| {
                black_box(calculate_intrinsic_gas(black_box(d)));
            });
        });
    }

    group.finish();
}

fn bench_gas_meter_ops(c: &mut Criterion) {
    let tx = make_tx();

    c.bench_function("gas_meter_consume_refund_cycle", |b| {
        b.iter(|| {
            let mut meter = GasMeter::new(100_000);
            for _ in 0..100 {
                meter.consume(black_box(100)).expect("consume should fit limit");
            }
            meter.refund(black_box(5_000));
            black_box(meter.calculate_fee(&tx));
        });
    });
}

criterion_group!(execution_benches, bench_intrinsic_gas, bench_gas_meter_ops);
criterion_main!(execution_benches);
