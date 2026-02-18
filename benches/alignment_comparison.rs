use const_secret::{
    align::{Aligned16, Aligned8},
    drop_strategy::NoOp,
    rc4::Rc4,
    xor::Xor,
    ByteArray, Encrypted,
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

const KEY_16: [u8; 16] = *b"benchmark-key-16";

// XOR Alignment comparison for size 23
fn xor_alignment_size_23(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_alignment_size_23");

    group.bench_function("unaligned", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);
            black_box(&*e);
        });
    });

    group.bench_function("aligned8", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Xor<0xAA, NoOp>, ByteArray, 23>> =
                Aligned8(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]));
            black_box(&*e.0);
        });
    });

    group.bench_function("aligned16", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Xor<0xAA, NoOp>, ByteArray, 23>> =
                Aligned16(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]));
            black_box(&*e.0);
        });
    });

    group.finish();
}

// XOR Alignment comparison for size 53
fn xor_alignment_size_53(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_alignment_size_53");

    group.bench_function("unaligned", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 53> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 53>::new([0u8; 53]);
            black_box(&*e);
        });
    });

    group.bench_function("aligned8", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Xor<0xAA, NoOp>, ByteArray, 53>> =
                Aligned8(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 53>::new([0u8; 53]));
            black_box(&*e.0);
        });
    });

    group.bench_function("aligned16", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Xor<0xAA, NoOp>, ByteArray, 53>> =
                Aligned16(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 53>::new([0u8; 53]));
            black_box(&*e.0);
        });
    });

    group.finish();
}

// XOR Alignment comparison for size 89
fn xor_alignment_size_89(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_alignment_size_89");

    group.bench_function("unaligned", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 89> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]);
            black_box(&*e);
        });
    });

    group.bench_function("aligned8", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Xor<0xAA, NoOp>, ByteArray, 89>> =
                Aligned8(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]));
            black_box(&*e.0);
        });
    });

    group.bench_function("aligned16", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Xor<0xAA, NoOp>, ByteArray, 89>> =
                Aligned16(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]));
            black_box(&*e.0);
        });
    });

    group.finish();
}

// RC4 Alignment comparison for size 23
fn rc4_alignment_size_23(c: &mut Criterion) {
    let mut group = c.benchmark_group("rc4_alignment_size_23");

    group.bench_function("unaligned", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);
            black_box(&*e);
        });
    });

    group.bench_function("aligned8", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>> = Aligned8(
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16),
            );
            black_box(&*e.0);
        });
    });

    group.bench_function("aligned16", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>> = Aligned16(
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16),
            );
            black_box(&*e.0);
        });
    });

    group.finish();
}

// RC4 Alignment comparison for size 53
fn rc4_alignment_size_53(c: &mut Criterion) {
    let mut group = c.benchmark_group("rc4_alignment_size_53");

    group.bench_function("unaligned", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 53> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 53>::new([0u8; 53], KEY_16);
            black_box(&*e);
        });
    });

    group.bench_function("aligned8", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 53>> = Aligned8(
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 53>::new([0u8; 53], KEY_16),
            );
            black_box(&*e.0);
        });
    });

    group.bench_function("aligned16", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 53>> = Aligned16(
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 53>::new([0u8; 53], KEY_16),
            );
            black_box(&*e.0);
        });
    });

    group.finish();
}

// RC4 Alignment comparison for size 89
fn rc4_alignment_size_89(c: &mut Criterion) {
    let mut group = c.benchmark_group("rc4_alignment_size_89");

    group.bench_function("unaligned", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>::new([0u8; 89], KEY_16);
            black_box(&*e);
        });
    });

    group.bench_function("aligned8", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>> = Aligned8(
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>::new([0u8; 89], KEY_16),
            );
            black_box(&*e.0);
        });
    });

    group.bench_function("aligned16", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>> = Aligned16(
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>::new([0u8; 89], KEY_16),
            );
            black_box(&*e.0);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    xor_alignment_size_23,
    xor_alignment_size_53,
    xor_alignment_size_89,
    rc4_alignment_size_23,
    rc4_alignment_size_53,
    rc4_alignment_size_89,
);
criterion_main!(benches);
