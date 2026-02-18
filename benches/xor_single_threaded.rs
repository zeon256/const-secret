use const_secret::{
    ByteArray, Encrypted,
    align::{Aligned8, Aligned16},
    drop_strategy::NoOp,
    xor::Xor,
};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

// XOR Single-threaded benchmarks with non-base2 sizes

fn xor_first_decrypt_size_7(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 7> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 7>::new([0u8; 7]);
            black_box(&*e);
        });
    });
}

fn xor_first_decrypt_size_13(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_13", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 13> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 13>::new([0u8; 13]);
            black_box(&*e);
        });
    });
}

fn xor_first_decrypt_size_17(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_17", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 17> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 17>::new([0u8; 17]);
            black_box(&*e);
        });
    });
}

fn xor_first_decrypt_size_23(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);
            black_box(&*e);
        });
    });
}

fn xor_first_decrypt_size_29(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_29", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 29> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 29>::new([0u8; 29]);
            black_box(&*e);
        });
    });
}

fn xor_first_decrypt_size_53(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_53", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 53> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 53>::new([0u8; 53]);
            black_box(&*e);
        });
    });
}

fn xor_first_decrypt_size_89(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 89> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]);
            black_box(&*e);
        });
    });
}

fn xor_first_decrypt_size_127(c: &mut Criterion) {
    c.bench_function("xor_first_decrypt_size_127", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 127> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 127>::new([0u8; 127]);
            black_box(&*e);
        });
    });
}

// Cached access benchmarks
fn xor_cached_access_size_7(c: &mut Criterion) {
    c.bench_function("xor_cached_access_size_7", |b| {
        let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 7> =
            Encrypted::<Xor<0xAA, NoOp>, ByteArray, 7>::new([0u8; 7]);
        let _ = &*e; // Pre-warm
        b.iter(|| {
            black_box(&*e);
        });
    });
}

fn xor_cached_access_size_23(c: &mut Criterion) {
    c.bench_function("xor_cached_access_size_23", |b| {
        let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
            Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);
        let _ = &*e;
        b.iter(|| {
            black_box(&*e);
        });
    });
}

fn xor_cached_access_size_89(c: &mut Criterion) {
    c.bench_function("xor_cached_access_size_89", |b| {
        let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 89> =
            Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]);
        let _ = &*e;
        b.iter(|| {
            black_box(&*e);
        });
    });
}

// Aligned8 benchmarks
fn xor_aligned8_first_size_7(c: &mut Criterion) {
    c.bench_function("xor_aligned8_first_size_7", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Xor<0xAA, NoOp>, ByteArray, 7>> =
                Aligned8(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 7>::new([0u8; 7]));
            black_box(&*e.0);
        });
    });
}

fn xor_aligned8_first_size_23(c: &mut Criterion) {
    c.bench_function("xor_aligned8_first_size_23", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Xor<0xAA, NoOp>, ByteArray, 23>> =
                Aligned8(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]));
            black_box(&*e.0);
        });
    });
}

fn xor_aligned8_first_size_89(c: &mut Criterion) {
    c.bench_function("xor_aligned8_first_size_89", |b| {
        b.iter(|| {
            let e: Aligned8<Encrypted<Xor<0xAA, NoOp>, ByteArray, 89>> =
                Aligned8(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]));
            black_box(&*e.0);
        });
    });
}

// Aligned16 benchmarks
fn xor_aligned16_first_size_7(c: &mut Criterion) {
    c.bench_function("xor_aligned16_first_size_7", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Xor<0xAA, NoOp>, ByteArray, 7>> =
                Aligned16(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 7>::new([0u8; 7]));
            black_box(&*e.0);
        });
    });
}

fn xor_aligned16_first_size_23(c: &mut Criterion) {
    c.bench_function("xor_aligned16_first_size_23", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Xor<0xAA, NoOp>, ByteArray, 23>> =
                Aligned16(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]));
            black_box(&*e.0);
        });
    });
}

fn xor_aligned16_first_size_89(c: &mut Criterion) {
    c.bench_function("xor_aligned16_first_size_89", |b| {
        b.iter(|| {
            let e: Aligned16<Encrypted<Xor<0xAA, NoOp>, ByteArray, 89>> =
                Aligned16(Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]));
            black_box(&*e.0);
        });
    });
}

criterion_group!(
    benches,
    xor_first_decrypt_size_7,
    xor_first_decrypt_size_13,
    xor_first_decrypt_size_17,
    xor_first_decrypt_size_23,
    xor_first_decrypt_size_29,
    xor_first_decrypt_size_53,
    xor_first_decrypt_size_89,
    xor_first_decrypt_size_127,
    xor_cached_access_size_7,
    xor_cached_access_size_23,
    xor_cached_access_size_89,
    xor_aligned8_first_size_7,
    xor_aligned8_first_size_23,
    xor_aligned8_first_size_89,
    xor_aligned16_first_size_7,
    xor_aligned16_first_size_23,
    xor_aligned16_first_size_89,
);
criterion_main!(benches);
