use const_secret::{drop_strategy::NoOp, rc4::Rc4, ByteArray, Encrypted};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

// RC4 keys of different realistic sizes
const KEY_5: [u8; 5] = *b"mykey";
const KEY_16: [u8; 16] = *b"sixteen-byte-key";
const KEY_32: [u8; 32] = *b"thirty-two-byte-key-1234567890ab";

// RC4 with 5-byte key
fn rc4_key5_first_decrypt_size_7(c: &mut Criterion) {
    c.bench_function("rc4_key5_first_decrypt_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<5, NoOp<[u8; 5]>>, ByteArray, 7> =
                Encrypted::<Rc4<5, NoOp<[u8; 5]>>, ByteArray, 7>::new([0u8; 7], KEY_5);
            black_box(&*e);
        });
    });
}

fn rc4_key5_first_decrypt_size_23(c: &mut Criterion) {
    c.bench_function("rc4_key5_first_decrypt_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<5, NoOp<[u8; 5]>>, ByteArray, 23> =
                Encrypted::<Rc4<5, NoOp<[u8; 5]>>, ByteArray, 23>::new([0u8; 23], KEY_5);
            black_box(&*e);
        });
    });
}

fn rc4_key5_first_decrypt_size_89(c: &mut Criterion) {
    c.bench_function("rc4_key5_first_decrypt_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<5, NoOp<[u8; 5]>>, ByteArray, 89> =
                Encrypted::<Rc4<5, NoOp<[u8; 5]>>, ByteArray, 89>::new([0u8; 89], KEY_5);
            black_box(&*e);
        });
    });
}

// RC4 with 16-byte key
fn rc4_key16_first_decrypt_size_7(c: &mut Criterion) {
    c.bench_function("rc4_key16_first_decrypt_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 7> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 7>::new([0u8; 7], KEY_16);
            black_box(&*e);
        });
    });
}

fn rc4_key16_first_decrypt_size_23(c: &mut Criterion) {
    c.bench_function("rc4_key16_first_decrypt_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);
            black_box(&*e);
        });
    });
}

fn rc4_key16_first_decrypt_size_89(c: &mut Criterion) {
    c.bench_function("rc4_key16_first_decrypt_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>::new([0u8; 89], KEY_16);
            black_box(&*e);
        });
    });
}

// RC4 with 32-byte key
fn rc4_key32_first_decrypt_size_7(c: &mut Criterion) {
    c.bench_function("rc4_key32_first_decrypt_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<32, NoOp<[u8; 32]>>, ByteArray, 7> =
                Encrypted::<Rc4<32, NoOp<[u8; 32]>>, ByteArray, 7>::new([0u8; 7], KEY_32);
            black_box(&*e);
        });
    });
}

fn rc4_key32_first_decrypt_size_23(c: &mut Criterion) {
    c.bench_function("rc4_key32_first_decrypt_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<32, NoOp<[u8; 32]>>, ByteArray, 23> =
                Encrypted::<Rc4<32, NoOp<[u8; 32]>>, ByteArray, 23>::new([0u8; 23], KEY_32);
            black_box(&*e);
        });
    });
}

fn rc4_key32_first_decrypt_size_89(c: &mut Criterion) {
    c.bench_function("rc4_key32_first_decrypt_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<32, NoOp<[u8; 32]>>, ByteArray, 89> =
                Encrypted::<Rc4<32, NoOp<[u8; 32]>>, ByteArray, 89>::new([0u8; 89], KEY_32);
            black_box(&*e);
        });
    });
}

// Cached access benchmarks
fn rc4_cached_access_size_7(c: &mut Criterion) {
    c.bench_function("rc4_cached_access_size_7", |b| {
        let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 7> =
            Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 7>::new([0u8; 7], KEY_16);
        let _ = &*e; // Pre-warm
        b.iter(|| {
            black_box(&*e);
        });
    });
}

fn rc4_cached_access_size_23(c: &mut Criterion) {
    c.bench_function("rc4_cached_access_size_23", |b| {
        let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23> =
            Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);
        let _ = &*e;
        b.iter(|| {
            black_box(&*e);
        });
    });
}

fn rc4_cached_access_size_89(c: &mut Criterion) {
    c.bench_function("rc4_cached_access_size_89", |b| {
        let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89> =
            Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>::new([0u8; 89], KEY_16);
        let _ = &*e;
        b.iter(|| {
            black_box(&*e);
        });
    });
}

criterion_group!(
    benches,
    rc4_key5_first_decrypt_size_7,
    rc4_key5_first_decrypt_size_23,
    rc4_key5_first_decrypt_size_89,
    rc4_key16_first_decrypt_size_7,
    rc4_key16_first_decrypt_size_23,
    rc4_key16_first_decrypt_size_89,
    rc4_key32_first_decrypt_size_7,
    rc4_key32_first_decrypt_size_23,
    rc4_key32_first_decrypt_size_89,
    rc4_cached_access_size_7,
    rc4_cached_access_size_23,
    rc4_cached_access_size_89,
);
criterion_main!(benches);
