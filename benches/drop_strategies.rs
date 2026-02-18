use const_secret::{
    ByteArray, Encrypted,
    drop_strategy::{NoOp, Zeroize},
    rc4::Rc4,
    xor::Xor,
};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const KEY_16: [u8; 16] = *b"benchmark-key-16";

// XOR Drop strategy benchmarks
fn xor_drop_noop_size_7(c: &mut Criterion) {
    c.bench_function("xor_drop_noop_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 7> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 7>::new([0u8; 7]);
            let _ = &*e; // Force decryption
            black_box(e);
        });
    });
}

fn xor_drop_noop_size_23(c: &mut Criterion) {
    c.bench_function("xor_drop_noop_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn xor_drop_noop_size_89(c: &mut Criterion) {
    c.bench_function("xor_drop_noop_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, NoOp>, ByteArray, 89> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 89>::new([0u8; 89]);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn xor_drop_zeroize_size_7(c: &mut Criterion) {
    c.bench_function("xor_drop_zeroize_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, Zeroize>, ByteArray, 7> =
                Encrypted::<Xor<0xAA, Zeroize>, ByteArray, 7>::new([0u8; 7]);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn xor_drop_zeroize_size_23(c: &mut Criterion) {
    c.bench_function("xor_drop_zeroize_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, Zeroize>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, Zeroize>, ByteArray, 23>::new([0u8; 23]);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn xor_drop_zeroize_size_89(c: &mut Criterion) {
    c.bench_function("xor_drop_zeroize_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Xor<0xAA, Zeroize>, ByteArray, 89> =
                Encrypted::<Xor<0xAA, Zeroize>, ByteArray, 89>::new([0u8; 89]);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn xor_drop_reencrypt_size_7(c: &mut Criterion) {
    c.bench_function("xor_drop_reencrypt_size_7", |b| {
        b.iter(|| {
            use const_secret::xor::ReEncrypt;
            let e: Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 7> =
                Encrypted::<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 7>::new([0u8; 7]);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn xor_drop_reencrypt_size_23(c: &mut Criterion) {
    c.bench_function("xor_drop_reencrypt_size_23", |b| {
        b.iter(|| {
            use const_secret::xor::ReEncrypt;
            let e: Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 23>::new([0u8; 23]);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn xor_drop_reencrypt_size_89(c: &mut Criterion) {
    c.bench_function("xor_drop_reencrypt_size_89", |b| {
        b.iter(|| {
            use const_secret::xor::ReEncrypt;
            let e: Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 89> =
                Encrypted::<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 89>::new([0u8; 89]);
            let _ = &*e;
            black_box(e);
        });
    });
}

// RC4 Drop strategy benchmarks
fn rc4_drop_noop_size_7(c: &mut Criterion) {
    c.bench_function("rc4_drop_noop_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 7> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 7>::new([0u8; 7], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_noop_size_23(c: &mut Criterion) {
    c.bench_function("rc4_drop_noop_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_noop_size_89(c: &mut Criterion) {
    c.bench_function("rc4_drop_noop_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 89>::new([0u8; 89], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_zeroize_size_7(c: &mut Criterion) {
    c.bench_function("rc4_drop_zeroize_size_7", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 7> =
                Encrypted::<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 7>::new([0u8; 7], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_zeroize_size_23(c: &mut Criterion) {
    c.bench_function("rc4_drop_zeroize_size_23", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 23> =
                Encrypted::<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_zeroize_size_89(c: &mut Criterion) {
    c.bench_function("rc4_drop_zeroize_size_89", |b| {
        b.iter(|| {
            let e: Encrypted<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 89> =
                Encrypted::<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 89>::new([0u8; 89], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_reencrypt_size_7(c: &mut Criterion) {
    c.bench_function("rc4_drop_reencrypt_size_7", |b| {
        b.iter(|| {
            use const_secret::rc4::ReEncrypt;
            let e: Encrypted<Rc4<16, ReEncrypt<16>>, ByteArray, 7> =
                Encrypted::<Rc4<16, ReEncrypt<16>>, ByteArray, 7>::new([0u8; 7], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_reencrypt_size_23(c: &mut Criterion) {
    c.bench_function("rc4_drop_reencrypt_size_23", |b| {
        b.iter(|| {
            use const_secret::rc4::ReEncrypt;
            let e: Encrypted<Rc4<16, ReEncrypt<16>>, ByteArray, 23> =
                Encrypted::<Rc4<16, ReEncrypt<16>>, ByteArray, 23>::new([0u8; 23], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

fn rc4_drop_reencrypt_size_89(c: &mut Criterion) {
    c.bench_function("rc4_drop_reencrypt_size_89", |b| {
        b.iter(|| {
            use const_secret::rc4::ReEncrypt;
            let e: Encrypted<Rc4<16, ReEncrypt<16>>, ByteArray, 89> =
                Encrypted::<Rc4<16, ReEncrypt<16>>, ByteArray, 89>::new([0u8; 89], KEY_16);
            let _ = &*e;
            black_box(e);
        });
    });
}

criterion_group!(
    benches,
    xor_drop_noop_size_7,
    xor_drop_noop_size_23,
    xor_drop_noop_size_89,
    xor_drop_zeroize_size_7,
    xor_drop_zeroize_size_23,
    xor_drop_zeroize_size_89,
    xor_drop_reencrypt_size_7,
    xor_drop_reencrypt_size_23,
    xor_drop_reencrypt_size_89,
    rc4_drop_noop_size_7,
    rc4_drop_noop_size_23,
    rc4_drop_noop_size_89,
    rc4_drop_zeroize_size_7,
    rc4_drop_zeroize_size_23,
    rc4_drop_zeroize_size_89,
    rc4_drop_reencrypt_size_7,
    rc4_drop_reencrypt_size_23,
    rc4_drop_reencrypt_size_89,
);
criterion_main!(benches);
