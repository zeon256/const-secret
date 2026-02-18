use const_secret::{drop_strategy::NoOp, rc4::Rc4, xor::Xor, ByteArray, Encrypted};
use criterion::{criterion_group, criterion_main, Criterion};
use std::{hint::black_box, sync::Arc, thread};

const KEY_16: [u8; 16] = *b"benchmark-key-16";

// XOR Concurrent benchmarks
fn xor_concurrent_cold_10_threads(c: &mut Criterion) {
    c.bench_function("xor_concurrent_cold_10", |b| {
        b.iter(|| {
            const DATA: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);

            let shared = Arc::new(DATA);
            let mut handles = vec![];

            for _ in 0..10 {
                let clone = Arc::clone(&shared);
                handles.push(thread::spawn(move || {
                    black_box(&*clone);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

fn xor_concurrent_cold_20_threads(c: &mut Criterion) {
    c.bench_function("xor_concurrent_cold_20", |b| {
        b.iter(|| {
            const DATA: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);

            let shared = Arc::new(DATA);
            let mut handles = vec![];

            for _ in 0..20 {
                let clone = Arc::clone(&shared);
                handles.push(thread::spawn(move || {
                    black_box(&*clone);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

fn xor_concurrent_cold_50_threads(c: &mut Criterion) {
    c.bench_function("xor_concurrent_cold_50", |b| {
        b.iter(|| {
            const DATA: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);

            let shared = Arc::new(DATA);
            let mut handles = vec![];

            for _ in 0..50 {
                let clone = Arc::clone(&shared);
                handles.push(thread::spawn(move || {
                    black_box(&*clone);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

fn xor_concurrent_hot_10_threads(c: &mut Criterion) {
    c.bench_function("xor_concurrent_hot_10", |b| {
        b.iter(|| {
            const DATA: Encrypted<Xor<0xAA, NoOp>, ByteArray, 23> =
                Encrypted::<Xor<0xAA, NoOp>, ByteArray, 23>::new([0u8; 23]);

            let shared = Arc::new(DATA);
            let _ = &*shared; // Pre-warm

            let mut handles = vec![];
            for _ in 0..10 {
                let clone = Arc::clone(&shared);
                handles.push(thread::spawn(move || {
                    black_box(&*clone);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

// RC4 Concurrent benchmarks
fn rc4_concurrent_cold_10_threads(c: &mut Criterion) {
    c.bench_function("rc4_concurrent_cold_10", |b| {
        b.iter(|| {
            const DATA: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);

            let shared = Arc::new(DATA);
            let mut handles = vec![];

            for _ in 0..10 {
                let clone = Arc::clone(&shared);
                handles.push(thread::spawn(move || {
                    black_box(&*clone);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

fn rc4_concurrent_cold_20_threads(c: &mut Criterion) {
    c.bench_function("rc4_concurrent_cold_20", |b| {
        b.iter(|| {
            const DATA: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);

            let shared = Arc::new(DATA);
            let mut handles = vec![];

            for _ in 0..20 {
                let clone = Arc::clone(&shared);
                handles.push(thread::spawn(move || {
                    black_box(&*clone);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

fn rc4_concurrent_hot_10_threads(c: &mut Criterion) {
    c.bench_function("rc4_concurrent_hot_10", |b| {
        b.iter(|| {
            const DATA: Encrypted<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23> =
                Encrypted::<Rc4<16, NoOp<[u8; 16]>>, ByteArray, 23>::new([0u8; 23], KEY_16);

            let shared = Arc::new(DATA);
            let _ = &*shared; // Pre-warm

            let mut handles = vec![];
            for _ in 0..10 {
                let clone = Arc::clone(&shared);
                handles.push(thread::spawn(move || {
                    black_box(&*clone);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

criterion_group!(
    benches,
    xor_concurrent_cold_10_threads,
    xor_concurrent_cold_20_threads,
    xor_concurrent_cold_50_threads,
    xor_concurrent_hot_10_threads,
    rc4_concurrent_cold_10_threads,
    rc4_concurrent_cold_20_threads,
    rc4_concurrent_hot_10_threads,
);
criterion_main!(benches);
