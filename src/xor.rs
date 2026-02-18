//! XOR encryption algorithm implementation.
//!
//! This module provides a simple XOR-based encryption algorithm. While not
//! cryptographically secure, it is fast and suitable for basic obfuscation
//! of secrets in compiled binaries.
//!
//! # Algorithm
//!
//! The [`Xor`] algorithm uses a single-byte key that is XOR'd with each
//! byte of the plaintext. The same operation is used for both encryption
//! and decryption (XOR is its own inverse).
//!
//! # Types
//!
//! - [`Xor<KEY, D>`]: The main algorithm type with const generic key and drop strategy
//! - [`ReEncrypt<KEY>`]: A drop strategy that re-encrypts data on drop
//!
//! # Example
//!
//! ```rust
//! use const_secret::{
//!     Encrypted, StringLiteral,
//!     drop_strategy::Zeroize,
//!     xor::{ReEncrypt, Xor},
//! };
//!
//! // Zeroize on drop (default)
//! const SECRET: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
//!     Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");
//!
//! // Re-encrypt on drop
//! const SECRET2: Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 6> =
//!     Encrypted::<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 6>::new(*b"secret");
//!
//! fn main() {
//!     let s1: &str = &*SECRET;
//!     assert_eq!(s1, "hello");
//!     
//!     let s2: &str = &*SECRET2;
//!     assert_eq!(s2, "secret");
//! }
//! ```

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::Deref,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::{
    Algorithm, ByteArray, Encrypted, STATE_DECRYPTED, STATE_DECRYPTING, STATE_UNENCRYPTED,
    StringLiteral,
    drop_strategy::{DropStrategy, Zeroize},
};

pub struct ReEncrypt<const KEY: u8>;

impl<const KEY: u8> DropStrategy for ReEncrypt<KEY> {
    type Extra = ();
    fn drop(data: &mut [u8], _extra: &()) {
        for byte in data {
            *byte ^= KEY;
        }
    }
}

/// An algorithm that performs XOR encryption and decryption.
/// This algorithm is generic over drop strategy.
pub struct Xor<const KEY: u8, D: DropStrategy = Zeroize>(PhantomData<D>);

impl<const KEY: u8, D: DropStrategy<Extra = ()>> Algorithm for Xor<KEY, D> {
    type Drop = D;
    type Extra = ();
}

impl<const KEY: u8, D: DropStrategy<Extra = ()>, M, const N: usize> Encrypted<Xor<KEY, D>, M, N> {
    pub const fn new(mut buffer: [u8; N]) -> Self {
        // We use a while loop because const contexts do not allow for-loops.
        let mut i = 0;
        while i < N {
            buffer[i] ^= KEY;
            i += 1;
        }

        Encrypted {
            buffer: UnsafeCell::new(buffer),
            decryption_state: AtomicU8::new(STATE_UNENCRYPTED),
            extra: (),
            _phantom: PhantomData,
        }
    }
}

impl<const KEY: u8, D: DropStrategy<Extra = ()>, const N: usize> Deref
    for Encrypted<Xor<KEY, D>, ByteArray, N>
{
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        // Fast path: already decrypted
        if self.decryption_state.load(Ordering::Acquire) == STATE_DECRYPTED {
            // SAFETY: `buffer` is initialized and lives as long as `self`.
            return unsafe { &*self.buffer.get() };
        }

        // Try to acquire the decryption lock by transitioning from UNENCRYPTED to DECRYPTING
        match self.decryption_state.compare_exchange(
            STATE_UNENCRYPTED,
            STATE_DECRYPTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: `buffer` is always initialized and points to valid `[u8; N]`.
                // We won the race, perform decryption with exclusive mutable access.
                let data = unsafe { &mut *self.buffer.get() };
                for byte in data.iter_mut() {
                    *byte ^= KEY;
                }

                // Decryption complete - release lock by transitioning to DECRYPTED
                // Use Release ordering to ensure all decryption writes are visible to other threads
                self.decryption_state.store(STATE_DECRYPTED, Ordering::Release);
            }
            Err(_) => {
                // Lost the race - another thread is decrypting
                // Spin-wait until decryption completes
                while self.decryption_state.load(Ordering::Acquire) != STATE_DECRYPTED {
                    core::hint::spin_loop();
                }
            }
        }

        // SAFETY: `buffer` is initialized and lives as long as `self`.
        // Decryption is complete (either by us or another thread), so it's safe
        // to return a shared reference.
        unsafe { &*self.buffer.get() }
    }
}

impl<const KEY: u8, D: DropStrategy<Extra = ()>, const N: usize> Deref
    for Encrypted<Xor<KEY, D>, StringLiteral, N>
{
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // Fast path: already decrypted
        if self.decryption_state.load(Ordering::Acquire) == STATE_DECRYPTED {
            // SAFETY: `buffer` is initialized and lives as long as `self`.
            let bytes = unsafe { &*self.buffer.get() };
            // SAFETY: Since the original input was a valid UTF-8 string literal, XOR with a single byte key will not produce invalid UTF-8. The length is also preserved, so the resulting bytes will still form a valid UTF-8 string.
            return unsafe { core::str::from_utf8_unchecked(bytes) };
        }

        // Try to acquire the decryption lock by transitioning from UNENCRYPTED to DECRYPTING
        match self.decryption_state.compare_exchange(
            STATE_UNENCRYPTED,
            STATE_DECRYPTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: `buffer` is always initialized and points to valid `[u8; N]`.
                // We won the race, perform decryption with exclusive mutable access.
                let data = unsafe { &mut *self.buffer.get() };
                for byte in data.iter_mut() {
                    *byte ^= KEY;
                }

                // Decryption complete - release lock by transitioning to DECRYPTED
                // Use Release ordering to ensure all decryption writes are visible to other threads
                self.decryption_state.store(STATE_DECRYPTED, Ordering::Release);
            }
            Err(_) => {
                // Lost the race - another thread is decrypting
                // Spin-wait until decryption completes
                while self.decryption_state.load(Ordering::Acquire) != STATE_DECRYPTED {
                    core::hint::spin_loop();
                }
            }
        }

        // SAFETY: `buffer` is initialized and lives as long as `self`.
        // Decryption is complete (either by us or another thread), so it's safe
        // to return a shared reference.
        let bytes = unsafe { &*self.buffer.get() };

        // SAFETY: Since the original input was a valid UTF-8 string literal, XOR with a single byte key will not produce invalid UTF-8. The length is also preserved, so the resulting bytes will still form a valid UTF-8 string.
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ByteArray, StringLiteral,
        align::{Aligned8, Aligned16},
        drop_strategy::{NoOp, Zeroize},
        xor::Xor,
    };

    use alloc::vec;
    use alloc::vec::Vec;
    use core::{mem::size_of, sync::atomic::AtomicUsize};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_size() {
        assert_eq!(17, size_of::<Encrypted<Xor<0xAA, Zeroize>, ByteArray, 16>>());
        assert_eq!(17, size_of::<Encrypted<Xor<0xAA, NoOp>, ByteArray, 16>>());
        assert_eq!(17, size_of::<Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 16>>());

        // Alignment tests.
        assert_eq!(24, size_of::<Aligned8<Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 16>>>());
        assert_eq!(
            32,
            size_of::<Aligned16<Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 16>>>()
        );
    }

    const CONST_ENCRYPTED: Encrypted<Xor<0xAA, Zeroize>, ByteArray, 5> =
        Encrypted::<Xor<0xAA, Zeroize>, ByteArray, 5>::new(*b"hello");

    const CONST_ENCRYPTED_STR: Encrypted<Xor<0xFF, Zeroize>, StringLiteral, 3> =
        Encrypted::<Xor<0xFF, Zeroize>, StringLiteral, 3>::new(*b"abc");

    const CONST_ENCRYPTED_SINGLE: Encrypted<Xor<0xFF, Zeroize>, ByteArray, 1> =
        Encrypted::<Xor<0xFF, Zeroize>, ByteArray, 1>::new([42]);

    const CONST_ENCRYPTED_ZEROS: Encrypted<Xor<0xAA, Zeroize>, ByteArray, 4> =
        Encrypted::<Xor<0xAA, Zeroize>, ByteArray, 4>::new([0, 0, 0, 0]);

    const CONST_ENCRYPTED_NOOP_KEY: Encrypted<Xor<0x00, Zeroize>, ByteArray, 3> =
        Encrypted::<Xor<0x00, Zeroize>, ByteArray, 3>::new(*b"abc");

    #[test]
    fn test_new_in_const_context() {
        let plain: &[u8; 5] = &*CONST_ENCRYPTED;
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn test_buffer_is_encrypted_before_deref() {
        // Each use of the const produces a fresh copy, so this instance is never deref'd.
        let encrypted = CONST_ENCRYPTED;

        // Before deref, the raw buffer should hold plaintext XOR'd with the key.
        let raw = unsafe { &*encrypted.buffer.get() };
        let expected = [b'h' ^ 0xAA, b'e' ^ 0xAA, b'l' ^ 0xAA, b'l' ^ 0xAA, b'o' ^ 0xAA];
        assert_eq!(raw, &expected, "buffer should be XOR-encrypted before deref");
        assert_ne!(raw, b"hello", "buffer must NOT be plaintext before deref");
    }

    #[test]
    fn test_string_buffer_is_encrypted_before_deref() {
        let encrypted = CONST_ENCRYPTED_STR;

        let raw = unsafe { &*encrypted.buffer.get() };
        let expected = [b'a' ^ 0xFF, b'b' ^ 0xFF, b'c' ^ 0xFF];
        assert_eq!(raw, &expected, "string buffer should be XOR-encrypted before deref");
        assert_ne!(raw, b"abc");
    }

    #[test]
    fn test_bytearray_deref_decrypts() {
        let encrypted = CONST_ENCRYPTED;

        // Deref should decrypt and return the original plaintext.
        let plain: &[u8; 5] = &*encrypted;
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn test_bytearray_deref_single_byte() {
        let pre_deref = CONST_ENCRYPTED_SINGLE;
        let raw = unsafe { &*pre_deref.buffer.get() };
        assert_eq!(raw, &[42 ^ 0xFF]);

        let encrypted = CONST_ENCRYPTED_SINGLE;
        let plain: &[u8; 1] = &*encrypted;
        assert_eq!(plain, &[42]);
    }

    #[test]
    fn test_bytearray_deref_all_zeros() {
        let pre_deref = CONST_ENCRYPTED_ZEROS;
        let raw = unsafe { &*pre_deref.buffer.get() };
        assert_eq!(raw, &[0xAA, 0xAA, 0xAA, 0xAA]);

        let encrypted = CONST_ENCRYPTED_ZEROS;
        let plain: &[u8; 4] = &*encrypted;
        assert_eq!(plain, &[0, 0, 0, 0]);
    }

    #[test]
    fn test_bytearray_deref_key_zero_is_identity() {
        // A key of 0x00 means XOR is a no-op; buffer equals plaintext.
        let pre_deref = CONST_ENCRYPTED_NOOP_KEY;
        let raw = unsafe { &*pre_deref.buffer.get() };
        assert_eq!(raw, b"abc", "key 0x00 should leave buffer unchanged");

        let encrypted = CONST_ENCRYPTED_NOOP_KEY;
        let plain: &[u8; 3] = &*encrypted;
        assert_eq!(plain, b"abc");
    }

    #[test]
    fn test_bytearray_multiple_derefs_are_idempotent() {
        let encrypted = CONST_ENCRYPTED;

        let first: &[u8; 5] = &*encrypted;
        let second: &[u8; 5] = &*encrypted;
        assert_eq!(first, b"hello");
        assert_eq!(second, b"hello");
    }

    #[test]
    fn test_encrypted_is_sync() {
        const fn assert_sync<T: Sync>() {}
        const fn check() {
            assert_sync::<Encrypted<Xor<0xAA, Zeroize>, ByteArray, 5>>();
            assert_sync::<Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 5>>();
            assert_sync::<Encrypted<Xor<0xCC, NoOp>, ByteArray, 8>>();
        }
        check();
    }

    #[test]
    fn test_concurrent_deref_same_value() {
        const SHARED: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
            Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");

        let shared = Arc::new(SHARED);
        let mut handles: Vec<thread::JoinHandle<()>> = vec![];

        for _ in 0..10 {
            let shared_clone = Arc::clone(&shared);
            let handle = thread::spawn(move || {
                let decrypted: &str = &*shared_clone;
                assert_eq!(decrypted, "hello");
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_deref_bytearray() {
        const SHARED: Encrypted<Xor<0xFF, Zeroize>, ByteArray, 4> =
            Encrypted::<Xor<0xFF, Zeroize>, ByteArray, 4>::new([1, 2, 3, 4]);

        let shared = Arc::new(SHARED);
        let mut handles: Vec<thread::JoinHandle<()>> = vec![];

        for _ in 0..20 {
            let shared_clone = Arc::clone(&shared);
            let handle = thread::spawn(move || {
                let decrypted: &[u8; 4] = &*shared_clone;
                assert_eq!(decrypted, &[1, 2, 3, 4]);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_deref_reencrypt() {
        const SHARED: Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 6> =
            Encrypted::<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 6>::new(*b"secret");

        let shared = Arc::new(SHARED);
        let mut handles: Vec<thread::JoinHandle<()>> = vec![];

        for _ in 0..15 {
            let shared_clone = Arc::clone(&shared);
            let handle = thread::spawn(move || {
                let decrypted: &str = &*shared_clone;
                assert_eq!(decrypted, "secret");
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_deref_race_condition() {
        const SHARED: Encrypted<Xor<0x42, Zeroize>, StringLiteral, 8> =
            Encrypted::<Xor<0x42, Zeroize>, StringLiteral, 8>::new(*b"racetest");

        let shared = Arc::new(SHARED);
        let results = Arc::new(AtomicUsize::new(0));
        let mut handles: Vec<thread::JoinHandle<()>> = vec![];

        for _ in 0..50 {
            let shared_clone = Arc::clone(&shared);
            let results_clone = Arc::clone(&results);
            let handle = thread::spawn(move || {
                let decrypted: &str = &*shared_clone;
                if decrypted == "racetest" {
                    results_clone.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let success_count = results.load(core::sync::atomic::Ordering::Relaxed);
        assert_eq!(success_count, 50, "all threads should see correct plaintext");
    }

    #[test]
    fn test_concurrent_multiple_values() {
        const SECRET1: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
            Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");
        const SECRET2: Encrypted<Xor<0xFF, Zeroize>, ByteArray, 4> =
            Encrypted::<Xor<0xFF, Zeroize>, ByteArray, 4>::new([1, 2, 3, 4]);

        let secret1 = Arc::new(SECRET1);
        let secret2 = Arc::new(SECRET2);
        let mut handles: Vec<thread::JoinHandle<()>> = vec![];

        for i in 0..20 {
            if i % 2 == 0 {
                let secret_clone = Arc::clone(&secret1);
                let handle = thread::spawn(move || {
                    let decrypted: &str = &*secret_clone;
                    assert_eq!(decrypted, "hello");
                });
                handles.push(handle);
            } else {
                let secret_clone = Arc::clone(&secret2);
                let handle = thread::spawn(move || {
                    let decrypted: &[u8; 4] = &*secret_clone;
                    assert_eq!(decrypted, &[1, 2, 3, 4]);
                });
                handles.push(handle);
            }
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
