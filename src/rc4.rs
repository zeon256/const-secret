//! RC4 stream cipher algorithm implementation.
//!
//! This module provides the RC4 (Rivest Cipher 4) stream cipher implementation.
//! RC4 is a widely-used stream cipher that uses a variable-length key (1-256 bytes)
//! to generate a pseudorandom keystream which is XOR'd with the plaintext.
//!
//! # Security Note
//!
//! RC4 is considered cryptographically broken and should not be used for
//! security-sensitive applications. It is provided here for obfuscation purposes
//! only. For production use, consider using a modern authenticated encryption
//! algorithm.
//!
//! # Algorithm
//!
//! RC4 consists of two main phases:
//! 1. **KSA (Key Scheduling Algorithm)**: Initializes a 256-byte permutation
//!    table (S-box) based on the key
//! 2. **PRGA (Pseudo-Random Generation Algorithm)**: Generates keystream bytes
//!    by permuting the S-box
//!
//! # Types
//!
//! - [`Rc4<KEY_LEN, D>`](Rc4): The main algorithm type with const generic key length
//! - [`ReEncrypt<KEY_LEN>`](ReEncrypt): A drop strategy that re-encrypts data on drop
//!
//! # Example
//!
//! ```rust
//! use const_secret::{
//!     Encrypted, StringLiteral,
//!     drop_strategy::Zeroize,
//!     rc4::{ReEncrypt, Rc4},
//! };
//!
//! const KEY: [u8; 5] = *b"mykey";
//!
//! // Zeroize on drop (default)
//! const SECRET: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5> =
//!     Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5>::new(*b"hello", KEY);
//!
//! // Re-encrypt on drop
//! const SECRET2: Encrypted<Rc4<5, ReEncrypt<5>>, StringLiteral, 6> =
//!     Encrypted::<Rc4<5, ReEncrypt<5>>, StringLiteral, 6>::new(*b"secret", KEY);
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

/// Re-encrypts the buffer using RC4 on drop.
/// This ensures the plaintext never remains in memory after the value is dropped.
pub struct ReEncrypt<const KEY_LEN: usize>;

impl<const KEY_LEN: usize> DropStrategy for ReEncrypt<KEY_LEN> {
    type Extra = [u8; KEY_LEN];

    fn drop(data: &mut [u8], key: &[u8; KEY_LEN]) {
        // Re-run RC4 to re-encrypt the buffer
        let mut s = [0u8; 256];
        let mut j: u8 = 0;

        // Initialize S-box
        let mut i = 0usize;
        while i < 256 {
            s[i] = i as u8;
            i += 1;
        }

        // KSA
        let mut i = 0usize;
        while i < 256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % KEY_LEN]);
            s.swap(i, j as usize);
            i += 1;
        }

        // PRGA: Re-encrypt
        let mut i: u8 = 0;
        j = 0;
        let mut idx = 0usize;
        let n = data.len();
        while idx < n {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            data[idx] ^= k;
            idx += 1;
        }
    }
}

/// An algorithm that performs RC4 encryption and decryption.
/// This algorithm is generic over drop strategy.
///
/// RC4 is a stream cipher that uses a variable-length key (1-256 bytes).
/// The key is stored alongside the encrypted data and is used to reproduce
/// the keystream for decryption at runtime.
pub struct Rc4<const KEY_LEN: usize, D: DropStrategy = Zeroize>(PhantomData<D>);

impl<const KEY_LEN: usize, D: DropStrategy<Extra = [u8; KEY_LEN]>> Algorithm for Rc4<KEY_LEN, D> {
    type Drop = D;
    type Extra = [u8; KEY_LEN];
}

impl<const KEY_LEN: usize, D: DropStrategy<Extra = [u8; KEY_LEN]>, M, const N: usize>
    Encrypted<Rc4<KEY_LEN, D>, M, N>
{
    /// Creates a new encrypted buffer using RC4.
    ///
    /// # Arguments
    /// * `buffer` - The plaintext data to encrypt (must be an array of length N)
    /// * `key` - The RC4 key (must be an array of length `KEY_LEN`)
    ///
    /// This function performs RC4 encryption at compile time:
    /// 1. Runs the Key Scheduling Algorithm (KSA) to initialize the S-box
    /// 2. Runs the Pseudo-Random Generation Algorithm (PRGA) to generate keystream
    /// 3. XORs the keystream with the plaintext
    pub const fn new(mut buffer: [u8; N], key: [u8; KEY_LEN]) -> Self {
        // RC4 Key Scheduling Algorithm (KSA) and PRGA combined
        // We use a fixed 256-byte S-box for simplicity
        let mut s = [0u8; 256];
        let mut j: u8 = 0;

        // Initialize S-box
        let mut i = 0usize;
        while i < 256 {
            s[i] = i as u8;
            i += 1;
        }

        // KSA: Permute S-box based on key
        let mut i = 0usize;
        while i < 256 {
            let key_byte = key[i % KEY_LEN];
            j = j.wrapping_add(s[i]).wrapping_add(key_byte);
            // Swap s[i] and s[j]
            let temp = s[i];
            s[i] = s[j as usize];
            s[j as usize] = temp;
            i += 1;
        }

        // PRGA: Generate keystream and encrypt buffer in place
        let mut i: u8 = 0;
        j = 0;
        let mut idx = 0usize;
        while idx < N {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            // Swap s[i] and s[j]
            let temp = s[i as usize];
            s[i as usize] = s[j as usize];
            s[j as usize] = temp;
            // Generate keystream byte and XOR with buffer
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            buffer[idx] ^= k;
            idx += 1;
        }

        Encrypted {
            buffer: UnsafeCell::new(buffer),
            decryption_state: AtomicU8::new(STATE_UNENCRYPTED),
            extra: key,
            _phantom: PhantomData,
        }
    }
}

impl<const KEY_LEN: usize, D: DropStrategy<Extra = [u8; KEY_LEN]>, const N: usize> Deref
    for Encrypted<Rc4<KEY_LEN, D>, ByteArray, N>
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
                // Reconstruct RC4 state from stored key and decrypt
                let key = &self.extra;
                let mut s = [0u8; 256];
                let mut j: u8 = 0;

                // Initialize S-box
                let mut i = 0usize;
                while i < 256 {
                    s[i] = i as u8;
                    i += 1;
                }

                // KSA
                let mut i = 0usize;
                while i < 256 {
                    j = j.wrapping_add(s[i]).wrapping_add(key[i % KEY_LEN]);
                    s.swap(i, j as usize);
                    i += 1;
                }

                // PRGA: Decrypt
                let mut i: u8 = 0;
                j = 0;
                let mut idx = 0usize;
                while idx < N {
                    i = i.wrapping_add(1);
                    j = j.wrapping_add(s[i as usize]);
                    s.swap(i as usize, j as usize);
                    let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
                    data[idx] ^= k;
                    idx += 1;
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

impl<const KEY_LEN: usize, D: DropStrategy<Extra = [u8; KEY_LEN]>, const N: usize> Deref
    for Encrypted<Rc4<KEY_LEN, D>, StringLiteral, N>
{
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // Fast path: already decrypted
        if self.decryption_state.load(Ordering::Acquire) == STATE_DECRYPTED {
            // SAFETY: `buffer` is initialized and lives as long as `self`.
            let bytes = unsafe { &*self.buffer.get() };
            // SAFETY: Since the original input was a valid UTF-8 string literal, XOR
            // with RC4 keystream preserves the length, and RC4 is a bijection,
            // so the resulting bytes will still form a valid UTF-8 string.
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
                // Reconstruct RC4 state from stored key and decrypt
                let key = &self.extra;
                let mut s = [0u8; 256];
                let mut j: u8 = 0;

                // Initialize S-box
                let mut i = 0usize;
                while i < 256 {
                    s[i] = i as u8;
                    i += 1;
                }

                // KSA
                let mut i = 0usize;
                while i < 256 {
                    j = j.wrapping_add(s[i]).wrapping_add(key[i % KEY_LEN]);
                    s.swap(i, j as usize);
                    i += 1;
                }

                // PRGA: Decrypt
                let mut i: u8 = 0;
                j = 0;
                let mut idx = 0usize;
                while idx < N {
                    i = i.wrapping_add(1);
                    j = j.wrapping_add(s[i as usize]);
                    s.swap(i as usize, j as usize);
                    let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
                    data[idx] ^= k;
                    idx += 1;
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

        // SAFETY: Since the original input was a valid UTF-8 string literal, XOR
        // with RC4 keystream preserves the length, and RC4 is a bijection,
        // so the resulting bytes will still form a valid UTF-8 string.
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ByteArray, StringLiteral,
        drop_strategy::{NoOp, Zeroize},
        rc4::Rc4,
    };

    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::thread;

    // 5-byte key
    const RC4_KEY: [u8; 5] = *b"mykey";
    const RC4_KEY2: [u8; 16] = *b"sixteen-byte-key";

    const CONST_ENCRYPTED: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 5> =
        Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 5>::new(*b"hello", RC4_KEY);

    const CONST_ENCRYPTED_STR: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5> =
        Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5>::new(*b"hello", RC4_KEY);

    const CONST_ENCRYPTED_16: Encrypted<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 8> =
        Encrypted::<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 8>::new(*b"longdata", RC4_KEY2);

    #[test]
    fn test_rc4_buffer_is_encrypted_before_deref() {
        let encrypted = CONST_ENCRYPTED;

        // Before deref, the raw buffer should hold the RC4-encrypted data
        let raw = unsafe { &*encrypted.buffer.get() };
        // RC4 encryption produces different output than plaintext
        assert_ne!(raw, b"hello", "buffer must NOT be plaintext before deref");
        // The key should be stored in the extra field
        assert_eq!(encrypted.extra, RC4_KEY, "key should be stored in extra");
    }

    #[test]
    fn test_rc4_bytearray_deref_decrypts() {
        let encrypted = CONST_ENCRYPTED;

        // Deref should decrypt and return the original plaintext
        let plain: &[u8; 5] = &*encrypted;
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn test_rc4_string_deref_decrypts() {
        let encrypted = CONST_ENCRYPTED_STR;

        // Deref should decrypt and return the original plaintext
        let plain: &str = &*encrypted;
        assert_eq!(plain, "hello");
    }

    #[test]
    fn test_rc4_multiple_derefs_are_idempotent() {
        let encrypted = CONST_ENCRYPTED;

        let first: &[u8; 5] = &*encrypted;
        let second: &[u8; 5] = &*encrypted;
        assert_eq!(first, b"hello");
        assert_eq!(second, b"hello");
    }

    #[test]
    fn test_rc4_different_key_length() {
        let encrypted = CONST_ENCRYPTED_16;

        let plain: &[u8; 8] = &*encrypted;
        assert_eq!(plain, b"longdata");
    }

    #[test]
    fn test_rc4_encrypted_is_sync() {
        const fn assert_sync<T: Sync>() {}
        const fn check() {
            assert_sync::<Encrypted<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 8>>();
            assert_sync::<Encrypted<Rc4<16, Zeroize<[u8; 16]>>, StringLiteral, 10>>();
            assert_sync::<Encrypted<Rc4<32, NoOp<[u8; 32]>>, ByteArray, 16>>();
        }
        check();
    }

    #[test]
    fn test_rc4_concurrent_deref_same_value() {
        const SHARED: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5> =
            Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 5>::new(*b"hello", RC4_KEY);

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
    fn test_rc4_concurrent_deref_bytearray() {
        const SHARED: Encrypted<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 4> =
            Encrypted::<Rc4<16, Zeroize<[u8; 16]>>, ByteArray, 4>::new([1, 2, 3, 4], RC4_KEY2);

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
    fn test_rc4_concurrent_deref_race_condition() {
        const SHARED: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 8> =
            Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, StringLiteral, 8>::new(*b"racetest", RC4_KEY);

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
    fn test_rc4_single_byte() {
        const ENCRYPTED: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 1> =
            Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 1>::new([42], RC4_KEY);

        let plain: &[u8; 1] = &*ENCRYPTED;
        assert_eq!(plain, &[42]);
    }

    #[test]
    fn test_rc4_all_zeros() {
        const ENCRYPTED: Encrypted<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 4> =
            Encrypted::<Rc4<5, Zeroize<[u8; 5]>>, ByteArray, 4>::new([0, 0, 0, 0], RC4_KEY);

        let plain: &[u8; 4] = &*ENCRYPTED;
        assert_eq!(plain, &[0, 0, 0, 0]);
    }

    #[test]
    fn test_rc4_reencrypt_drop() {
        use crate::rc4::ReEncrypt;

        const SHARED: Encrypted<Rc4<5, ReEncrypt<5>>, StringLiteral, 5> =
            Encrypted::<Rc4<5, ReEncrypt<5>>, StringLiteral, 5>::new(*b"hello", RC4_KEY);

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

        // After all threads finish and the Arc is dropped, the data should be re-encrypted
        // (We can't easily test the re-encryption result here, but the test verifies
        // that ReEncrypt compiles and works with the type system)
    }
}
