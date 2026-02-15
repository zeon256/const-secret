use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::xor::Xor;

mod dtor;
mod xor;

pub trait AlgorithmDtor {
    fn drop<const N: usize>(data_ref: &mut [u8; N]);
}

// SAFETY: Encrypted can be safely shared between threads because:
// 1. is_decrypted is an AtomicBool providing synchronization
// 2. We use compare_exchange to ensure only one thread performs decryption
// 3. After decryption, data is only read (immutable access)
unsafe impl<A, const N: usize, U> Sync for Encrypted<A, N, U> where A: AlgorithmDtor {}

pub struct StringLiteral;
pub struct ByteArray;

// The encrypted type: holds the data (mutable via UnsafeCell) and a flag.
pub struct Encrypted<A: AlgorithmDtor, const N: usize, U> {
    data: UnsafeCell<[u8; N]>,
    is_decrypted: AtomicBool,
    _phantom: PhantomData<(A, U)>,
}

impl<A, const N: usize, U> Drop for Encrypted<A, N, U>
where
    A: AlgorithmDtor,
{
    fn drop(&mut self) {
        let data_ref = unsafe { &mut *self.data.get() };
        A::drop(data_ref)
    }
}

impl<const KEY: u8, const N: usize, D: AlgorithmDtor> Deref
    for Encrypted<Xor<KEY, D>, N, StringLiteral>
{
    type Target = str;

    fn deref(&self) -> &str {
        // Fast path: already decrypted
        if self.is_decrypted.load(Ordering::Acquire) {
            // SAFETY: The data is guaranteed to be valid ASCII
            return unsafe { str::from_utf8_unchecked(&*self.data.get()) };
        }

        // Try to claim the decryption
        if self
            .is_decrypted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe {
                self.xor_in_place();
            }
        }

        unsafe { std::str::from_utf8_unchecked(&*self.data.get()) }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use crate::{
        dtor::{NoOpDtor, ZeroizeDtor},
        xor::XorSymmetric,
    };

    use super::*;

    fn process_buffer(buf: &[u8]) {
        println!("Processed: {:?}", buf);
    }

    fn process_string(s: &str) {
        println!("Processed string: {}", s);
    }

    #[test]
    fn use_encrypted() {
        const ENCRYPTED_BYTES: Encrypted<Xor<0xAA, ZeroizeDtor>, 5, ByteArray> =
            Encrypted::new([1, 2, 3, 4, 5]);

        const ENCRYPTED_STR: Encrypted<Xor<0xFF, NoOpDtor>, 11, StringLiteral> =
            Encrypted::new(*b"hello world");

        const ENCRYPTED_XOR: Encrypted<XorSymmetric<0xAA>, 5, ByteArray> =
            Encrypted::new([5, 3, 1, 4, 5]);

        const ENCRYPTED_XOR_STR: Encrypted<XorSymmetric<0xAA>, 8, StringLiteral> =
            Encrypted::new(*b"Joe mama");

        process_buffer(&ENCRYPTED_BYTES);
        process_string(&ENCRYPTED_STR);
        process_buffer(&ENCRYPTED_XOR);
        process_string(&ENCRYPTED_XOR_STR);
    }

    #[test]
    fn test_basic_deref() {
        const ENCRYPTED: Encrypted<Xor<0xAA, ZeroizeDtor>, 5, ByteArray> =
            Encrypted::new([1, 2, 3, 4, 5]);
        let decrypted = &*ENCRYPTED;
        assert_eq!(decrypted, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_multiple_derefs() {
        const ENCRYPTED: Encrypted<Xor<0xFF, ZeroizeDtor>, 5, ByteArray> =
            Encrypted::new([1, 2, 3, 4, 5]);
        let d1 = &*ENCRYPTED;
        let d2 = &*ENCRYPTED;
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_string_deref() {
        const ENCRYPTED: Encrypted<Xor<0xAA, ZeroizeDtor>, 5, StringLiteral> =
            Encrypted::new(*b"hello");
        let s = &*ENCRYPTED;
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let encrypted = Arc::new(Encrypted::<Xor<0xAA, ZeroizeDtor>, 5, ByteArray>::new([
            1, 2, 3, 4, 5,
        ]));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let enc = Arc::clone(&encrypted);
                thread::spawn(move || {
                    let _data = &*enc;
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_zeroize_dtor_residue() {
        use std::mem::ManuallyDrop;
        use std::ptr;

        // Use Box to ensure stable memory location
        let mut encrypted =
            ManuallyDrop::new(Box::new(
                Encrypted::<Xor<0xAA, ZeroizeDtor>, 5, ByteArray>::new([1, 2, 3, 4, 5]),
            ));

        // Trigger decryption
        let buffer = &***encrypted;
        assert_eq!(buffer, [1, 2, 3, 4, 5]);

        // Get pointer to internal data before drop
        let data_ptr = encrypted.data.get();

        // Manually drop the inner value (not the Box wrapper in ManuallyDrop)
        // Need to use drop_in_place because we only want the destructor to run
        // but not deallocate the memory
        unsafe {
            ptr::drop_in_place(&mut **encrypted);
        }

        // After drop, memory should be zeroed
        let residue = unsafe { ptr::read(data_ptr) };
        assert_eq!(
            residue,
            [0, 0, 0, 0, 0],
            "ZeroizeDtor should zero memory on drop"
        );
    }

    #[test]
    fn test_noop_dtor_residue() {
        use std::mem::ManuallyDrop;
        use std::ptr;

        // Use Box to ensure stable memory location
        let mut encrypted =
            ManuallyDrop::new(Box::new(
                Encrypted::<Xor<0xAA, NoOpDtor>, 5, ByteArray>::new([1, 2, 3, 4, 5]),
            ));

        // Trigger decryption
        let buffer = &***encrypted;
        assert_eq!(buffer, [1, 2, 3, 4, 5]);

        // The decrypted plaintext should be [1, 2, 3, 4, 5]
        let expected: [u8; 5] = [1, 2, 3, 4, 5];

        // Get pointer to internal data
        let data_ptr = encrypted.data.get();

        // Manually drop the inner value
        // Need to use drop_in_place because we only want the destructor to run
        // but not deallocate the memory
        unsafe {
            ptr::drop_in_place(&mut **encrypted);
        }

        // After drop, memory should remain as decrypted (no-op)
        let residue = unsafe { ptr::read(data_ptr) };
        assert_eq!(
            residue, expected,
            "NoOpDtor should leave memory unchanged on drop"
        );
    }

    #[test]
    fn test_xor_symmetric_dtor_residue() {
        use std::mem::ManuallyDrop;
        use std::ptr;

        const KEY: u8 = 0xAA;
        let plaintext: [u8; 5] = [1, 2, 3, 4, 5];

        // Pre-compute expected encrypted form
        let expected_encrypted: [u8; 5] = [
            plaintext[0] ^ KEY,
            plaintext[1] ^ KEY,
            plaintext[2] ^ KEY,
            plaintext[3] ^ KEY,
            plaintext[4] ^ KEY,
        ];

        // Use Box to ensure stable memory location
        let mut encrypted = ManuallyDrop::new(Box::new(
            Encrypted::<XorSymmetric<KEY>, 5, ByteArray>::new(plaintext),
        ));

        // Trigger decryption
        let buffer = &***encrypted;
        assert_eq!(buffer, plaintext);

        // Get pointer to internal data
        let data_ptr = encrypted.data.get();

        // Manually drop the inner value
        // Need to use drop_in_place because we only want the destructor to run
        // but not deallocate the memory
        unsafe {
            ptr::drop_in_place(&mut **encrypted);
        }

        // After drop, memory should be XORed back (re-encrypted)
        let residue = unsafe { ptr::read(data_ptr) };
        assert_eq!(
            residue, expected_encrypted,
            "XorSymmetric should re-encrypt memory on drop"
        );
    }

    #[test]
    fn test_noop_dtor() {
        const ENCRYPTED: Encrypted<Xor<0xAA, NoOpDtor>, 5, ByteArray> =
            Encrypted::new([1, 2, 3, 4, 5]);
        let decrypted = &*ENCRYPTED;
        assert_eq!(decrypted, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_noop_dtor_string() {
        const ENCRYPTED: Encrypted<Xor<0xFF, NoOpDtor>, 11, StringLiteral> =
            Encrypted::new(*b"hello world");
        let s = &*ENCRYPTED;
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_xor_symmetric() {
        const ENCRYPTED: Encrypted<XorSymmetric<0xAA>, 5, ByteArray> =
            Encrypted::new([1, 2, 3, 4, 5]);
        let decrypted = &*ENCRYPTED;
        assert_eq!(decrypted, &[1, 2, 3, 4, 5]);
        // XorSymmetric XORs back on drop using the same key
    }

    #[test]
    fn test_xor_symmetric_string() {
        const ENCRYPTED: Encrypted<XorSymmetric<0xFF>, 11, StringLiteral> =
            Encrypted::new(*b"hello world");
        let s = &*ENCRYPTED;
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_xor_symmetric_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let encrypted = Arc::new(Encrypted::<XorSymmetric<0xAA>, 5, ByteArray>::new([
            1, 2, 3, 4, 5,
        ]));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let enc = Arc::clone(&encrypted);
                thread::spawn(move || {
                    let data: &[u8] = &**enc;
                    assert_eq!(data, &[1, 2, 3, 4, 5]);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }
}
