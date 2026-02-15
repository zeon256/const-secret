use std::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::Deref,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{dtor::ZeroizeDtor, AlgorithmDtor, ByteArray, Encrypted};

/// Special only for xor encryption
/// Users might want to use this to xor back the data on drop
pub struct XorDtor<const KEY: u8>;

impl<const KEY: u8> AlgorithmDtor for XorDtor<KEY> {
    fn drop<const N: usize>(data_ref: &mut [u8; N]) {
        for i in 0..N {
            data_ref[i] ^= KEY;
        }
    }
}

/// An algorithm that performs XOR encryption and decryption
/// This algorithm is generic over destructor.
///
/// Sometimes you want the destructor to zero out while sometimes you want
/// it to be no-op or even encrypt the data back.
/// Prima facie, zeroize is the safest. However, sometimes you may want to
/// encrypt the data back which may expose information about the key because of he compiled
/// assembly. However, due to optimizations, it can be harder to see what the key is because
/// this algorithm is generic over KEYs. So you can have per buffer encryption which
/// may yield different assembly instructions depending on the key.
pub struct Xor<const KEY: u8, D: AlgorithmDtor = ZeroizeDtor>(PhantomData<D>);

/// XOR algorithm that XORs back on drop using the same key.
/// This ensures the encryption key and drop key are always in sync.
pub type XorSymmetric<const KEY: u8> = Xor<KEY, XorDtor<KEY>>;

impl<const KEY: u8, D: AlgorithmDtor> AlgorithmDtor for Xor<KEY, D> {
    fn drop<const N: usize>(data_ref: &mut [u8; N]) {
        D::drop(data_ref);
    }
}

impl<const KEY: u8, const N: usize, U, D> Encrypted<Xor<KEY, D>, N, U>
where
    D: AlgorithmDtor,
{
    pub const fn new(plaintext: [u8; N]) -> Self {
        let mut encrypted = [0u8; N];
        // cant use for loops here because it is not stable in const fn
        let mut i = 0;
        while i < N {
            encrypted[i] = plaintext[i] ^ KEY;
            i += 1;
        }
        Self {
            data: UnsafeCell::new(encrypted),
            is_decrypted: AtomicBool::new(false),
            _phantom: PhantomData,
        }
    }

    // Private in-place mutate (decrypt or encrypt; same for XOR).
    pub unsafe fn xor_in_place(&self) {
        let data_ptr = self.data.get();
        let mut_buf = unsafe { &mut *data_ptr };
        for byte in mut_buf.iter_mut() {
            *byte ^= KEY;
        }
    }
}

impl<const KEY: u8, const N: usize, D: AlgorithmDtor> Deref for Encrypted<Xor<KEY, D>, N, ByteArray> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // Fast path: already decrypted
        if self.is_decrypted.load(Ordering::Acquire) {
            return unsafe { &*self.data.get() };
        }

        // Try to claim the decryption
        if self
            .is_decrypted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // We won the race - we decrypt
            unsafe {
                self.xor_in_place();
            }
        }
        // else: another thread is decrypting or has decrypted
        // The Acquire ordering ensures we see their writes

        unsafe { &*self.data.get() }
    }
}
