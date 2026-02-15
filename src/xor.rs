use core::{cell::UnsafeCell, marker::PhantomData, sync::atomic::AtomicBool};

use crate::{
    Algorithm, Encrypted, GetMutBuffer,
    drop_strategy::{DropStrategy, NoOp, Zeroize},
};

pub struct ReEncrypt<const KEY: u8>;

impl<const KEY: u8> DropStrategy for ReEncrypt<KEY> {
    fn drop(data: &mut [u8]) {
        for byte in data {
            *byte ^= KEY;
        }
    }
}

impl<const KEY: u8> Algorithm for Xor<KEY, Zeroize> {
    type Buffer<const N: usize> = [u8; N];
    type IsDecrypted = ();
    type Drop = Zeroize;
}

impl<const KEY: u8> Algorithm for Xor<KEY, NoOp> {
    type Buffer<const N: usize> = [u8; N];
    type IsDecrypted = ();
    type Drop = NoOp;
}

impl<const KEY: u8> Algorithm for Xor<KEY, ReEncrypt<KEY>> {
    type Buffer<const N: usize> = UnsafeCell<[u8; N]>;
    type IsDecrypted = AtomicBool;
    type Drop = ReEncrypt<KEY>;
}

impl<const KEY: u8, D, const N: usize> GetMutBuffer for Encrypted<Xor<KEY, Zeroize>, D, N> {
    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl<const KEY: u8, D, const N: usize> GetMutBuffer for Encrypted<Xor<KEY, NoOp>, D, N> {
    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl<const KEY: u8, D, const N: usize> GetMutBuffer for Encrypted<Xor<KEY, ReEncrypt<KEY>>, D, N> {
    fn buffer_mut(&mut self) -> &mut [u8] {
        // UnsafeCell is required for interior mutability during re-encryption.
        // SAFETY: The buffer is always initialized and never moved or dropped.
        unsafe { &mut *self.buffer.get() }
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
pub struct Xor<const KEY: u8, D: DropStrategy = Zeroize>(PhantomData<D>);

impl<const KEY: u8, D, const N: usize> Encrypted<Xor<KEY, Zeroize>, D, N> {
    pub const fn new(mut buffer: [u8; N]) -> Self {
        // since we cant use for loops in const context we must use a while loop
        let mut i = 0;
        while i < N {
            buffer[i] ^= KEY;
            i += 1;
        }

        Encrypted {
            buffer,
            is_decrypted: (),
            _phantom: PhantomData,
        }
    }
}

impl<const KEY: u8, D, const N: usize> Encrypted<Xor<KEY, NoOp>, D, N> {
    pub const fn new(mut buffer: [u8; N]) -> Self {
        // since we cant use for loops in const context we must use a while loop
        let mut i = 0;
        while i < N {
            buffer[i] ^= KEY;
            i += 1;
        }

        Encrypted {
            buffer,
            is_decrypted: (),
            _phantom: PhantomData,
        }
    }
}

impl<const KEY: u8, D, const N: usize> Encrypted<Xor<KEY, ReEncrypt<KEY>>, D, N> {
    pub const fn new(mut buffer: [u8; N]) -> Self {
        // since we cant use for loops in const context we must use a while loop
        let mut i = 0;
        while i < N {
            buffer[i] ^= KEY;
            i += 1;
        }

        Encrypted {
            buffer: UnsafeCell::new(buffer),
            is_decrypted: AtomicBool::new(false),
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Aligned8, Aligned16, ByteArray, drop_strategy::Zeroize, xor::Xor};
    use core::mem::size_of;

    #[test]
    fn test_size() {
        // these are already aligned
        assert_eq!(16, size_of::<Encrypted<Xor<0xAA, Zeroize>, ByteArray, 16>>());
        assert_eq!(16, size_of::<Encrypted<Xor<0xAA, NoOp>, ByteArray, 16>>());
        // alright homies, atomicbool has alignment of 1
        // so in this case it will be 17 bytes weird innit?
        assert_eq!(17, size_of::<Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 16>>());

        // alignment tests
        assert_eq!(24, size_of::<Aligned8<Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 16>>>());
        assert_eq!(32, size_of::<Aligned16<Encrypted<Xor<0xAA, ReEncrypt<0xAA>>, ByteArray, 16>>>());
    }
}
