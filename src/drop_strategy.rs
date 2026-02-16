//! Drop strategies for handling encrypted data when it goes out of scope.
//!
//! This module provides different strategies for what happens to decrypted data
//! when an [`Encrypted`](crate::Encrypted) value is dropped. Each strategy
//! implements the [`DropStrategy`] trait.
//!
//! # Available Strategies
//!
//! - [`Zeroize`]: Overwrites the buffer with zeros using the `zeroize` crate
//! - [`NoOp`]: Does nothing, leaving the data in memory as-is
//!
//! Algorithm-specific strategies:
//! - [`xor::ReEncrypt`](crate::xor::ReEncrypt): Re-encrypts with XOR
//! - [`rc4::ReEncrypt`](crate::rc4::ReEncrypt): Re-encrypts with RC4
//!
//! # Generic Over Extra Data
//!
//! These strategies are generic over the `Extra` type to support different
//! algorithms that may need to store additional data (like encryption keys).

use core::marker::PhantomData;
use zeroize::Zeroize as ZeroizeTrait;

pub trait DropStrategy {
    type Extra;
    fn drop(data: &mut [u8], extra: &Self::Extra);
}

/// Zeroizes the buffer on drop. Generic over the Extra type to work with any algorithm.
pub struct Zeroize<E = ()>(PhantomData<E>);
/// Does nothing on drop. Generic over the Extra type to work with any algorithm.
pub struct NoOp<E = ()>(PhantomData<E>);

impl<E> DropStrategy for Zeroize<E> {
    type Extra = E;
    fn drop(data: &mut [u8], _extra: &E) {
        data.zeroize();
    }
}

impl<E> DropStrategy for NoOp<E> {
    type Extra = E;
    fn drop(_data: &mut [u8], _extra: &E) {}
}
