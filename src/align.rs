//! Alignment wrapper types for forcing specific memory alignment.
//!
//! This module provides newtype wrappers that force specific alignment
//! for the inner type. This is useful when you need to ensure that
//! encrypted data has a particular memory alignment.
//!
//! # Types
//!
//! - [`Aligned8`]: Forces 8-byte alignment
//! - [`Aligned16`]: Forces 16-byte alignment
//!
//! # Example
//!
//! ```rust
//! use const_secret::{
//!     align::Aligned16,
//!     Encrypted, ByteArray,
//!     drop_strategy::Zeroize,
//!     xor::Xor,
//! };
//!
//! // Ensure the encrypted data is 16-byte aligned
//! const SECRET: Aligned16<Encrypted<Xor<0xAA, Zeroize>, ByteArray, 16>> =
//!     Aligned16(Encrypted::<Xor<0xAA, Zeroize>, ByteArray, 16>::new([0u8; 16]));
//!
//! fn main() {
//!     // Access the inner encrypted data
//!     let _inner: &Encrypted<Xor<0xAA, Zeroize>, ByteArray, 16> = &SECRET.0;
//! }
//! ```

#[repr(align(8))]
#[derive(Debug)]
pub struct Aligned8<E>(pub E);

#[repr(align(16))]
#[derive(Debug)]
pub struct Aligned16<E>(pub E);
