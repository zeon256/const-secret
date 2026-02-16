//! A `no_std` crate for compile-time encrypted secrets.
//!
//! This crate provides encrypted storage for sensitive data that is encrypted at compile time
//! and only decrypted at runtime when accessed. This prevents secrets from appearing in
//! plaintext in the final binary.
//!
//! # Features
//!
//! - **Compile-time encryption**: Secrets are encrypted during compilation
//! - **Multiple algorithms**: XOR (simple, fast) and RC4 (stream cipher)
//! - **Drop strategies**: Control what happens to decrypted data on drop:
//!   - `Zeroize`: Overwrites memory with zeros
//!   - `ReEncrypt`: Re-encrypts the data
//!   - `NoOp`: Leaves data unchanged
//! - **Thread-safe**: `Sync` implementation allows concurrent access
//! - `no_std` compatible: Works in embedded environments
//!
//! # Examples
//!
//! ## XOR Algorithm
//!
//! XOR is the simplest and fastest algorithm. It uses a single-byte key:
//!
//! ```rust
//! use const_secret::{
//!     Encrypted, StringLiteral,
//!     drop_strategy::Zeroize,
//!     xor::{ReEncrypt, Xor},
//! };
//!
//! // Zeroize on drop (safest - clears memory)
//! const SECRET_ZEROIZE: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
//!     Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");
//!
//! // Re-encrypt on drop (good for frequently accessed secrets)
//! const SECRET_REENCRYPT: Encrypted<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 6> =
//!     Encrypted::<Xor<0xBB, ReEncrypt<0xBB>>, StringLiteral, 6>::new(*b"secret");
//!
//! // No-op on drop (fastest, but leaves data in memory)
//! const SECRET_NOOP: Encrypted<Xor<0xCC, Zeroize>, StringLiteral, 4> =
//!     Encrypted::<Xor<0xCC, Zeroize>, StringLiteral, 4>::new(*b"test");
//! ```
//!
//! ## RC4 Algorithm
//!
//! RC4 is a stream cipher with variable-length keys (1-256 bytes).
//! **Note:** RC4 is cryptographically broken; use only for basic obfuscation:
//!
//! ```rust
//! use const_secret::{
//!     Encrypted, StringLiteral, ByteArray,
//!     drop_strategy::Zeroize,
//!     rc4::{ReEncrypt, Rc4},
//! };
//!
//! const KEY: [u8; 16] = *b"my-secret-key-16";
//!
//! // RC4 with zeroize drop strategy
//! const RC4_SECRET: Encrypted<Rc4<16, Zeroize<[u8; 16]>>, StringLiteral, 6> =
//!     Encrypted::<Rc4<16, Zeroize<[u8; 16]>>, StringLiteral, 6>::new(*b"rc4sec", KEY);
//!
//! // RC4 with re-encrypt drop strategy
//! const RC4_REENCRYPT: Encrypted<Rc4<16, ReEncrypt<16>>, StringLiteral, 8> =
//!     Encrypted::<Rc4<16, ReEncrypt<16>>, StringLiteral, 8>::new(*b"rc4data!", KEY);
//! ```
//!
//! ## Usage Modes
//!
//! ### `StringLiteral` Mode
//!
//! For UTF-8 string data. Returns `&str` on dereference:
//!
//! ```rust
//! use const_secret::{
//!     Encrypted, StringLiteral,
//!     drop_strategy::Zeroize,
//!     xor::Xor,
//! };
//!
//! const API_KEY: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 34> =
//!     Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 34>::new(
//!         *b"sk-live-1234567890abcdefghijklmnop"
//!     );
//!
//! fn main() {
//!     let key: &str = &*API_KEY;
//!     assert_eq!(key, "sk-live-1234567890abcdefghijklmnop");
//! }
//! ```
//!
//! ### `ByteArray` Mode
//!
//! For binary data. Returns `&[u8; N]` on dereference:
//!
//! ```rust
//! use const_secret::{
//!     Encrypted, ByteArray,
//!     drop_strategy::Zeroize,
//!     xor::Xor,
//! };
//!
//! const BINARY_SECRET: Encrypted<Xor<0xBB, Zeroize>, ByteArray, 16> =
//!     Encrypted::<Xor<0xBB, Zeroize>, ByteArray, 16>::new([
//!         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
//!         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
//!     ]);
//!
//! fn main() {
//!     let data: &[u8; 16] = &*BINARY_SECRET;
//!     assert_eq!(data[0], 0x01);
//! }
//! ```
//!
//! ## Choosing an Algorithm
//!
//! | Algorithm | Speed | Security | Use Case |
//! |-----------|-------|----------|----------|
//! | XOR       | Fast  | Basic    | Simple obfuscation, speed critical |
//! | RC4       | Medium| Broken   | Variable key length, slightly better obfuscation |
//!
//! ## Drop Strategies
//!
//! | Strategy   | Behavior on Drop | Best For |
//! |------------|------------------|----------|
//! | `Zeroize`  | Overwrites with zeros | Maximum security |
//! | `ReEncrypt`| Re-encrypts data | If you prefer the residue to remain encrypted after using |
//! | `NoOp`     | Leaves unchanged | Performance critical, non-sensitive |
//!
//! # Architecture
//!
//! The crate uses a type-level architecture:
//! - [`Algorithm`]: Trait defining encryption algorithm and associated data
//! - [`Encrypted<A, M, N>`]: Main struct holding encrypted data
//! - [`DropStrategy`]: Trait for handling drop behavior
//! - Mode markers: [`StringLiteral`] and [`ByteArray`]

#![no_std]
#![cfg_attr(not(debug_assertions), deny(warnings))]
#![warn(
    clippy::all,
    clippy::await_holding_lock,
    clippy::char_lit_as_u8,
    clippy::checked_conversions,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::doc_markdown,
    clippy::empty_enums,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::expl_impl_clone_on_copy,
    clippy::explicit_deref_methods,
    clippy::explicit_into_iter_loop,
    clippy::fallible_impl_from,
    clippy::filter_map_next,
    clippy::float_cmp_const,
    clippy::fn_params_excessive_bools,
    clippy::if_let_mutex,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::invalid_upcast_comparisons,
    clippy::large_types_passed_by_value,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::manual_ok_or,
    clippy::map_flatten,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    unexpected_cfgs,
    clippy::missing_errors_doc,
    clippy::missing_safety_doc,
    clippy::mut_mut,
    clippy::mutex_integer,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::needless_pass_by_value,
    clippy::option_option,
    clippy::path_buf_push_overwrite,
    clippy::ptr_as_ptr,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_functions_in_if_condition,
    clippy::string_add_assign,
    clippy::string_add,
    clippy::string_lit_as_bytes,
    clippy::todo,
    clippy::trait_duplication_in_bounds,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::useless_transmute,
    clippy::verbose_file_reads,
    clippy::zero_sized_map_values,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
extern crate alloc;

pub mod align;
pub mod drop_strategy;
pub mod rc4;
pub mod xor;

use crate::drop_strategy::DropStrategy;
use core::{cell::UnsafeCell, fmt, marker::PhantomData, sync::atomic::AtomicBool};

/// A trait that defines an encryption algorithm and its associated types.
///
/// This trait is implemented by algorithm types (like [`xor::Xor`]
/// and [`rc4::Rc4`]) to specify:
/// - The drop strategy to use when the encrypted data is dropped
/// - The extra data type that the algorithm needs to store alongside the buffer
///
/// The `Extra` associated type allows algorithms to store additional data
/// (like encryption keys for RC4) within the [`Encrypted`] struct.
pub trait Algorithm {
    /// The drop strategy to use when the encrypted data is dropped.
    type Drop: DropStrategy<Extra = Self::Extra>;
    /// Additional data stored alongside the encrypted buffer.
    ///
    /// For XOR this is `()` (no extra data needed), for RC4 this is the key array.
    type Extra;
}

/// Mode marker type indicating the encrypted data should be treated as a UTF-8 string literal.
///
/// When used as the `M` type parameter of [`Encrypted<A, M, N>`], dereferencing
/// returns `&str` instead of `&[u8; N]`.
///
/// # Safety
///
/// The original plaintext must be valid UTF-8. The encryption algorithm must
/// preserve the byte values such that decryption produces valid UTF-8.
pub struct StringLiteral;

/// Mode marker type indicating the encrypted data should be treated as a byte array.
///
/// When used as the `M` type parameter of [`Encrypted<A, M, N>`], dereferencing
/// returns `&[u8; N]` (a reference to the raw byte array).
pub struct ByteArray;

/// An encrypted container that holds data encrypted at compile time.
///
/// This struct stores encrypted data that is decrypted on first access via
/// the [`Deref`](core::ops::Deref) implementation. The decryption happens
/// exactly once, after which the plaintext is cached for subsequent accesses.
///
/// # Type Parameters
///
/// - `A`: The encryption algorithm type implementing [`Algorithm`]
/// - `M`: The mode marker type ([`StringLiteral`] or [`ByteArray`])
/// - `N`: The size of the encrypted buffer in bytes
///
/// # Thread Safety
///
/// The struct is `Sync`, allowing concurrent access from multiple threads.
/// The first thread to access the data performs the decryption; subsequent
/// accesses read the already-decrypted buffer.
///
/// # Drop Behavior
///
/// When dropped, the data is handled according to the algorithm's
/// [`DropStrategy`]:
/// - [`Zeroize`](crate::drop_strategy::Zeroize): Overwrites with zeros
/// - [`ReEncrypt`](crate::xor::ReEncrypt) / [`ReEncrypt`](crate::rc4::ReEncrypt): Re-encrypts
/// - [`NoOp`](crate::drop_strategy::NoOp): Leaves data unchanged
///
/// # Example
///
/// ```rust
/// use const_secret::{
///     Encrypted, StringLiteral,
///     drop_strategy::Zeroize,
///     xor::Xor,
/// };
///
/// const SECRET: Encrypted<Xor<0xAA, Zeroize>, StringLiteral, 5> =
///     Encrypted::<Xor<0xAA, Zeroize>, StringLiteral, 5>::new(*b"hello");
///
/// fn main() {
///     // Decrypts on first access
///     let decrypted: &str = &*SECRET;
///     assert_eq!(decrypted, "hello");
/// }
/// ```
pub struct Encrypted<A: Algorithm, M, const N: usize> {
    /// The encrypted/decrypted data buffer.
    ///
    /// Uses [`UnsafeCell`] for interior mutability to allow decryption on first access.
    buffer: UnsafeCell<[u8; N]>,
    /// Flag indicating whether the buffer has been decrypted.
    ///
    /// Uses atomic operations to ensure thread-safe one-time decryption.
    is_decrypted: AtomicBool,
    /// Algorithm-specific extra data (e.g., the encryption key for RC4).
    extra: A::Extra,
    /// Phantom marker to carry the algorithm and mode type information.
    _phantom: PhantomData<(A, M)>,
}

impl<A: Algorithm, M, const N: usize> fmt::Debug for Encrypted<A, M, N> {
    /// Formats the `Encrypted` struct for debugging.
    ///
    /// Note that the actual buffer contents are not displayed for security reasons.
    /// Only the `is_decrypted` flag is shown. The output uses `finish_non_exhaustive()`
    /// to indicate there are additional fields not shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypted")
            .field("is_decrypted", &self.is_decrypted)
            .finish_non_exhaustive()
    }
}

impl<A: Algorithm, M, const N: usize> Drop for Encrypted<A, M, N> {
    /// Handles the encrypted data when the struct is dropped.
    ///
    /// Applies the algorithm's [`DropStrategy`]
    /// to the buffer. This may zeroize, re-encrypt, or leave the data unchanged
    /// depending on the configured strategy.
    fn drop(&mut self) {
        // SAFETY: `buffer` is initialized and exclusively borrowed through `&mut self`.
        let data_ref = unsafe { &mut *self.buffer.get() };
        A::Drop::drop(data_ref, &self.extra);
    }
}

// SAFETY: `Encrypted` is `Sync` because:
// 1. The `AtomicBool` ensures only one thread can transition `is_decrypted` from false to true
//    via `compare_exchange`, providing exclusive access to the mutation.
// 2. After the first successful deref, `is_decrypted` is true and the buffer never mutates again.
// 3. Multiple threads can safely read the stable, decrypted buffer concurrently.
// 4. The buffer is only mutated during initialization (const) and the first deref (once per value).
unsafe impl<A: Algorithm, M, const N: usize> Sync for Encrypted<A, M, N>
where
    A: Sync,
    A::Extra: Sync,
    M: Sync,
{
}
