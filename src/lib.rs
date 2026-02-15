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

pub mod drop_strategy;
pub mod xor;

use crate::drop_strategy::DropStrategy;
use core::{cell::UnsafeCell, marker::PhantomData, sync::atomic::AtomicBool};

pub trait Algorithm {
    type Drop: DropStrategy;
}

pub struct StringLiteral;
pub struct ByteArray;

#[derive(Debug)]
pub struct Encrypted<A: Algorithm, M, const N: usize> {
    buffer: UnsafeCell<[u8; N]>,
    is_decrypted: AtomicBool,
    _phantom: PhantomData<(A, M)>,
}

impl<A: Algorithm, M, const N: usize> Drop for Encrypted<A, M, N> {
    fn drop(&mut self) {
        // SAFETY: `buffer` is initialized and exclusively borrowed through `&mut self`.
        let data_ref = unsafe { &mut *self.buffer.get() };
        A::Drop::drop(data_ref);
    }
}

// SAFETY: `Encrypted` is `Sync` because:
// 1. The `AtomicBool` ensures only one thread can transition `is_decrypted` from false to true
//    via `compare_exchange`, providing exclusive access to the XOR mutation.
// 2. After the first successful deref, `is_decrypted` is true and the buffer never mutates again.
// 3. Multiple threads can safely read the stable, decrypted buffer concurrently.
// 4. The buffer is only mutated during initialization (const) and the first deref (once per value).
unsafe impl<A: Algorithm, M, const N: usize> Sync for Encrypted<A, M, N>
where
    A: Sync,
    M: Sync,
{
}

#[repr(align(8))]
#[derive(Debug)]
pub struct Aligned8<E>(E);

#[repr(align(16))]
#[derive(Debug)]
pub struct Aligned16<E>(E);
