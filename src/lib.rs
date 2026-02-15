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

pub mod drop_strategy;
pub mod xor;

use crate::drop_strategy::DropStrategy;
use core::{fmt::Debug, marker::PhantomData};

pub trait Algorithm {
    type Buffer<const N: usize>: Debug;
    type IsDecrypted: Debug;
    type Drop: DropStrategy;
}

pub trait GetMutBuffer {
    fn buffer_mut(&mut self) -> &mut [u8];
}

pub struct StringLiteral;
pub struct ByteArray;

#[derive(Debug)]
pub struct Encrypted<A: Algorithm, D, const N: usize>
where
    Self: GetMutBuffer,
{
    buffer: A::Buffer<N>,
    is_decrypted: A::IsDecrypted,
    _phantom: PhantomData<D>,
}

impl<A: Algorithm, D, const N: usize> Drop for Encrypted<A, D, N>
where
    Self: GetMutBuffer,
{
    fn drop(&mut self) {
        let data_ref = self.buffer_mut();
        A::Drop::drop(data_ref);
    }
}

#[repr(align(8))]
#[derive(Debug)]
pub struct Aligned8<E>(E);

#[repr(align(16))]
#[derive(Debug)]
pub struct Aligned16<E>(E);
