#![cfg_attr(all(target_arch = "bpf", not(test)), no_std)]
#![cfg_attr(all(target_arch = "bpf", not(test)), no_main)]
#![allow(static_mut_refs)]

#[cfg(target_arch = "bpf")]
mod program;

#[cfg(target_arch = "bpf")]
pub use program::*;

#[cfg(not(target_arch = "bpf"))]
fn main() {}
