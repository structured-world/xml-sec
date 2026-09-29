//! Backend-neutral XML byte encoding detection and strict transcoding.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

#[path = "../../../src/xml_input/shared.rs"]
mod shared;

pub use shared::*;
