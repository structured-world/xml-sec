//! RustCrypto sha3 0.12.0, embedded to preserve the local bit-tail API in
//! published packages. Changes and provenance: docs/sha3-patch.md.

pub use sha2::digest::{self, Digest};

use core::fmt;
use digest::{
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
    common::{
        AlgorithmName, BlockSizeUser,
        hazmat::{DeserializeStateError, SerializableState, SerializedState},
    },
    consts::{U28, U32, U48, U64, U72, U104, U136, U144, U201},
    typenum::Unsigned,
};
use keccak::{Keccak, State1600};

mod oids;
#[cfg(test)]
pub(crate) mod tests;
mod utils;

/// The final byte contains unused high bits or is not a partial octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(feature = "xmlenc", test))]
pub struct InvalidBitTail;

#[cfg(any(feature = "xmlenc", test))]
impl fmt::Display for InvalidBitTail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid SHA-3 final bit string")
    }
}

#[cfg(any(feature = "xmlenc", test))]
impl core::error::Error for InvalidBitTail {}

macro_rules! impl_sha3_variants {
    ($(
        $(#[$attr:meta])*
        $name:ident($rate_ty:ty, $out_len:ty, $pad:expr);
    )*) => {$(
        $(#[$attr])*
        #[derive(Clone, Default)]
        pub struct $name {
            state: State1600,
            cursor: sponge_cursor::SpongeCursor<{ <$rate_ty>::USIZE }>,
            keccak: Keccak,
        }

        #[cfg(any(feature = "xmlenc", test))]
        impl $name {
            /// Finalize with zero to seven additional message bits, stored in
            /// the low bits of `tail`, least-significant bit first. All unused
            /// high bits must be zero. Complete octets use `update` as usual.
            pub fn finalize_with_bits(
                mut self,
                tail: u8,
                bit_len: u8,
            ) -> Result<Output<Self>, InvalidBitTail> {
                if bit_len > 7 || tail >> bit_len != 0 {
                    return Err(InvalidBitTail);
                }
                if bit_len == 0 {
                    return Ok(Digest::finalize(self));
                }
                let mut output = Output::<Self>::default();
                self.keccak.with_f1600(|f1600| {
                    utils::pad_bits::<$pad, { <$rate_ty>::USIZE }>(
                        &mut self.state,
                        self.cursor.pos(),
                        tail,
                        bit_len,
                        f1600,
                    );
                    f1600(&mut self.state);
                    utils::read_state(&self.state, &mut output);
                });
                Ok(output)
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.state = Default::default();
                self.cursor = Default::default();
            }
        }

        impl HashMarker for $name {}

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.keccak.with_f1600(|f1600| {
                    self.cursor.absorb_u64_le(&mut self.state, f1600, data);
                });
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = $rate_ty;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $out_len;
        }

        impl FixedOutput for $name {
            fn finalize_into(mut self, dst: &mut Output<Self>) {
                utils::pad::<$pad, { <$rate_ty>::USIZE }>(&mut self.state, &self.cursor);
                self.keccak.with_f1600(|f1600| {
                    f1600(&mut self.state);
                    utils::read_state(&mut self.state, dst);
                });
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, dst: &mut Output<Self>) {
                utils::pad::<$pad, { <$rate_ty>::USIZE }>(&mut self.state, &self.cursor);
                self.keccak.with_f1600(|f1600| {
                    f1600(&mut self.state);
                    utils::read_state(&mut self.state, dst);
                });
                Reset::reset(self);
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl SerializableState for $name {
            type SerializedStateSize = U201;

            fn serialize(&self) -> SerializedState<Self> {
                utils::serialize(&self.state, &self.cursor).into()
            }

            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                utils::deserialize(serialized_state.into())
                    .ok_or(DeserializeStateError)
                    .map(|(state, cursor)| Self {
                        state,
                        cursor,
                        keccak: Keccak::new(),
                    })
            }
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl Drop for $name {
            #[inline]
            fn drop(&mut self) {
                {
                    use digest::zeroize::Zeroize;
                    self.state.zeroize();
                    self.cursor.zeroize();
                }
            }
        }

        impl digest::zeroize::ZeroizeOnDrop for $name {}
    )*};
}

const SHA3_PAD: u8 = 0x06;

impl_sha3_variants!(
    /// SHA-3-224 hasher.
    Sha3_224(U144, U28, SHA3_PAD);
    /// SHA-3-256 hasher.
    Sha3_256(U136, U32, SHA3_PAD);
    /// SHA-3-384 hasher.
    Sha3_384(U104, U48, SHA3_PAD);
    /// SHA-3-256 hasher.
    Sha3_512(U72, U64, SHA3_PAD);

);
