//! Destinations for canonical bytes.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::C14nError;

/// Receives canonical bytes in document order; an error stops serialization.
pub(crate) trait ByteSink {
    /// Accepts all of `bytes` or fails.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), C14nError>;
}

#[cfg(feature = "std")]
impl<W: std::io::Write + ?Sized> ByteSink for W {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), C14nError> {
        self.write_all(bytes).map_err(C14nError::Io)
    }
}

// With `std` the `io::Write` adapter above covers `Vec<u8>`.
#[cfg(not(feature = "std"))]
impl ByteSink for Vec<u8> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), C14nError> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}
