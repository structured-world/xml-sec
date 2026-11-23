//! Streaming decoder of the `XMLDSig` Base64 transform.

use structured_base64::{Base64Error, STANDARD};

#[cfg(test)]
mod tests;

/// Alphabet bytes are decoded in blocks of whole quanta; the same `STANDARD`
/// profile as the resident transform enforces padding. A decoded block spans a
/// whole digest block, so the digest hashes it in place.
const BASE64_BLOCK: usize = 8192;

/// RFC 2045 section 6.8: decoders ignore every byte outside the alphabet.
pub(crate) fn is_rfc2045_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

/// Where in the unfiltered input the strict decoder's failures fall.
///
/// The filter keeps only alphabet bytes and `=`, so a failure of the strict
/// decoder over its output can only be the first `=` (misplaced or excess
/// padding), the symbol before it (nonzero unused bits) or the input's end
/// (an incomplete quantum). Only those positions are kept, at O(1) per chunk.
#[derive(Default)]
pub(crate) struct Base64Origin {
    /// Input bytes seen, filtered or not.
    consumed: usize,
    /// Position of the last symbol before the first `=`.
    last_symbol: usize,
    /// Position of the first `=`.
    first_padding: Option<usize>,
}

impl Base64Origin {
    /// Account for the next `encoded` bytes of the unfiltered input.
    pub(crate) fn observe(&mut self, encoded: &[u8]) {
        let origin = self.consumed;
        // Bounded by the caller's input budget, which fits usize.
        self.consumed += encoded.len();
        if self.first_padding.is_some() {
            return;
        }
        let symbols = if encoded.contains(&b'=') {
            let padding = encoded
                .iter()
                .position(|byte| *byte == b'=')
                .unwrap_or(encoded.len());
            self.first_padding = Some(origin + padding);
            &encoded[..padding]
        } else {
            encoded
        };
        if let Some(last) = symbols
            .iter()
            .rposition(|byte| is_rfc2045_base64_byte(*byte))
        {
            self.last_symbol = origin + last;
        }
    }

    fn padded(&self) -> bool {
        self.first_padding.is_some()
    }

    /// `error` of the strict decoder over the filtered input, located in the
    /// unfiltered input.
    pub(crate) fn locate(&self, error: Base64Error) -> Base64Error {
        match error {
            Base64Error::InvalidByte(offset, byte) => {
                debug_assert!(byte == b'=' && self.first_padding.is_some());
                Base64Error::InvalidByte(self.first_padding.unwrap_or(offset), byte)
            }
            Base64Error::InvalidLastSymbol(_, byte) => {
                Base64Error::InvalidLastSymbol(self.last_symbol, byte)
            }
            Base64Error::InvalidLength(_) => Base64Error::InvalidLength(self.consumed),
            Base64Error::Invalid | Base64Error::OutputFull => error,
        }
    }
}

pub(crate) struct Base64Stream {
    block: [u8; BASE64_BLOCK],
    filled: usize,
    /// Alphabet bytes accepted so far: the length the resident decoder checks.
    accepted: usize,
    origin: Base64Origin,
    /// A failure of the strict decoder in filtered coordinates.
    failure: Option<Base64Error>,
}

impl Base64Stream {
    pub(crate) fn new() -> Self {
        Self {
            block: [0; BASE64_BLOCK],
            filled: 0,
            accepted: 0,
            origin: Base64Origin::default(),
            failure: None,
        }
    }

    /// Whether decoding still runs; a decoding error ends it.
    pub(crate) fn active(&self) -> bool {
        self.failure.is_none()
    }

    /// Decode `chunk` and hand each decoded block to `sink`. A decoding error
    /// is kept and stops decoding; later input only counts toward the length.
    pub(crate) fn feed<E>(
        &mut self,
        chunk: &[u8],
        sink: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut chunk = chunk;
        while !chunk.is_empty() {
            if self.origin.padded() || self.failure.is_some() {
                // Padding may complete the block without a flush, so this
                // path takes the whole rest rather than the block's free space.
                self.origin.observe(chunk);
                self.feed_after_end(chunk);
                return Ok(());
            }
            let run = chunk.len().min(BASE64_BLOCK - self.filled);
            let (head, tail) = chunk.split_at(run);
            chunk = tail;
            self.origin.observe(head);
            let start = self.filled;
            // Encoded runs hold only alphabet bytes, so they are copied whole.
            if head
                .iter()
                .fold(true, |clean, &byte| clean & is_rfc2045_base64_byte(byte))
            {
                self.block[start..start + run].copy_from_slice(head);
                self.filled += run;
            } else {
                // `run` fits the free space, so even the last write is in bounds.
                for &byte in head {
                    self.block[self.filled] = byte;
                    self.filled += usize::from(is_rfc2045_base64_byte(byte));
                }
            }
            // Bounded by the caller's input limit, which fits usize.
            self.accepted += self.filled - start;
            if self.filled == BASE64_BLOCK {
                self.flush(sink)?;
            }
        }
        Ok(())
    }

    /// Input after the first `=` or a failure: padding that completes the
    /// current quantum still reaches the block, a symbol or a new quantum of
    /// padding is the resident decoder's misplaced-padding error, and every
    /// byte counts toward the length it checks first.
    #[cold]
    fn feed_after_end(&mut self, head: &[u8]) {
        for &byte in head.iter().filter(|byte| is_rfc2045_base64_byte(**byte)) {
            let quantum_start = self.accepted.is_multiple_of(4);
            // Bounded by the caller's input limit, which fits usize.
            self.accepted += 1;
            if matches!(self.failure, Some(Base64Error::InvalidByte(..))) {
                continue;
            }
            if byte != b'=' || quantum_start {
                // The resident decoder meets the misplaced first `=` before
                // the unused bits of the symbol preceding it; the offset is
                // replaced by that `=` when located.
                self.failure = Some(Base64Error::InvalidByte(self.accepted, b'='));
                continue;
            }
            if self.failure.is_none() {
                // The block flushes at whole quanta, so it has room for the
                // padding that completes the current one.
                self.block[self.filled] = byte;
                self.filled += 1;
            }
        }
    }

    fn flush<E>(&mut self, sink: &mut impl FnMut(&[u8]) -> Result<(), E>) -> Result<(), E> {
        let mut decoded = [0_u8; BASE64_BLOCK / 4 * 3];
        let encoded = &self.block[..self.filled];
        self.filled = 0;
        // The output block holds every quantum of a full input block, so
        // `OutputFull` cannot occur.
        match STANDARD.decode_slice(encoded, &mut decoded) {
            Ok(written) => sink(&decoded[..written]),
            Err(error) => {
                self.failure = Some(error);
                Ok(())
            }
        }
    }

    /// Decode the final partial block and report the failure the resident
    /// `STANDARD` decoder gives for the whole filtered input, located in the
    /// unfiltered input.
    pub(crate) fn finish<E>(
        mut self,
        sink: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<Option<Base64Error>, E> {
        if self.failure.is_none() && self.filled > 0 {
            self.flush(sink)?;
        }
        // RFC 4648 section 4: the resident decoder refuses an incomplete final
        // quantum before it reads any symbol.
        if !self.accepted.is_multiple_of(4) {
            return Ok(Some(Base64Error::InvalidLength(self.origin.consumed)));
        }
        Ok(self.failure.map(|failure| self.origin.locate(failure)))
    }
}
