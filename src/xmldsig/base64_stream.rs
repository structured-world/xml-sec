//! Streaming decoder of the `XMLDSig` Base64 transform.

#[cfg(test)]
mod tests;

/// Alphabet bytes are decoded in blocks of whole quanta; the same `STANDARD`
/// engine as the resident transform enforces padding. A decoded block spans a
/// whole digest block, so the digest hashes it in place.
const BASE64_BLOCK: usize = 8192;

/// RFC 2045 section 6.8: decoders ignore every byte outside the alphabet.
pub(crate) fn is_rfc2045_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

pub(crate) struct Base64Stream {
    block: [u8; BASE64_BLOCK],
    filled: usize,
    /// Alphabet bytes accepted so far: the offset the resident decoder reports
    /// within its filtered input.
    offset: usize,
    /// Offset of the padding that ended the last decoded block.
    padding: Option<usize>,
    failure: Option<base64::DecodeError>,
}

impl Base64Stream {
    pub(crate) fn new() -> Self {
        Self {
            block: [0; BASE64_BLOCK],
            filled: 0,
            offset: 0,
            padding: None,
            failure: None,
        }
    }

    /// Whether decoding still runs; a decoding error ends it.
    pub(crate) fn active(&self) -> bool {
        self.failure.is_none()
    }

    /// Decode `chunk` and hand each decoded block to `sink`. A decoding error
    /// is kept and stops this stream only.
    pub(crate) fn feed<E>(
        &mut self,
        chunk: &[u8],
        sink: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if self.failure.is_some() {
            return Ok(());
        }
        let mut chunk = chunk;
        while !chunk.is_empty() {
            if let Some(padding) = self.padding {
                // Padding ended the encoded data in an earlier block; the
                // resident decoder reports its first byte when more follows.
                if chunk.iter().any(|byte| is_rfc2045_base64_byte(*byte)) {
                    self.failure = Some(base64::DecodeError::InvalidByte(padding, b'='));
                }
                return Ok(());
            }
            let run = chunk.len().min(BASE64_BLOCK - self.filled);
            let (head, tail) = chunk.split_at(run);
            chunk = tail;
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
            self.offset += self.filled - start;
            if self.filled == BASE64_BLOCK {
                self.flush(sink)?;
                if self.failure.is_some() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn flush<E>(&mut self, sink: &mut impl FnMut(&[u8]) -> Result<(), E>) -> Result<(), E> {
        use base64::Engine as _;

        let mut decoded = [0_u8; BASE64_BLOCK / 4 * 3];
        let encoded = &self.block[..self.filled];
        // The block holds the last `filled` accepted bytes.
        let base = self.offset - encoded.len();
        let padding = encoded
            .iter()
            .rev()
            .take_while(|byte| **byte == b'=')
            .count();
        self.padding = (padding > 0).then(|| self.offset - padding);
        self.filled = 0;
        match base64::engine::general_purpose::STANDARD.decode_slice(encoded, &mut decoded) {
            Ok(written) => sink(&decoded[..written]),
            Err(error) => {
                self.failure = Some(match error {
                    base64::DecodeSliceError::DecodeError(base64::DecodeError::InvalidByte(
                        index,
                        byte,
                    )) => base64::DecodeError::InvalidByte(base + index, byte),
                    base64::DecodeSliceError::DecodeError(
                        base64::DecodeError::InvalidLastSymbol {
                            offset,
                            symbol,
                            symbol_value,
                        },
                    ) => base64::DecodeError::InvalidLastSymbol {
                        offset: base + offset,
                        symbol,
                        symbol_value,
                    },
                    base64::DecodeSliceError::DecodeError(base64::DecodeError::InvalidLength(
                        length,
                    )) => base64::DecodeError::InvalidLength(base + length),
                    base64::DecodeSliceError::DecodeError(error) => error,
                    // The output block holds every quantum of a full input
                    // block, so its size cannot be the failure.
                    base64::DecodeSliceError::OutputSliceTooSmall => {
                        base64::DecodeError::InvalidLength(encoded.len())
                    }
                });
                Ok(())
            }
        }
    }

    /// Decode the final partial block; an incomplete quantum is the padding
    /// error the resident `STANDARD` decoder reports for the whole input.
    pub(crate) fn finish<E>(
        mut self,
        sink: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<Option<base64::DecodeError>, E> {
        if self.failure.is_none() && self.filled > 0 {
            self.flush(sink)?;
        }
        Ok(self.failure)
    }
}
