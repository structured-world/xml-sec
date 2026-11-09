//! Streaming codecs with resumable state.
//!
//! [`Base64Codec`] encodes or decodes Base64 (RFC 4648 section 4 alphabet)
//! in pieces of any size: encoding breaks lines after a fixed number of
//! characters and pads with `=`, decoding skips white space and refuses any
//! other character outside the alphabet, a misplaced `=`, data after the
//! padding and a truncated group. These are the rules of libxmlsec1's codec,
//! which the libxmlsec1-compatible library exposes through its C API.

#[cfg(test)]
mod tests;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Why a [`Base64Codec`] step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// A character outside the alphabet, a misplaced `=`, data after the
    /// padding, or a state no codec reaches by itself.
    Invalid,
    /// The output slice cannot take what the step writes.
    OutputFull,
    /// The decoded input ended inside a group of four characters.
    Truncated,
}

/// The resumable state of one Base64 encoding or decoding stream.
///
/// The fields are plain data so that a caller keeping the state in memory of
/// its own (a C structure, for example) can store and restore it between
/// steps; a state no codec produces fails the next step with
/// [`Base64Error::Invalid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64Codec {
    /// Encodes when set, decodes otherwise.
    pub encode: bool,
    /// Characters per encoded line; 0 writes one line.
    pub columns: usize,
    /// The byte carried into the next output character.
    pub carry: u8,
    /// The position in the current group: 0 to 3.
    pub position: usize,
    /// Characters written on the current encoded line.
    pub line_position: usize,
    /// Set by padding while decoding, and once the final group is begun
    /// while encoding.
    pub finished: bool,
}

/// The outcome of one byte of the state machine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The input byte is used and an output byte written.
    ConsumeAndNext,
    /// An output byte is written; the same input byte is offered again.
    ConsumeAndRepeat,
    /// The input byte is used without output.
    Next,
    /// Nothing remains.
    Done,
    Failed,
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// The 6-bit value of a Base64 character, `None` for any other byte.
fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(26 + byte - b'a'),
        b'0'..=b'9' => Some(52 + byte - b'0'),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

impl Base64Codec {
    /// A fresh stream that encodes (with `columns` characters per line, 0
    /// for one line) or decodes.
    ///
    /// # Examples
    ///
    /// ```
    /// use xml_sec::codec::Base64Codec;
    ///
    /// let mut codec = Base64Codec::new(true, 4);
    /// let mut out = [0u8; 16];
    /// let written = codec.update(b"foobar", &mut out)?;
    /// let last = codec.finish(&mut out[written..])?;
    /// assert_eq!(&out[..written + last], b"Zm9v\nYmFy");
    /// # Ok::<(), xml_sec::codec::Base64Error>(())
    /// ```
    #[must_use]
    pub const fn new(encode: bool, columns: usize) -> Self {
        Self {
            encode,
            columns,
            carry: 0,
            position: 0,
            line_position: 0,
            finished: false,
        }
    }

    /// The output room that encoding `size` bytes with `columns` per line
    /// fits in, including a terminating byte; `None` when it overflows.
    #[must_use]
    pub fn encoded_capacity(columns: usize, size: usize) -> Option<usize> {
        let mut total = size.checked_mul(4)? / 3 + 4;
        if let Some(breaks) = total.checked_div(columns) {
            total = total.checked_add(breaks)?.checked_add(4)?;
        }
        total.checked_add(1)
    }

    /// The output room that decoding `size` characters fits in; `None` when
    /// it overflows.
    #[must_use]
    pub fn decoded_capacity(size: usize) -> Option<usize> {
        size.checked_mul(3).map(|bytes| bytes / 4 + 8)
    }

    /// Processes all of `input`; the bytes written to `output`.
    ///
    /// # Errors
    /// [`Base64Error::Invalid`] for input the decoder refuses or an invalid
    /// state, [`Base64Error::OutputFull`] when `output` cannot take the
    /// result. The state is then unspecified.
    ///
    /// # Examples
    ///
    /// ```
    /// use xml_sec::codec::{Base64Codec, Base64Error};
    ///
    /// let mut codec = Base64Codec::new(false, 0);
    /// let mut out = [0u8; 8];
    /// assert_eq!(codec.update(b" Zm 9v\n", &mut out), Ok(3));
    /// assert_eq!(&out[..3], b"foo");
    /// assert_eq!(Base64Codec::new(false, 0).update(b"Zg==Zg", &mut out), Err(Base64Error::Invalid));
    /// ```
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Base64Error> {
        let (read, written) = if self.encode {
            self.encode_all(input, output)?
        } else {
            self.decode_all(input, output)?
        };
        if read == input.len() {
            Ok(written)
        } else if self.encode || written == output.len() {
            Err(Base64Error::OutputFull)
        } else {
            // Decoding stopped before the input ended: data after padding.
            Err(Base64Error::Invalid)
        }
    }

    /// Ends the stream; the bytes written to `output` (the last encoded
    /// characters and padding, nothing when decoding).
    ///
    /// # Errors
    /// [`Base64Error::OutputFull`] when `output` is empty or cannot take the
    /// last characters, [`Base64Error::Truncated`] when decoding stopped
    /// inside a group, [`Base64Error::Invalid`] for an invalid state.
    pub fn finish(&mut self, output: &mut [u8]) -> Result<usize, Base64Error> {
        if output.is_empty() {
            return Err(Base64Error::OutputFull);
        }
        if !self.encode {
            return if self.position == 0 {
                Ok(0)
            } else {
                Err(Base64Error::Truncated)
            };
        }
        let mut written = 0;
        loop {
            if written == output.len() {
                return Err(Base64Error::OutputFull);
            }
            match self.encode_final_byte(&mut output[written]) {
                Step::ConsumeAndNext | Step::ConsumeAndRepeat => written += 1,
                Step::Done => return Ok(written),
                Step::Next | Step::Failed => return Err(Base64Error::Invalid),
            }
        }
    }

    fn encode_byte(&mut self, input: u8, output: &mut u8) -> Step {
        if self.columns > 0 && self.line_position >= self.columns {
            *output = b'\n';
            self.line_position = 0;
            return Step::ConsumeAndRepeat;
        }
        let previous = self.carry;
        let (value, next) = match self.position {
            0 => ((input >> 2) & 0x3f, Step::ConsumeAndNext),
            1 => (
                ((previous << 4) & 0x30) | ((input >> 4) & 0x0f),
                Step::ConsumeAndNext,
            ),
            2 => (
                ((previous << 2) & 0x3c) | ((input >> 6) & 0x03),
                Step::ConsumeAndRepeat,
            ),
            3 => (previous & 0x3f, Step::ConsumeAndNext),
            _ => return Step::Failed,
        };
        *output = ALPHABET[usize::from(value)];
        self.line_position += 1;
        if self.position == 3 {
            self.carry = 0;
            self.position = 0;
        } else {
            self.carry = input;
            self.position += 1;
        }
        next
    }

    fn encode_final_byte(&mut self, output: &mut u8) -> Step {
        if self.position == 0 {
            return Step::Done;
        }
        if self.columns > 0 && self.line_position >= self.columns {
            *output = b'\n';
            self.line_position = 0;
            return Step::ConsumeAndRepeat;
        }
        if !self.finished {
            self.finished = true;
            return self.encode_byte(0, output);
        }
        match self.position {
            1 | 2 => {
                *output = b'=';
                self.position += 1;
                self.line_position += 1;
                Step::ConsumeAndRepeat
            }
            3 => {
                *output = b'=';
                self.line_position += 1;
                self.position = 0;
                Step::ConsumeAndRepeat
            }
            _ => Step::Failed,
        }
    }

    fn decode_byte(&mut self, input: u8, output: &mut u8) -> Step {
        if self.finished && self.position == 0 {
            return Step::Done;
        }
        if input == b'=' {
            self.finished = true;
            return match self.position {
                2 => {
                    self.position += 1;
                    Step::Next
                }
                3 => {
                    self.position = 0;
                    Step::Next
                }
                _ => Step::Failed,
            };
        }
        if is_space(input) {
            return Step::Next;
        }
        let Some(value) = sextet(input).filter(|_| !self.finished) else {
            return Step::Failed;
        };
        let previous = self.carry;
        match self.position {
            0 => {
                self.carry = value;
                self.position += 1;
                Step::Next
            }
            1 => {
                *output = (previous << 2) | (value >> 4);
                self.carry = value;
                self.position += 1;
                Step::ConsumeAndNext
            }
            2 => {
                *output = (previous << 4) | (value >> 2);
                self.carry = value;
                self.position += 1;
                Step::ConsumeAndNext
            }
            3 => {
                *output = (previous << 6) | value;
                self.carry = 0;
                self.position = 0;
                Step::ConsumeAndNext
            }
            _ => Step::Failed,
        }
    }

    /// Encodes until the input or the output ends; the bytes read and written.
    fn encode_all(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), Base64Error> {
        let (mut read, mut written) = (0, 0);
        while read < input.len() && written < output.len() {
            match self.encode_byte(input[read], &mut output[written]) {
                Step::ConsumeAndNext => {
                    read += 1;
                    written += 1;
                }
                Step::ConsumeAndRepeat => written += 1,
                Step::Next | Step::Done | Step::Failed => return Err(Base64Error::Invalid),
            }
        }
        Ok((read, written))
    }

    /// Decodes until the input, the output or the stream ends, then skips
    /// trailing white space; the bytes read and written.
    fn decode_all(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), Base64Error> {
        let (mut read, mut written) = (0, 0);
        let mut step = Step::Next;
        while read < input.len() && written < output.len() && step != Step::Done {
            step = self.decode_byte(input[read], &mut output[written]);
            match step {
                Step::ConsumeAndNext => {
                    read += 1;
                    written += 1;
                }
                Step::ConsumeAndRepeat => written += 1,
                Step::Next => read += 1,
                Step::Done => {}
                Step::Failed => return Err(Base64Error::Invalid),
            }
        }
        while read < input.len() && is_space(input[read]) {
            read += 1;
        }
        Ok((read, written))
    }
}
