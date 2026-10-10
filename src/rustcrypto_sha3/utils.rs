use keccak::State1600;
use sponge_cursor::SpongeCursor;

#[cfg(any(feature = "xmlenc", test))]
pub(crate) fn pad_bits<const PAD: u8, const RATE: usize>(
    state: &mut State1600,
    position: usize,
    tail: u8,
    bit_len: u8,
    mut permute: impl FnMut(&mut State1600),
) {
    // FIPS 202 §§5.1, 6.1 and Appendix B.1: SHA-3 appends the 01
    // domain followed by pad10*1. Octets are absorbed least-significant bit
    // first; domain/padding may cross the rate even when the message does not.
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    let value = u16::from(tail) | (u16::from(PAD) << bit_len);
    let count = u32::from(bit_len) + (8 - PAD.leading_zeros());
    let mut bit_position = position * 8;
    for shift in 0..count {
        state[bit_position / 64] ^= u64::from((value >> shift) & 1) << (bit_position % 64);
        bit_position += 1;
        if bit_position == RATE * 8 {
            permute(state);
            bit_position = 0;
        }
    }
    state[RATE / 8 - 1] ^= 1 << 63;
}

#[inline(always)]
pub(crate) fn pad<const PAD: u8, const RATE: usize>(
    state: &mut State1600,
    cursor: &SpongeCursor<RATE>,
) {
    let pos = cursor.pos();
    let word_offset = pos / 8;
    let byte_offset = pos % 8;

    let pad = u64::from(PAD) << (8 * byte_offset);
    state[word_offset] ^= pad;
    state[RATE / 8 - 1] ^= 1 << 63;
}

#[inline(always)]
pub(crate) fn read_state(state: &State1600, dst: &mut [u8]) {
    assert!(size_of_val(dst) <= size_of_val(state));

    let chunks = dst.chunks_mut(size_of::<u64>());
    for (src, dst) in state.iter().zip(chunks) {
        dst.copy_from_slice(&src.to_le_bytes()[..dst.len()]);
    }
}

#[inline(always)]
pub(crate) fn serialize<const RATE: usize>(
    state: &State1600,
    cursor: &SpongeCursor<RATE>,
) -> [u8; 201] {
    let mut ser_state = [0u8; 201];
    let [state_dst @ .., cursor_dst] = &mut ser_state;

    let (state_dst_chunks, remainder) = state_dst.as_chunks_mut::<8>();
    debug_assert!(remainder.is_empty());
    for (src, dst) in state.iter().zip(state_dst_chunks.iter_mut()) {
        dst.copy_from_slice(&src.to_le_bytes());
    }

    *cursor_dst = cursor.raw_pos();
    ser_state
}

#[inline(always)]
pub(crate) fn deserialize<const RATE: usize>(
    ser_state: &[u8; 201],
) -> Option<(State1600, SpongeCursor<RATE>)> {
    // TODO(MSRV-1.88): use `ser_state.as_chunks()`
    let [state_src @ .., cursor_src] = ser_state;

    let n = size_of::<u64>();
    let state = core::array::from_fn(|i| {
        let chunk = state_src[n * i..][..n]
            .try_into()
            .expect("chunk has correct length");
        u64::from_le_bytes(chunk)
    });

    let cursor = SpongeCursor::new(*cursor_src)?;
    Some((state, cursor))
}
