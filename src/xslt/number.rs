//! Allocation-free numeric boundaries for the `XPath` binary64 value space.

/// Project two exact binary64 limbs with a single rounded addition.
#[inline]
pub(crate) fn unsigned(value: u64) -> f64 {
    let bytes = value.to_le_bytes();
    let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let high = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

#[inline]
pub(crate) fn signed(value: i64) -> f64 {
    let magnitude = unsigned(value.unsigned_abs());
    if value < 0 { -magnitude } else { magnitude }
}

/// Round once, including discarded sticky bits below the binary64 significand.
pub(crate) fn wide_unsigned(value: u128) -> f64 {
    let precision = u128::BITS - value.leading_zeros();
    if precision <= 53 {
        return unsigned(u64::try_from(value).expect("53-bit integer fits u64"));
    }
    let discarded_bits = precision - 53;
    let mut significand =
        u64::try_from(value >> discarded_bits).expect("shifted binary64 significand fits u64");
    let discarded = value & ((1_u128 << discarded_bits) - 1);
    let halfway = 1_u128 << (discarded_bits - 1);
    // XPath 1.0 §3.5 uses IEEE binary64. Round nearest, ties to even,
    // without first rounding a high limb and losing a low-limb sticky bit.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#numbers
    if discarded > halfway || (discarded == halfway && significand & 1 != 0) {
        significand += 1;
    }
    let mut exponent = u64::from(precision) + 1022;
    if significand == 1 << 53 {
        significand >>= 1;
        exponent += 1;
    }
    f64::from_bits((exponent << 52) | (significand - (1 << 52)))
}

pub(crate) fn wide_signed(value: i128) -> f64 {
    let magnitude = wide_unsigned(value.unsigned_abs());
    if value < 0 { -magnitude } else { magnitude }
}

#[inline]
pub(crate) fn size(value: usize) -> f64 {
    unsigned(u64::try_from(value).expect("supported pointer widths are at most 64 bits"))
}

/// Rust numeric-cast semantics: truncate, saturate at the boundary, and map NaN to zero.
/// <https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast>
pub(crate) fn truncating_wide_unsigned(value: f64) -> u128 {
    let bits = value.to_bits();
    let exponent = (bits >> 52) & 0x7ff;
    let fraction = bits & ((1 << 52) - 1);
    if bits >> 63 != 0 || exponent < 1023 || (exponent == 0x7ff && fraction != 0) {
        return 0;
    }
    if exponent >= 1151 {
        return u128::MAX;
    }
    let significand = u128::from(fraction | (1 << 52));
    if exponent >= 1075 {
        significand << (exponent - 1075)
    } else {
        significand >> (1075 - exponent)
    }
}

pub(crate) fn truncating_wide_signed(value: f64) -> i128 {
    let magnitude = truncating_wide_unsigned(value.abs());
    if magnitude > i128::MAX.unsigned_abs() {
        return if value.is_sign_negative() {
            i128::MIN
        } else {
            i128::MAX
        };
    }
    let magnitude = i128::try_from(magnitude).expect("magnitude was bounded by i128::MAX");
    if value.is_sign_negative() {
        -magnitude
    } else {
        magnitude
    }
}

pub(crate) fn truncating_signed(value: f64) -> i64 {
    let value = truncating_wide_signed(value).clamp(i128::from(i64::MIN), i128::from(i64::MAX));
    i64::try_from(value).expect("value was saturated to the i64 range")
}

pub(crate) fn truncating_unsigned(value: f64) -> u64 {
    let value = truncating_wide_unsigned(value).min(u128::from(u64::MAX));
    u64::try_from(value).expect("value was saturated to the u64 range")
}

pub(crate) fn truncating_byte(value: f64) -> u8 {
    let value = truncating_wide_unsigned(value).min(u128::from(u8::MAX));
    u8::try_from(value).expect("value was saturated to the u8 range")
}

pub(crate) fn truncating_size(value: f64) -> usize {
    let value = truncating_wide_unsigned(value).min(usize::MAX as u128);
    usize::try_from(value).expect("value was saturated to the usize range")
}

#[inline]
pub(crate) fn equal(left: f64, right: f64) -> bool {
    left.partial_cmp(&right) == Some(std::cmp::Ordering::Equal)
}

#[cfg(all(test, not(feature = "embedded")))]
mod tests;
