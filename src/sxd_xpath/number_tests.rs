#[test]
fn size_projection_rounds_once_to_binary64() {
    // XPath counts use IEEE-754 Number, including ties-to-even above 2^53.
    // Fixed encodings also catch truncation and a carry into the next exponent.
    for (integer, bits) in [
        (0u64, 0u64),
        (1, 0x3ff0_0000_0000_0000),
        (0xffff_ffff, 0x41ef_ffff_ffe0_0000),
        (0x001f_ffff_ffff_ffff, 0x433f_ffff_ffff_ffff),
        (0x0020_0000_0000_0000, 0x4340_0000_0000_0000),
        (0x0020_0000_0000_0001, 0x4340_0000_0000_0000),
        (0x0020_0000_0000_0002, 0x4340_0000_0000_0001),
        (0x0020_0000_0000_0003, 0x4340_0000_0000_0002),
        (0x003f_ffff_ffff_ffff, 0x4350_0000_0000_0000),
        (0x8000_0000_0000_0400, 0x43e0_0000_0000_0000),
        (0x8000_0000_0000_0c00, 0x43e0_0000_0000_0002),
        (u64::MAX, 0x43f0_0000_0000_0000),
    ] {
        if let Ok(integer) = usize::try_from(integer) {
            assert_eq!(super::xpath_size_number(integer).to_bits(), bits);
        }
    }
    // The standard decimal parser supplies an independent rounding oracle.
    for integer in (0..65536).chain([usize::MAX, usize::MAX - 1]) {
        let expected = integer.to_string().parse::<f64>().expect("integer number");
        assert_eq!(
            super::xpath_size_number(integer).to_bits(),
            expected.to_bits()
        );
    }
}

#[test]
fn exact_numeric_equality_preserves_ieee_boundaries() {
    // Language equality must not merge adjacent numbers or make NaN
    // reflexive; signed zeros and equal infinities remain equal.
    for (left, right, expected) in [
        (0.0, -0.0, true),
        (f64::NAN, f64::NAN, false),
        (f64::NAN, 1.0, false),
        (1.0, f64::NAN, false),
        (f64::INFINITY, f64::INFINITY, true),
        (f64::NEG_INFINITY, f64::INFINITY, false),
        (0.0, f64::from_bits(1), false),
        (1.0, f64::from_bits(1.0_f64.to_bits() + 1), false),
        (-1.0, -1.0, true),
    ] {
        assert_eq!(super::same_xpath_number(left, right), expected);
    }
}
