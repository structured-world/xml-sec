use super::*;

#[test]
fn integer_projection_rounds_binary64_ties_and_carries_once() {
    // Counts and EXSLT date components keep ties-to-even at each precision boundary.
    let cases: [(u64, f64); 7] = [
        (0, 0.0),
        (1, 1.0),
        (u64::from(u32::MAX), 4_294_967_295.0),
        ((1 << 53) - 1, 9_007_199_254_740_991.0),
        ((1 << 53) + 1, 9_007_199_254_740_992.0),
        ((1 << 53) + 3, 9_007_199_254_740_996.0),
        (u64::MAX, 18_446_744_073_709_551_616.0),
    ];
    for (input, expected) in cases {
        assert_eq!(unsigned(input).to_bits(), expected.to_bits());
        assert_eq!(
            wide_unsigned(u128::from(input)).to_bits(),
            expected.to_bits()
        );
    }
    assert_eq!(wide_unsigned(u128::MAX).to_bits(), 1151_u64 << 52);
    assert_eq!(
        wide_signed(i128::MIN).to_bits(),
        (1_u64 << 63) | (1150_u64 << 52)
    );
    assert_eq!(signed(i64::MIN).to_bits(), (1_u64 << 63) | (1086_u64 << 52));
    assert_eq!(size(0).to_bits(), 0);
    assert_eq!(size(1).to_bits(), 1.0_f64.to_bits());
}

#[test]
fn wide_projection_keeps_low_limb_sticky_bits() {
    // Adding independently rounded 64-bit limbs would round the first value down.
    let base = 1_u128 << 120;
    let half_ulp = 1_u128 << 67;
    assert_eq!(wide_unsigned(base + half_ulp).to_bits(), 1143_u64 << 52);
    assert_eq!(
        wide_unsigned(base + half_ulp + 1).to_bits(),
        (1143_u64 << 52) + 1
    );
    assert_eq!(
        wide_unsigned(base + 3 * half_ulp).to_bits(),
        (1143_u64 << 52) + 2
    );
}

#[test]
fn truncation_preserves_saturation_sign_and_nonfinite_behavior() {
    // This boundary intentionally reproduces Rust casts, not a new rejection policy.
    for input in [f64::NAN, -f64::NAN, 0.0, -0.0, 0.999, -0.999] {
        assert_eq!(truncating_wide_signed(input), 0);
        assert_eq!(truncating_wide_unsigned(input), 0);
    }
    assert_eq!(truncating_wide_signed(f64::INFINITY), i128::MAX);
    assert_eq!(truncating_wide_signed(f64::NEG_INFINITY), i128::MIN);
    assert_eq!(truncating_wide_unsigned(f64::INFINITY), u128::MAX);
    assert_eq!(truncating_wide_unsigned(f64::NEG_INFINITY), 0);
    assert_eq!(truncating_signed(-10.9), -10);
    assert_eq!(truncating_unsigned(10.9), 10);
    assert_eq!(truncating_signed(f64::INFINITY), i64::MAX);
    assert_eq!(truncating_signed(f64::NEG_INFINITY), i64::MIN);
    assert_eq!(truncating_unsigned(f64::INFINITY), u64::MAX);
    assert_eq!(truncating_byte(256.0), u8::MAX);
    assert_eq!(truncating_byte(-1.0), 0);
    assert_eq!(truncating_size(f64::INFINITY), usize::MAX);
    assert_eq!(truncating_size(12.9), 12);
}

#[test]
fn exact_equality_keeps_signed_zero_and_nan_semantics() {
    // XPath comparisons cannot use an epsilon, including adjacent representable numbers.
    assert!(equal(0.0, -0.0));
    assert!(!equal(f64::NAN, f64::NAN));
    assert!(!equal(1.0, 1.0_f64.next_up()));
    assert!(equal(f64::INFINITY, f64::INFINITY));
}
