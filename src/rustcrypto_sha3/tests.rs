use super::{Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512};

fn decode(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("NIST ASCII hex"), 16)
                .expect("NIST hexadecimal octet")
        })
        .collect()
}

pub(crate) fn check_nist_messages(
    width: usize,
    rate: usize,
    mut verify: impl FnMut(&[u8], usize, &[u8]),
) {
    let source = match width {
        224 => include_str!("testdata/SHA3_224ShortMsg.rsp"),
        256 => include_str!("testdata/SHA3_256ShortMsg.rsp"),
        384 => include_str!("testdata/SHA3_384ShortMsg.rsp"),
        512 => include_str!("testdata/SHA3_512ShortMsg.rsp"),
        _ => panic!("invalid SHA-3 vector width"),
    };
    let mut bits = 0;
    let mut message = Vec::new();
    let mut count = 0;
    for line in source.lines() {
        if let Some(value) = line.strip_prefix("Len = ") {
            bits = value.parse::<usize>().expect("NIST decimal bit length");
        } else if let Some(value) = line.strip_prefix("Msg = ") {
            message = decode(value);
        } else if let Some(value) = line.strip_prefix("MD = ") {
            verify(&message, bits, &decode(value));
            count += 1;
        }
    }
    assert_eq!(count, rate * 8 + 1);
}

#[test]
fn bit_tail_matches_every_nist_short_message() {
    // CAVS 19.0 bit-oriented ShortMsg, every length through one rate block.
    // Independent hashes catch domain/padding crossing and partial-bit order.
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
    macro_rules! check {
        ($hash:ty, $width:literal, $rate:expr) => {{
            check_nist_messages($width, $rate, |message, bits, expected| {
                let mut hash = <$hash>::new();
                hash.update(&message[..bits / 8]);
                let tail = if bits % 8 == 0 { 0 } else { message[bits / 8] };
                assert_eq!(
                    hash.finalize_with_bits(tail, (bits % 8) as u8)
                        .expect("canonical NIST tail")
                        .as_slice(),
                    expected,
                    "SHA3-{} Len={bits}",
                    $width
                );
            });
        }};
    }
    check!(Sha3_224, 224, 144);
    check!(Sha3_256, 256, 136);
    check!(Sha3_384, 384, 104);
    check!(Sha3_512, 512, 72);
}

#[test]
fn bit_tail_api_preserves_byte_hashes_and_rejects_noncanonical_tails() {
    // The patch must not change byte-oriented hashing, OIDs or domain suffixes.
    // Empty tails must match the independent unmodified upstream digest API.
    macro_rules! check {
        ($ours:ty, $upstream:ty, $rate:expr) => {
            for length in [0, 1, $rate - 1, $rate, $rate + 1, 2 * $rate + 7] {
                let message = vec![0xa5; length];
                let mut hash = <$ours>::new();
                hash.update(&message);
                assert_eq!(
                    hash.finalize_with_bits(0, 0)
                        .expect("empty bit tail")
                        .as_slice(),
                    <$upstream>::digest(&message).as_slice()
                );
            }
            assert!(<$ours>::new().finalize_with_bits(1, 0).is_err());
            assert!(<$ours>::new().finalize_with_bits(2, 1).is_err());
            assert!(<$ours>::new().finalize_with_bits(0, 8).is_err());
            assert!(<$ours>::new().finalize_with_bits(0, 255).is_err());
        };
    }
    check!(Sha3_224, sha3::Sha3_224, 144);
    check!(Sha3_256, sha3::Sha3_256, 136);
    check!(Sha3_384, sha3::Sha3_384, 104);
    check!(Sha3_512, sha3::Sha3_512, 72);
}
