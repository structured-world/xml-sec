//! Bit-oriented hash framing for XMLEnc ConcatKDF. Compression and initial
//! states come from RustCrypto; this adapter only supplies message padding.

use sha2::digest::{block_api::VariableOutputCore, common::hazmat::SerializableState};

use super::super::{ProviderError, ProviderInputError};
use crate::xmldsig::DigestAlgorithm;

pub(super) fn hash(
    algorithm: DigestAlgorithm,
    prefixes: &[&[u8]],
    tail: &[u8],
    bit_len: usize,
) -> Result<zeroize::Zeroizing<[u8; 64]>, ProviderError> {
    let total_bits = prefixes
        .iter()
        .map(|bytes| bytes.len() as u128 * 8)
        .sum::<u128>()
        + bit_len as u128;
    macro_rules! hash {
        ($initial:expr, $word:ty, $words:expr, $block:expr, $length:expr, $compress:path) => {{
            if $length == 8 && total_bits > u64::MAX as u128 {
                return Err(ProviderError::InvalidInput(
                    ProviderInputError::ConcatKdfParameters,
                ));
            }
            let initial = $initial.serialize();
            let mut state = zeroize::Zeroizing::new([0 as $word; $words]);
            for (word, bytes) in state
                .iter_mut()
                .zip(initial.chunks_exact(core::mem::size_of::<$word>()))
            {
                *word = <$word>::from_le_bytes(bytes.try_into().expect("RustCrypto state width"));
            }
            padded_blocks::<$block>(
                prefixes,
                tail,
                bit_len,
                &total_bits.to_be_bytes()[16 - $length..],
                |blocks| $compress(&mut state, blocks),
            );
            let mut output = zeroize::Zeroizing::new([0; 64]);
            for (bytes, word) in output
                .chunks_exact_mut(core::mem::size_of::<$word>())
                .zip(state.iter())
            {
                bytes.copy_from_slice(&word.to_be_bytes());
            }
            Ok(output)
        }};
    }
    macro_rules! sha3_hash {
        ($hash:ty) => {{
            use crate::rustcrypto_sha3::Digest as _;
            let mut hash = <$hash>::new();
            for prefix in prefixes {
                hash.update(prefix);
            }
            hash.update(&tail[..bit_len / 8]);
            let remainder = (bit_len % 8) as u8;
            // XMLEnc bit strings use significant high bits; the RustCrypto
            // bit-tail API uses FIPS 202 Appendix B.1's LSB-first encoding.
            // https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF
            // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
            let final_byte = if remainder == 0 {
                0
            } else {
                tail[bit_len / 8].reverse_bits()
            };
            let mut digest = hash
                .finalize_with_bits(final_byte, remainder)
                .map_err(|_| {
                    ProviderError::InvalidInput(ProviderInputError::ConcatKdfParameters)
                })?;
            let mut output = zeroize::Zeroizing::new([0; 64]);
            output[..digest.len()].copy_from_slice(&digest);
            zeroize::Zeroize::zeroize(&mut digest);
            Ok(output)
        }};
    }
    match algorithm {
        DigestAlgorithm::Sha3_224 => sha3_hash!(crate::rustcrypto_sha3::Sha3_224),
        DigestAlgorithm::Sha3_256 => sha3_hash!(crate::rustcrypto_sha3::Sha3_256),
        DigestAlgorithm::Sha3_384 => sha3_hash!(crate::rustcrypto_sha3::Sha3_384),
        DigestAlgorithm::Sha3_512 => sha3_hash!(crate::rustcrypto_sha3::Sha3_512),
        DigestAlgorithm::Sha1 => hash!(
            sha1::block_api::Sha1Core::default(),
            u32,
            5,
            64,
            8,
            sha1::block_api::compress
        ),
        DigestAlgorithm::Sha224 | DigestAlgorithm::Sha256 => hash!(
            sha2::block_api::Sha256VarCore::new(algorithm.output_len())
                .expect("SHA-2 output width"),
            u32,
            8,
            64,
            8,
            sha2::block_api::compress256
        ),
        DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512 => hash!(
            sha2::block_api::Sha512VarCore::new(algorithm.output_len())
                .expect("SHA-2 output width"),
            u64,
            8,
            128,
            16,
            sha2::block_api::compress512
        ),
        #[cfg(feature = "legacy-algorithms")]
        DigestAlgorithm::Md5 => legacy_hash::<md5::block_api::Md5Core>(
            prefixes,
            tail,
            bit_len,
            total_bits,
            algorithm.output_len(),
        ),
        #[cfg(feature = "legacy-algorithms")]
        DigestAlgorithm::Ripemd160 => legacy_hash::<ripemd::block_api::Ripemd160Core>(
            prefixes,
            tail,
            bit_len,
            total_bits,
            algorithm.output_len(),
        ),
    }
}

fn padded_blocks<const BLOCK: usize>(
    prefixes: &[&[u8]],
    tail: &[u8],
    bit_len: usize,
    length: &[u8],
    mut compress: impl FnMut(&[[u8; BLOCK]]),
) {
    let full_octets = bit_len / 8;
    let partial_bits = bit_len % 8;
    let mut buffer = zeroize::Zeroizing::new([0_u8; BLOCK]);
    let mut used = 0;
    for mut source in prefixes
        .iter()
        .copied()
        .chain(core::iter::once(&tail[..full_octets]))
    {
        while !source.is_empty() {
            if used == 0 && source.len() >= BLOCK {
                // Borrow aligned blocks; only cross-segment tails need copying.
                let (blocks, remainder) = source.as_chunks::<BLOCK>();
                compress(blocks);
                source = remainder;
                continue;
            }
            let count = source.len().min(BLOCK - used);
            buffer[used..used + count].copy_from_slice(&source[..count]);
            used += count;
            source = &source[count..];
            if used == BLOCK {
                compress(core::slice::from_ref(&*buffer));
                used = 0;
            }
        }
    }
    // FIPS 180-4 §5.1 / RFC 1321 §§2, 3.1: append the bit after the last
    // significant message bit, not after its storage octet. The length's
    // byte order is chosen by the hash, never by ConcatKDF's BE32 counter.
    // https://www.rfc-editor.org/rfc/rfc1321.html#section-3.1
    buffer[used] = if partial_bits == 0 {
        0x80
    } else {
        tail[full_octets] | (0x80 >> partial_bits)
    };
    used += 1;
    buffer[used..].fill(0);
    if used > BLOCK - length.len() {
        compress(core::slice::from_ref(&*buffer));
        buffer.fill(0);
    }
    buffer[BLOCK - length.len()..].copy_from_slice(length);
    compress(core::slice::from_ref(&*buffer));
}

#[cfg(feature = "legacy-algorithms")]
fn legacy_hash<C>(
    prefixes: &[&[u8]],
    tail: &[u8],
    bit_len: usize,
    total_bits: u128,
    width: usize,
) -> Result<zeroize::Zeroizing<[u8; 64]>, ProviderError>
where
    C: Default
        + sha2::digest::block_api::UpdateCore
        + sha2::digest::common::BlockSizeUser<BlockSize = sha2::digest::consts::U64>
        + SerializableState
        + zeroize::ZeroizeOnDrop,
{
    use sha2::digest::array::Array;
    let length = u64::try_from(total_bits)
        .map_err(|_| ProviderError::InvalidInput(ProviderInputError::ConcatKdfParameters))?
        .to_le_bytes();
    let mut core = C::default();
    padded_blocks::<64>(prefixes, tail, bit_len, &length, |blocks| {
        core.update_blocks(Array::cast_slice_from_core(blocks));
    });
    // RustCrypto's documented SerializableState starts with the chaining
    // value in little-endian order for both cores; no second finalization.
    let state = zeroize::Zeroizing::new(core.serialize());
    let mut output = zeroize::Zeroizing::new([0; 64]);
    output[..width].copy_from_slice(&state[..width]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(
            remainder.is_empty(),
            "NIST vector must contain complete octets"
        );
        pairs
            .iter()
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex vector"), 16)
                    .expect("valid NIST hexadecimal octet")
            })
            .collect()
    }

    #[test]
    fn sha3_xml_bit_order_and_borrowed_prefixes_match_every_nist_message() {
        // Independent NIST digests verify the XML adapter as well as the
        // patched finalizer: only the partial octet changes bit convention.
        // Split borrowed prefixes at several positions to catch lost tails.
        for (algorithm, width, rate) in [
            (DigestAlgorithm::Sha3_224, 224, 144),
            (DigestAlgorithm::Sha3_256, 256, 136),
            (DigestAlgorithm::Sha3_384, 384, 104),
            (DigestAlgorithm::Sha3_512, 512, 72),
        ] {
            crate::rustcrypto_sha3::tests::check_nist_messages(
                width,
                rate,
                |message, bits, expected| {
                    let mut xml = message[..bits.div_ceil(8)].to_vec();
                    if bits % 8 != 0 {
                        xml[bits / 8] = xml[bits / 8].reverse_bits();
                    }
                    for split in [0, (bits / 8).min(1), (bits / 8).min(31), bits / 8] {
                        let actual =
                            hash(algorithm, &[&xml[..split]], &xml[split..], bits - split * 8)
                                .expect("valid XML bit string");
                        assert_eq!(
                            &actual[..algorithm.output_len()],
                            expected,
                            "{algorithm:?}/{bits}/{split}"
                        );
                    }
                },
            );
        }
    }

    #[test]
    fn bit_padding_matches_nist_shavs_one_bit_vectors() {
        // CAVS 11.0 bit-oriented ShortMsg Len=1 vectors, retrieved from NIST.
        // These catch rounding the message length to eight bits for every SHA
        // initial state/output width; RustCrypto's byte APIs cannot test this.
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabittestvectors.zip
        for (algorithm, message, expected) in [
            (
                DigestAlgorithm::Sha1,
                0x00,
                "bb6b3e18f0115b57925241676f5b1ae88747b08a",
            ),
            (
                DigestAlgorithm::Sha224,
                0x80,
                "0d05096bca2a4a77a2b47a05a59618d01174b37892376135c1b6e957",
            ),
            (
                DigestAlgorithm::Sha256,
                0x00,
                "bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375",
            ),
            (
                DigestAlgorithm::Sha384,
                0x00,
                "634aa63038a164ae6c7d48b319f2aca0a107908e548519204c6d72dbeac0fdc3c9246674f98e8fd30221ba986e737d61",
            ),
            (
                DigestAlgorithm::Sha512,
                0x00,
                "b4594eb12959fc2e6979b6783554299cc0369f44083a8b0955baefd8830cda22894b0b46c0ed49490e391ad99af856cc1bd96f238c7f2a17cf37aeb7e793395a",
            ),
        ] {
            let expected = hex(expected);
            let actual = hash(algorithm, &[], &[message], 1).expect("valid one-bit NIST message");
            assert_eq!(&actual[..algorithm.output_len()], expected, "{algorithm:?}");
        }
    }

    #[test]
    fn bit_padding_and_segment_boundaries_match_nist_shavs() {
        // The last message bit fits immediately before the length field, or
        // forces an extra padding block. Splitting the prefix must not affect
        // the digest; exercise the exact 64- and 128-byte hash boundaries.
        for (algorithm, bit_len, message, expected) in [
            (
                DigestAlgorithm::Sha256,
                447,
                "86f15b8b677b7655f358a2c7fd5785bc84d31e079ed859b6af88e198debd36fccaf0ffbc785aa17a9158102aca14e6d0a362b28b54e892d2",
                "eaec4af4f0632711ae6d78bcadb50eb53aee0d2e65c906cd903349750ea71c92",
            ),
            (
                DigestAlgorithm::Sha256,
                448,
                "3488a0d1c0998edf4c16f35f0293e1a73134bc20efc2f8f702fd241501342852b614cbe5c7be781f951c415a6574242cbe3d8de011321d26",
                "75fd02880ba7d64381f6391811ec64c6852e9f579f11e47f097438089d7ed905",
            ),
            (
                DigestAlgorithm::Sha512,
                895,
                "ea08fbebb5bce55e0be90e187df11db48a63355b09d07738c7dbc92b7090d6c2b3f75665a1e890d056201dc7dc95ee044c07917536d8afa4431dda7719f585197f1a5438c2b5977157771108c1e5fdddb6f3539b7dd547339a121289addaf66c98997ccce0cc012756147045f6885124",
                "be830cfd7a9ac5c23fff9401344bc95be5c3adaf528ecfa21a1d7bd5e230ad8fb665f801a91be6cca863f54e05f83184efcc3517c019f24868cb2fdcffa7fcc8",
            ),
            (
                DigestAlgorithm::Sha512,
                896,
                "d3ddddf805b1678a02e39200f6440047acbb062e4a2f046a3ca7f1dd6eb03a18be00cd1eb158706a64af5834c68cf7f105b415194605222c99a2cbf72c50cb14bf2004b0574fce90376a8f560cb58c0168cefeb4718e69b8db3029c313b54d7bbd86a936615c2704615d5eef2f886681",
                "c614e385837ecd4b1e471edf2143cfb8fe2697c5a3ee3ad56c13cff09733ccf4ce3b993de7fb726e89b2283629ec48a0e6fbe6b50003c378a0f5b0405a629619",
            ),
        ] {
            let message = hex(message);
            let expected = hex(expected);
            for split in [0, 1, 31, 32, 55] {
                let actual = hash(
                    algorithm,
                    &[&message[..split]],
                    &message[split..],
                    bit_len - split * 8,
                )
                .expect("valid split NIST message");
                assert_eq!(
                    &actual[..algorithm.output_len()],
                    expected,
                    "{algorithm:?}/{bit_len}/{split}"
                );
            }
        }
    }
}
