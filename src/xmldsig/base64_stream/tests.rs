use super::{Base64Stream, is_rfc2045_base64_byte};
use alloc::{format, string::String, vec::Vec};
use structured_base64::{Base64Error, OwnedError};

/// The decoded bytes and error of one streamed input.
fn streamed(input: &[u8], chunk: usize) -> (Vec<u8>, Option<Base64Error>) {
    let mut output = Vec::new();
    let mut sink = |decoded: &[u8]| -> Result<(), ()> {
        output.extend_from_slice(decoded);
        Ok(())
    };
    let mut stream = Base64Stream::new();
    for piece in input.chunks(chunk) {
        stream
            .feed(piece, &mut sink)
            .expect("the sink never refuses");
    }
    let failure = stream.finish(&mut sink).expect("the sink never refuses");
    (output, failure)
}

/// The resident decoder over the filtered input, its failure located in
/// `input` through the original position of every byte the filter kept.
fn resident(input: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let positions: Vec<usize> = (0..input.len())
        .filter(|index| is_rfc2045_base64_byte(input[*index]))
        .collect();
    let filtered: Vec<u8> = positions.iter().map(|index| input[*index]).collect();
    structured_base64::STANDARD
        .decode(&filtered)
        .map_err(|error| match error {
            OwnedError::Codec(Base64Error::InvalidByte(offset, byte)) => {
                Base64Error::InvalidByte(positions[offset], byte)
            }
            OwnedError::Codec(Base64Error::InvalidLastSymbol(offset, byte)) => {
                Base64Error::InvalidLastSymbol(positions[offset], byte)
            }
            OwnedError::Codec(Base64Error::InvalidLength(_)) => {
                Base64Error::InvalidLength(input.len())
            }
            OwnedError::Codec(error) => error,
            OwnedError::Reserve(error) => panic!("test allocation: {error}"),
        })
}

/// A decoded payload long enough to cross several decoding blocks.
fn encoded(length: usize) -> String {
    let payload: Vec<u8> = [0_u8, 1, 2, 250, 251, 255]
        .into_iter()
        .cycle()
        .take(length)
        .collect();
    crate::base64::encode(&payload)
}

fn assert_matches_resident(input: &[u8]) {
    // The chunk boundary decides which feed path a byte takes, so it must
    // never change the outcome.
    for chunk in [1, 3, 4, 7, 4095, 8191, 8192, 8193, input.len().max(1)] {
        let (output, failure) = streamed(input, chunk);
        match resident(input) {
            Ok(expected) => {
                assert_eq!(failure, None, "chunk {chunk}");
                assert_eq!(output, expected, "chunk {chunk}");
            }
            Err(expected) => assert_eq!(failure, Some(expected), "chunk {chunk}"),
        }
    }
}

#[test]
fn valid_input_matches_the_resident_decoder_at_every_block_boundary() {
    // Lengths around one block cover a final quantum on and past the boundary.
    for length in [0, 1, 2, 3, 6141, 6142, 6143, 6144, 6145, 6146, 20_000] {
        assert_matches_resident(encoded(length).as_bytes());
    }
}

#[test]
fn ignored_bytes_match_the_resident_filter_wherever_they_fall() {
    // RFC 2045 section 6.8: a foreign byte moves a run onto the byte filter.
    let plain = encoded(20_000);
    let lines = plain
        .as_bytes()
        .chunks(76)
        .collect::<Vec<_>>()
        .join(&b"\r\n"[..]);
    assert_matches_resident(&lines);
    let mut late = plain.into_bytes();
    late.insert(10_000, b' ');
    assert_matches_resident(&late);
    assert_matches_resident(b" \n\t");
}

#[test]
fn padding_errors_match_the_resident_decoder_inside_and_across_blocks() {
    let block = "QUJD".repeat(2048);
    for input in [
        // Data after padding inside one block.
        "QQ==QUJD".to_owned(),
        // Padding ends a block; the data follows in the next one.
        format!("{}QQ==QUJD", "QUJD".repeat(2047)),
        // The same with a separator hiding the next alphabet byte.
        format!("{}QQ==\nQUJD", "QUJD".repeat(2047)),
        // Data after padding beyond the first block.
        format!("{block}QQ==QUJD"),
        // Padding alone, in excess, and in an incomplete quantum.
        "====".to_owned(),
        "QQ===".to_owned(),
        format!("{block}Q"),
        format!("{block}QQ"),
        format!("{block}QQ="),
        // Non-canonical trailing bits.
        "QR==".to_owned(),
    ] {
        assert_matches_resident(input.as_bytes());
    }
}

#[test]
fn failures_are_located_in_the_original_input() {
    // Offsets count every input byte, including those RFC 2045 filters out,
    // and an incomplete quantum ends where the input ends.
    for (input, expected) in [
        (&b" \n=AAA"[..], Base64Error::InvalidByte(2, b'=')),
        (b"Q R==", Base64Error::InvalidLastSymbol(2, b'R')),
        (b"QUJD Q\n", Base64Error::InvalidLength(7)),
        (b"QQ==\r\nQUJD", Base64Error::InvalidByte(2, b'=')),
    ] {
        for chunk in [1, 2, 3, input.len()] {
            assert_eq!(
                streamed(input, chunk).1,
                Some(expected),
                "{input:?} {chunk}"
            );
        }
        assert_matches_resident(input);
    }
}

#[test]
fn data_after_padding_reports_the_resident_length_error() {
    // The resident decoder checks the whole input's length before any symbol,
    // so an incomplete quantum after padding is a length error, wherever the
    // padding falls relative to a decoding block.
    for input in [
        format!("{}QQ==Q", "QUJD".repeat(2047)),
        "QQ==Q".to_owned(),
        format!("{}QR==QUJD", "QUJD".repeat(2047)),
    ] {
        assert_matches_resident(input.as_bytes());
    }
    assert_eq!(
        streamed(format!("{}QQ==Q", "QUJD".repeat(2047)).as_bytes(), 8192).1,
        Some(Base64Error::InvalidLength(8193))
    );
}

#[test]
fn a_sink_error_stops_the_stream_with_that_error() {
    let input = encoded(20_000);
    let mut calls = 0;
    let mut stream = Base64Stream::new();
    let error = stream
        .feed(input.as_bytes(), &mut |_: &[u8]| {
            calls += 1;
            Err("refused")
        })
        .expect_err("a sink refusal ends the feed");
    assert_eq!(error, "refused");
    assert_eq!(calls, 1);
}

#[test]
fn a_decoding_failure_ends_the_stream_and_ignores_later_input() {
    let mut stream = Base64Stream::new();
    let mut sink = |_: &[u8]| -> Result<(), ()> { Ok(()) };
    stream
        .feed(b"QQ==", &mut sink)
        .expect("the sink never refuses");
    let block = "QUJD".repeat(2048);
    stream
        .feed(block.as_bytes(), &mut sink)
        .expect("the sink never refuses");
    assert!(!stream.active());
    stream
        .feed(b"anything", &mut sink)
        .expect("the sink never refuses");
    assert!(
        stream
            .finish(&mut sink)
            .expect("the sink never refuses")
            .is_some()
    );
}
