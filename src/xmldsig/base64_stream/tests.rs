use super::{Base64Stream, is_rfc2045_base64_byte};
use base64::Engine as _;

/// The decoded bytes and error of one streamed input.
fn streamed(input: &[u8], chunk: usize) -> (Vec<u8>, Option<base64::DecodeError>) {
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

fn resident(input: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    let filtered: Vec<u8> = input
        .iter()
        .copied()
        .filter(|byte| is_rfc2045_base64_byte(*byte))
        .collect();
    base64::engine::general_purpose::STANDARD.decode(filtered)
}

/// A decoded payload long enough to cross several decoding blocks.
fn encoded(length: usize) -> String {
    let payload: Vec<u8> = [0_u8, 1, 2, 250, 251, 255]
        .into_iter()
        .cycle()
        .take(length)
        .collect();
    base64::engine::general_purpose::STANDARD.encode(payload)
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
