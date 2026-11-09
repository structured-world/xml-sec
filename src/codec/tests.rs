//! The Base64 codec against RFC 4648 vectors and its stream rules: line
//! breaks, white space, padding and what follows it.

use alloc::{string::String, vec, vec::Vec};

use super::{Base64Codec, Base64Error};

fn encoded(input: &[u8], columns: usize) -> String {
    let mut codec = Base64Codec::new(true, columns);
    let mut output = vec![0; Base64Codec::encoded_capacity(columns, input.len()).expect("size")];
    let written = codec.update(input, &mut output).expect("encode");
    let last = codec.finish(&mut output[written..]).expect("final");
    String::from_utf8(output[..written + last].to_vec()).expect("ASCII")
}

fn decoded(input: &str) -> Result<Vec<u8>, Base64Error> {
    let mut codec = Base64Codec::new(false, 0);
    let mut output = vec![0; Base64Codec::decoded_capacity(input.len()).expect("size")];
    let written = codec.update(input.as_bytes(), &mut output)?;
    let last = codec.finish(&mut output[written..])?;
    Ok(output[..written + last].to_vec())
}

/// RFC 4648 section 10 vectors, both directions.
#[test]
fn rfc_4648_vectors() {
    for (plain, base64) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(encoded(plain.as_bytes(), 0), base64, "{plain}");
        assert_eq!(decoded(base64).as_deref(), Ok(plain.as_bytes()), "{base64}");
    }
}

/// A line break follows every `columns` output characters, padding
/// included, and never ends the output.
#[test]
fn line_breaks_after_columns() {
    assert_eq!(encoded(b"foobar", 4), "Zm9v\nYmFy");
    assert_eq!(encoded(b"foob", 4), "Zm9v\nYg==");
    assert_eq!(encoded(&[0xff; 6], 3), "///\n///\n//");
}

/// White space anywhere is skipped; data after the padding, a misplaced
/// padding, a foreign character and a truncated group fail with their
/// reason.
#[test]
fn decoding_rules() {
    assert_eq!(decoded(" Zm 9v\r\nYmFy \t").as_deref(), Ok(&b"foobar"[..]));
    assert_eq!(decoded("Zg==\n"), Ok(b"f".to_vec()));
    assert_eq!(decoded("Zg==Zg=="), Err(Base64Error::Invalid));
    assert_eq!(decoded("Z==="), Err(Base64Error::Invalid));
    assert_eq!(decoded("Zm9v!"), Err(Base64Error::Invalid));
    assert_eq!(decoded("Zm9"), Err(Base64Error::Truncated));
}

/// Too little output room is reported, not truncated output.
#[test]
fn output_room_is_checked() {
    let mut out = [0u8; 2];
    assert_eq!(
        Base64Codec::new(false, 0).update(b"Zm9v", &mut out),
        Err(Base64Error::OutputFull)
    );
    assert_eq!(
        Base64Codec::new(true, 0).update(b"foo", &mut out),
        Err(Base64Error::OutputFull)
    );
    assert_eq!(
        Base64Codec::new(true, 0).finish(&mut []),
        Err(Base64Error::OutputFull)
    );
}

/// A state no codec produces fails instead of indexing out of range.
#[test]
fn foreign_state_is_refused() {
    let mut codec = Base64Codec {
        position: 7,
        ..Base64Codec::new(true, 0)
    };
    let mut out = [0u8; 8];
    assert_eq!(codec.update(b"x", &mut out), Err(Base64Error::Invalid));
}
