#[test]
fn registered_codecs_roundtrip_every_defined_byte() {
    // Bounded scalar-to-byte branches preserve every repertoire entry,
    // including C1 controls and the Thai undefined gaps.
    use super::IanaSingleByteEncoding;
    for encoding in [
        IanaSingleByteEncoding::Latin1,
        IanaSingleByteEncoding::Latin5,
        IanaSingleByteEncoding::Iso8859_11,
        IanaSingleByteEncoding::Tis620,
    ] {
        for byte in u8::MIN..=u8::MAX {
            if let Some(character) = encoding.decode_byte(byte) {
                assert_eq!(encoding.encode_char(character), Some(byte));
            }
        }
        assert_eq!(encoding.encode_char('\u{10ffff}'), None);
    }
}
