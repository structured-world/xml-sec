use xml_sec::{
    encoding::decode_xml_octets,
    xml_input::{Error, decode_xml_bounded},
};

#[test]
fn trusted_encoding_metadata_decodes_declarationless_xml_with_a_limit() {
    let latin1 = b"<root>caf\xe9</root>";
    assert!(matches!(
        decode_xml_octets(latin1, 64),
        Err(Error::InvalidBytes("UTF-8"))
    ));

    let decoded = decode_xml_bounded(latin1, Some("ISO-8859-1"), 64)
        .expect("trusted metadata selects Latin-1");
    assert_eq!(decoded, "<root>café</root>");
    assert!(matches!(
        decode_xml_bounded(latin1, Some("ISO-8859-1"), 8),
        Err(Error::DecodedLimit { maximum: 8, .. })
    ));
}

#[test]
fn trusted_metadata_cannot_override_the_xml_declaration() {
    let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>";
    assert!(matches!(
        decode_xml_bounded(xml, Some("ISO-8859-1"), 128),
        Err(Error::ConflictingEncoding(_))
    ));
}
