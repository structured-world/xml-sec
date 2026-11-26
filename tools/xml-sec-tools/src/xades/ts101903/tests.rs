use super::decimal;

#[test]
fn serial_numbers_are_written_in_decimal() {
    // X509SerialNumber is an xsd:integer; OpenSSL prints serials in hex, and
    // a 20-byte serial is far wider than any machine integer.
    assert_eq!(decimal(&[]), "0");
    assert_eq!(decimal(&[0, 0]), "0");
    assert_eq!(decimal(&[0x01, 0x00]), "256");
    assert_eq!(decimal(&[0xff; 8]), u64::MAX.to_string());
    assert_eq!(decimal(&[0xff; 16]), u128::MAX.to_string());
    // 2^160 - 1, the largest 20-byte serial.
    assert_eq!(
        decimal(&[0xff; 20]),
        "1461501637330902918203684832716283019655932542975"
    );
}
