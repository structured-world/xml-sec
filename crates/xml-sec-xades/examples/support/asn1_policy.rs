//! An ETSI TR 102 272 V1.1.1 §6.1 `SignaturePolicy` in DER, the document of
//! an explicit policy whose digest is computed as that specification says.

/// The `SPDocSpecification` the example policies name for the TR 102 272
/// digest rule; the identifier is the caller's choice.
pub const SPECIFICATION: &str = "urn:example:asn1-signature-policy";

/// `1.2.3.4.5.6`, the policy version in `signPolicyInfo`.
pub const POLICY_OID: &str = "urn:oid:1.2.3.4.5.6";

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    // X.690 §8.1.3: the short form below 128, else the shortest long form.
    let length = u8::try_from(content.len()).expect("a policy under 256 bytes");
    let mut bytes = if length < 0x80 {
        vec![tag, length]
    } else {
        vec![tag, 0x81, length]
    };
    bytes.extend_from_slice(content);
    bytes
}

/// A policy over SHA-256: `signPolicyHashAlg`, then `signPolicyInfo` with
/// the version OID, the issue date, the issuer, the field of application
/// and an empty validation policy, and a `signPolicyHash` over the first two
/// when `stored` gives it.
pub fn document(stored: Option<&[u8]>) -> Vec<u8> {
    // 2.16.840.1.101.3.4.2.1, id-sha256, without parameters.
    let algorithm = tlv(0x30, &tlv(0x06, &[96, 134, 72, 1, 101, 3, 4, 2, 1]));
    let issued = tlv(0x18, b"20261126000000Z");
    let period = tlv(0x30, &issued);
    let rules = tlv(
        0x30,
        &[period.as_slice(), &tlv(0x30, &[]), &tlv(0x30, &[])].concat(),
    );
    let authority = tlv(0x30, &tlv(0x82, b"policy.example"));
    let information = tlv(
        0x30,
        &[
            tlv(0x06, &[42, 3, 4, 5, 6]).as_slice(),
            &issued,
            &authority,
            &tlv(0x0c, b"XAdES signatures"),
            &rules,
        ]
        .concat(),
    );
    let mut contents = [algorithm, information].concat();
    if let Some(stored) = stored {
        contents.extend(tlv(0x04, stored));
    }
    tlv(0x30, &contents)
}
