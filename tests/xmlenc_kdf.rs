#![cfg(feature = "xmlenc")]

use xml_sec::policy::DecryptionPolicy;
use xml_sec::provider::{CryptoProvider, KdfContext, RUST_CRYPTO_PROVIDER};
use xml_sec::xmlenc::{ConcatKdfField, parse_key_derivation_method};

const NS: &str = "http://www.w3.org/2009/xmlenc11#";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const HMAC256: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";

fn concat(attributes: &str) -> String {
    format!(
        "<KeyDerivationMethod xmlns='{NS}' Algorithm='{NS}ConcatKDF'><ConcatKDFParams {attributes}><DigestMethod xmlns='http://www.w3.org/2000/09/xmldsig#' Algorithm='{SHA256}'/></ConcatKDFParams></KeyDerivationMethod>"
    )
}

#[test]
fn concat_xml_preserves_unaligned_attribute_boundaries() {
    // XMLEnc 1.1 example 25 requires 8 + 5 + 5 significant bits, not
    // three octet-aligned buffers or their padding-count prefixes.
    let xml = concat("AlgorithmID='0000' PartyUInfo='03D8' PartyVInfo='03D0'");
    let method = parse_key_derivation_method(&xml, &DecryptionPolicy::default()).unwrap();
    let parameters = method.parameters(16).unwrap();
    assert_eq!(
        method
            .concat_field_bits(ConcatKdfField::PartyUInfo)
            .unwrap()
            .collect::<Vec<_>>(),
        [true, true, false, true, true]
    );
    assert_eq!(
        method
            .concat_field_bits(ConcatKdfField::PartyVInfo)
            .unwrap()
            .collect::<Vec<_>>(),
        [true, true, false, true, false]
    );
    assert!(
        method
            .concat_field_bits(ConcatKdfField::SuppPubInfo)
            .is_none()
    );
    assert_eq!(
        parameters.info,
        KdfContext::Bits {
            bytes: &[0x00, 0xde, 0x80],
            bit_len: 18
        }
    );
    let derived = RUST_CRYPTO_PROVIDER
        .derive_key(&parameters, b"shared secret")
        .unwrap();
    assert_eq!(derived.len(), 16);
}

#[test]
fn concat_xml_rejects_invalid_padding_and_hex() {
    // Malformed bit strings must fail during syntax validation, before KDF work.
    for value in ["0", "08FF", "03D9", "01FF", "GG", "00F F", "07"] {
        let xml = concat(&format!("PartyUInfo='{value}'"));
        assert!(
            parse_key_derivation_method(&xml, &DecryptionPolicy::default()).is_err(),
            "{value}"
        );
    }
}

#[test]
fn pbkdf2_xml_has_no_asn1_defaults() {
    // Unlike the ASN.1 format, the XML schema requires KeyLength and PRF;
    // accepting missing fields would silently select different keying material.
    let prefix = format!(
        "<KeyDerivationMethod xmlns='{NS}' Algorithm='{NS}pbkdf2'><PBKDF2-params><Salt><Specified>c2FsdA==</Specified></Salt><IterationCount>2</IterationCount>"
    );
    for fields in [
        String::new(),
        "<KeyLength>16</KeyLength>".into(),
        format!("<PRF Algorithm='{HMAC256}'/>"),
    ] {
        let xml = format!("{prefix}{fields}</PBKDF2-params></KeyDerivationMethod>");
        assert!(parse_key_derivation_method(&xml, &DecryptionPolicy::default()).is_err());
    }
    let xml = format!(
        "{prefix}<KeyLength>16</KeyLength><PRF Algorithm='{HMAC256}'/></PBKDF2-params></KeyDerivationMethod>"
    );
    let method = parse_key_derivation_method(&xml, &DecryptionPolicy::default()).unwrap();
    assert!(method.parameters(32).is_err());
    let parameters = method.parameters(16).unwrap();
    assert_eq!(parameters.iterations, 2);
    assert_eq!(parameters.salt, b"salt");
    assert_eq!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"password")
            .unwrap()
            .len(),
        16
    );
}

#[test]
fn kdf_xml_bounds_metadata_before_decoding() {
    // The standalone entry point must use the same immutable parser and
    // metadata policy as EncryptedData; small limits cannot be bypassed.
    let mut policy = DecryptionPolicy::default();
    policy.resources.max_encryption_metadata_bytes = 64;
    assert!(
        parse_key_derivation_method(
            &concat(&format!("PartyUInfo='00{}'", "FF".repeat(64))),
            &policy
        )
        .is_err()
    );
}

#[test]
fn concat_every_partial_boundary_matches_independent_bit_packing() {
    // Every partial join must preserve bit order without carrying padding
    // from one party's identifier into the next field.
    for first in 1usize..=8 {
        for second in 1usize..=8 {
            let a = 0xffu8 << (8 - first);
            let b = 0xa5u8 & (0xff << (8 - second));
            let xml = concat(&format!(
                "PartyUInfo='{:02X}{a:02X}' PartyVInfo='{:02X}{b:02X}'",
                8 - first,
                8 - second
            ));
            let method = parse_key_derivation_method(&xml, &DecryptionPolicy::default()).unwrap();
            let mut expected = vec![0; (first + second).div_ceil(8)];
            for (offset, bit) in (0..first)
                .map(|i| (a >> (7 - i)) & 1)
                .chain((0..second).map(|i| (b >> (7 - i)) & 1))
                .enumerate()
            {
                expected[offset / 8] |= bit << (7 - offset % 8);
            }
            assert_eq!(
                method.parameters(16).unwrap().info,
                KdfContext::Bits {
                    bytes: &expected,
                    bit_len: first + second
                }
            );
        }
    }
}

#[test]
fn hkdf_donor_profile_uses_base64_not_rfc_agreement_hex() {
    // Compatibility XML retains base64 salt/info and binds explicit width;
    // it must not adopt the different RFC AgreementMethod hex encoding.
    let xml = format!(
        "<KeyDerivationMethod xmlns='{NS}' Algorithm='http://www.w3.org/2021/04/xmldsig-more#hkdf'><HKDFParams xmlns='http://www.w3.org/2021/04/xmldsig-more#'><PRF Algorithm='{HMAC256}'/><Salt>c2FsdA==</Salt><Info>aW5mbw==</Info><KeyLength>32</KeyLength></HKDFParams></KeyDerivationMethod>"
    );
    let method = parse_key_derivation_method(&xml, &DecryptionPolicy::default()).unwrap();
    let parameters = method.parameters(32).unwrap();
    assert_eq!(parameters.salt, b"salt");
    assert_eq!(parameters.info, KdfContext::Octets(b"info"));
    assert!(method.parameters(16).is_err());
    for modified in [
        xml.replace("<Info>aW5mbw==</Info>", "<Info>aW5mbw==</Info><Salt/>"),
        xml.replace("<KeyLength>32</KeyLength>", "<KeyLength>0</KeyLength>"),
        xml.replace("<PRF", "<DigestMethod"),
    ] {
        assert!(parse_key_derivation_method(&modified, &DecryptionPolicy::default()).is_err());
    }
}

#[test]
fn kdf_containers_reject_unexpected_character_data() {
    // Element-only grammar accepts XML whitespace, not arbitrary text or NBSP;
    // silently skipping it would make parser implementations disagree.
    for text in ["unexpected", "\u{a0}"] {
        let xml = concat("").replace("<ConcatKDFParams", &format!("{text}<ConcatKDFParams"));
        assert!(parse_key_derivation_method(&xml, &DecryptionPolicy::default()).is_err());
    }
    assert!(
        parse_key_derivation_method(&concat("PartyUInfo='00'"), &DecryptionPolicy::default())
            .is_ok()
    );
}

#[test]
fn kdf_serialization_preserves_every_field_and_partial_octet() {
    // Transporting KDF parameters must not collapse omitted/empty fields or
    // pad party identifiers before concatenation at the receiving endpoint.
    let policy = DecryptionPolicy::default();
    let inputs = [
        concat("AlgorithmID='0000' PartyUInfo='03D8' PartyVInfo='03D0' SuppPubInfo='00'"),
        format!(
            "<KeyDerivationMethod xmlns='{NS}' Algorithm='{NS}pbkdf2'><PBKDF2-params><Salt><Specified>c2FsdA==</Specified></Salt><IterationCount>4294967297</IterationCount><KeyLength>16</KeyLength><PRF Algorithm='{HMAC256}'/></PBKDF2-params></KeyDerivationMethod>"
        ),
        format!(
            "<KeyDerivationMethod xmlns='{NS}' Algorithm='http://www.w3.org/2021/04/xmldsig-more#hkdf'><HKDFParams xmlns='http://www.w3.org/2021/04/xmldsig-more#'><PRF Algorithm='{HMAC256}'/><Salt>c2FsdA==</Salt><Info>aW5mbw==</Info><KeyLength>16</KeyLength></HKDFParams></KeyDerivationMethod>"
        ),
    ];
    for input in inputs {
        let method = parse_key_derivation_method(&input, &policy).unwrap();
        let output = method.to_xml(&policy.resources).unwrap();
        assert_eq!(
            parse_key_derivation_method(&output, &policy).unwrap(),
            method
        );
        let mut exact = policy.resources.clone();
        exact.max_xml_document_bytes = output.len();
        assert_eq!(method.to_xml(&exact).unwrap(), output);
        exact.max_xml_document_bytes -= 1;
        assert!(method.to_xml(&exact).is_err());
    }
}

#[test]
fn concat_serialization_limits_original_fields_not_a_base64_copy() {
    // Four individually bounded hex fields can fill the normalized context
    // allowance; ConcatKDF never serializes that context as base64.
    let mut policy = DecryptionPolicy::default();
    policy.resources.max_encryption_metadata_bytes = 200;
    let field = format!("00{}", "AB".repeat(50));
    let input = concat(&format!(
        "AlgorithmID='{field}' PartyUInfo='{field}' PartyVInfo='{field}' SuppPubInfo='{field}'"
    ));
    let method = parse_key_derivation_method(&input, &policy).unwrap();
    let output = method.to_xml(&policy.resources).unwrap();
    assert_eq!(
        parse_key_derivation_method(&output, &policy).unwrap(),
        method
    );
}
