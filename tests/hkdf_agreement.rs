#![cfg(feature = "xmlenc")]

use xml_sec::policy::DecryptionPolicy;
use xml_sec::provider::RUST_CRYPTO_PROVIDER;
use xml_sec::xmlenc::{KeyEstablishmentBudget, parse_hkdf_agreement_method};

fn xml(hash: &str, fields: &str) -> String {
    format!(
        "<AgreementMethod xmlns='http://www.w3.org/2001/04/xmlenc#' xmlns:m='http://www.w3.org/2021/04/xmldsig-more#' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' Algorithm='http://www.w3.org/2021/04/xmldsig-more#hkdf'><ds:DigestMethod Algorithm='{hash}'/>{fields}<KeySize>42</KeySize></AgreementMethod>"
    )
}

#[test]
fn rfc9231_hkdf_example_matches_rfc5869_a1() {
    // The normative hash selection and the RFC's illustrative HMAC URI must
    // produce the same A.1 bytes; KeySize=42 is octets in this profile.
    let policy = DecryptionPolicy::default();
    for hash in [
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    ] {
        let text = xml(
            hash,
            "<m:Salt>000102030405060708090a0b0c</m:Salt><OriginatorKeyInfo>0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b</OriginatorKeyInfo><KA-Nonce>f0f1f2f3f4f5f6f7f8f9</KA-Nonce>",
        );
        let agreement =
            parse_hkdf_agreement_method(&text, &policy, xml_sec::XmlBackend::default()).unwrap();
        let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
        let key = agreement
            .derive_key(42, None, &RUST_CRYPTO_PROVIDER, &mut budget)
            .unwrap();
        assert_eq!(
            &*key,
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
        assert!(
            agreement
                .derive_key(42, Some(b"override"), &RUST_CRYPTO_PROVIDER, &mut budget)
                .is_err()
        );
        assert!(
            agreement
                .derive_key(16, None, &RUST_CRYPTO_PROVIDER, &mut budget)
                .is_err()
        );
        assert!(!format!("{agreement:?}").contains("0b0b"));
    }
}

#[test]
fn missing_ikm_requires_explicit_request_and_optional_fields_follow_rfc_defaults() {
    // Absent XML IKM is not empty IKM: applications must supply it explicitly.
    // Absent salt/info are permitted and reproduce RFC 5869 A.3.
    let policy = DecryptionPolicy::default();
    let text = xml("http://www.w3.org/2001/04/xmlenc#sha256", "");
    let agreement =
        parse_hkdf_agreement_method(&text, &policy, xml_sec::XmlBackend::default()).unwrap();
    let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    assert!(
        agreement
            .derive_key(42, None, &RUST_CRYPTO_PROVIDER, &mut budget)
            .is_err()
    );
    assert_eq!(budget.owned_bytes(), 0);
    let key = agreement
        .derive_key(42, Some(&[0x0b; 22]), &RUST_CRYPTO_PROVIDER, &mut budget)
        .unwrap();
    assert_eq!(
        &*key,
        &[
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8
        ]
    );
}

#[test]
fn hkdf_wire_profile_rejects_duplicates_namespace_confusion_and_bad_hex() {
    // This adapter must not confuse base64 HKDFParams, XMLDSig names or
    // duplicate parameters with RFC 9231's hexadecimal profile.
    let policy = DecryptionPolicy::default();
    for fields in [
        "<m:Salt>0</m:Salt>",
        "<m:Salt>GG</m:Salt>",
        "<m:Salt>0b 0b</m:Salt>",
        "<m:Salt>AA</m:Salt><m:Salt>BB</m:Salt>",
        "<Salt>AA</Salt>",
        "<KA-Nonce><m:Salt/></KA-Nonce>",
        "<OriginatorKeyInfo>0b</OriginatorKeyInfo><OriginatorKeyInfo>0b</OriginatorKeyInfo>",
        "<KeySize>16</KeySize>",
        "unexpected",
        "\u{a0}",
    ] {
        assert!(
            parse_hkdf_agreement_method(
                &xml("http://www.w3.org/2001/04/xmlenc#sha256", fields),
                &policy,
                xml_sec::XmlBackend::default()
            )
            .is_err(),
            "{fields}"
        );
    }
    let text = xml("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "");
    assert!(parse_hkdf_agreement_method(&text, &policy, xml_sec::XmlBackend::default()).is_err());
}

#[test]
fn fragmented_hex_text_has_the_same_semantics_without_secret_concatenation() {
    // Comments and CDATA split parser text nodes, including a pair of nibbles;
    // decoding must borrow fragments rather than inspect only the first text.
    let policy = DecryptionPolicy::default();
    let hash = "http://www.w3.org/2001/04/xmlenc#sha256";
    let fields = "<OriginatorKeyInfo> 0<!-- boundary --><![CDATA[b]]>0b </OriginatorKeyInfo><m:Salt>0<![CDATA[1]]>02</m:Salt>";
    let split =
        parse_hkdf_agreement_method(&xml(hash, fields), &policy, xml_sec::XmlBackend::default())
            .unwrap();
    let whole = parse_hkdf_agreement_method(
        &xml(
            hash,
            "<OriginatorKeyInfo>0b0b</OriginatorKeyInfo><m:Salt>0102</m:Salt>",
        ),
        &policy,
        xml_sec::XmlBackend::default(),
    )
    .unwrap();
    let mut first = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    let mut second = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    assert_eq!(
        split
            .derive_key(42, None, &RUST_CRYPTO_PROVIDER, &mut first)
            .unwrap(),
        whole
            .derive_key(42, None, &RUST_CRYPTO_PROVIDER, &mut second)
            .unwrap()
    );
}
