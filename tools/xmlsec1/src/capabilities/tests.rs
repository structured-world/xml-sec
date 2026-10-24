use super::*;

#[test]
fn modern_signature_and_digest_capabilities_are_discoverable() {
    // Capability queries must agree with the actual public signing path.
    for name in ["ecdsa-sha3-256", "sha3-256", "eddsa-ed25519", "eddsa-ed448"] {
        assert!(TRANSFORMS.contains(&name), "missing {name}");
    }
    assert!(KEY_DATA.contains(&"eddsa"));
    assert_eq!(
        TRANSFORMS.contains(&"ml-dsa-44"),
        cfg!(feature = "experimental-pq")
    );
}

#[test]
fn checks_comma_separated_and_repeated_capabilities() {
    assert!(all_requested_available(
        TRANSFORMS,
        &["c14n,rsa-sha256".into(), "sha256".into()]
    ));
    assert_eq!(
        all_requested_available(TRANSFORMS, &["xslt".into()]),
        cfg!(feature = "xslt")
    );
    assert!(all_requested_available(
        TRANSFORMS,
        &["rsa-oaep-enc11".into()]
    ));
    assert!(all_requested_available(
        TRANSFORMS,
        &["rsa-oaep-mgf1p".into()]
    ));
    assert!(!all_requested_available(KEY_DATA, &["key-name".into()]));
}

#[test]
fn empty_queries_match_the_donor_vacuous_success_contract() {
    // No requested names means no missing capabilities in libxmlsec1.
    assert!(all_requested_available(TRANSFORMS, &[]));
}

#[test]
fn key_data_capabilities_are_distinct_from_generation_algorithms() {
    assert!(KEY_DATA.contains(&"rsa"));
    assert_eq!(generated_key_len("aes-128"), Some(16));
    assert_eq!(generated_key_len("rsa-1024"), None);
}

#[test]
fn kem_capabilities_follow_the_selected_engine() {
    // XML algorithm recognition never implies that an engine implements it.
    let provider = xml_sec::provider::RustCryptoProvider;
    assert_eq!(
        KEY_DATA.contains(&"encapsulation-mechanism"),
        cfg!(feature = "experimental-pq")
    );
    assert_eq!(
        key_data_available("encapsulation-mechanism", &provider),
        cfg!(feature = "experimental-pq")
    );
    for name in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"] {
        assert_eq!(
            transform_available(name, &provider),
            cfg!(feature = "experimental-pq")
        );
        assert_eq!(
            TRANSFORMS.contains(&name),
            cfg!(feature = "experimental-pq")
        );
    }
    assert_eq!(
        key_data_available("ml-kem", &provider),
        cfg!(feature = "experimental-pq")
    );
}

#[test]
fn list_has_stable_empty_and_non_empty_representations() {
    let mut output = Vec::new();
    list("transforms", &[], &mut output).unwrap();
    assert_eq!(output, b"Registered transforms:\n(none)\n");

    output.clear();
    list("transforms", &["c14n", "sha256"], &mut output).unwrap();
    assert_eq!(output, b"Registered transforms:\n\"c14n\",\"sha256\"\n");
}
