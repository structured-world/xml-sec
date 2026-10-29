use super::{
    Digests, NOT_AFTER, NOT_BEFORE, RSA_SHA256_PROFILE, TEST_INSTANT, TIME_COMPACT, baseline,
    counter_signature, document, enveloped_reference, plain_signature,
};

fn digests() -> Digests {
    Digests {
        signer_sha256: "c2lnbmVy".into(),
        signer_sha384: "c2lnbmVyMzg0".into(),
        root_sha256: "cm9vdA==".into(),
        signer_md5: "bWQ1".into(),
    }
}

#[test]
fn the_certificate_validity_contains_the_signing_time_and_the_test_instant() {
    // A fixture signed outside its certificate's validity would fail for the wrong reason.
    for instant in [TIME_COMPACT, TEST_INSTANT] {
        assert!((NOT_BEFORE..NOT_AFTER).contains(&instant), "{instant}");
    }
}

#[test]
fn the_baseline_template_is_an_enveloped_b_b_signature() {
    // Line layout follows the original generator, so regenerated fixtures keep their shape.
    let digests = digests();
    let typed = r#"Type="http://uri.etsi.org/01903#SignedProperties""#;
    let text = document(
        "Enveloped baseline payload",
        &baseline(&digests, typed, RSA_SHA256_PROFILE),
        RSA_SHA256_PROFILE,
    );
    assert!(text.starts_with(
        "<Document><Data Id=\"payload\">Enveloped baseline payload</Data>\n<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"sig\">\n  <ds:SignedInfo>\n"
    ));
    assert!(text.contains(
        "    <ds:Reference Id=\"sig-data\" URI=\"\">\n      <ds:Transforms>\n        <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"
    ));
    assert!(text.contains(&format!("    <ds:Reference {typed} URI=\"#sp\">\n")));
    assert!(text.contains("<xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Target=\"#sig\">"));
    assert!(text.contains("                <ds:DigestValue>c2lnbmVy</ds:DigestValue>\n"));
    // Empty optional parts keep their indented line, as the original templates did.
    assert!(text.contains("<ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>\n  \n  <ds:Object>\n"));
    assert!(
        text.contains("</xades:SignedProperties>\n      \n    </xades:QualifyingProperties>\n")
    );
    assert!(text.ends_with("</ds:Signature>\n</Document>\n"));
}

#[test]
fn inserted_fragments_carry_no_trailing_newline() {
    // References and nested signatures are spliced into a line of their parent.
    for fragment in [
        enveloped_reference("sig", RSA_SHA256_PROFILE),
        plain_signature("inner", "inner-data", "", RSA_SHA256_PROFILE),
        counter_signature("counter", "sig-value", RSA_SHA256_PROFILE),
    ] {
        assert!(!fragment.ends_with('\n'), "{fragment}");
    }
    // An absent attribute leaves the space before URI, as the original template did.
    assert!(
        plain_signature("inner", "inner-data", "", RSA_SHA256_PROFILE)
            .contains("<ds:Reference  URI=\"#inner-data\">")
    );
}
