use super::{date_time, declarations, tokens};

#[test]
fn a_token_copied_into_another_property_keeps_that_propertys_result() {
    // The same token bytes under an ArchiveTimeStamp stamp other input than
    // under the SignatureTimeStamp they were made for; each property's own
    // result applies, never the first one found for those bytes.
    use xml_sec_xades::{TimestampRole, TokenIntegrity};
    let token = vec![1, 2, 3];
    let declared = super::etsi::Declared {
        signature_timestamps: vec![token.clone()],
        archive_timestamps: vec![token.clone()],
        token_integrity: vec![
            (
                TimestampRole::Signature,
                token.clone(),
                Some(TokenIntegrity::Intact),
            ),
            (
                TimestampRole::Archive,
                token.clone(),
                Some(TokenIntegrity::ImprintMismatch),
            ),
        ],
        ..super::etsi::Declared::default()
    };
    assert_eq!(
        declared.intact(TimestampRole::Signature, 0, &token),
        Some(TokenIntegrity::Intact)
    );
    assert_eq!(
        declared.intact(TimestampRole::Archive, 0, &token),
        Some(TokenIntegrity::ImprintMismatch)
    );
    assert_eq!(declared.intact(TimestampRole::Archive, 0, &[9]), None);
}

#[test]
fn a_rejected_token_keeps_its_cause_in_the_etsi_finding() {
    // EN 319 102-1 V1.4.1 clause 5.2.7 tells a data hash mismatch (the
    // token's imprint) apart from a signature that does not verify; a token
    // that does not hold to its profile is a format failure.
    use structured_ltv::validation::SubIndication;
    use xml_sec_xades::TokenIntegrity;
    for (integrity, sub) in [
        (TokenIntegrity::ImprintMismatch, SubIndication::HashFailure),
        (
            TokenIntegrity::SignatureInvalid,
            SubIndication::SigCryptoFailure,
        ),
        (TokenIntegrity::Rejected, SubIndication::FormatFailure),
    ] {
        assert_eq!(
            super::etsi::token_finding(integrity),
            Some(sub),
            "{integrity:?}"
        );
    }
    assert_eq!(super::etsi::token_finding(TokenIntegrity::Intact), None);
}

#[test]
fn a_token_that_passed_its_validation_reads_as_passed() {
    // A timestamp validation (EN 319 102-1 V1.4.1 clause 5.4) concludes
    // PASSED, FAILED or INDETERMINATE, as DSS concludes a TIMESTAMP block;
    // TOTAL_PASSED is a signature's conclusion and read as a failed token.
    use structured_ltv::validation::SubIndication;
    use structured_ltv::validation::long_term::Decision;
    let mut each = vec![serde_json::json!({ "role": "Signature", "current": null })];
    super::etsi::record(&mut each, Decision::Passed);
    assert_eq!(each[0]["current"]["indication"], "PASSED");
    assert_eq!(each[0]["current"]["sub"], serde_json::Value::Null);
    super::etsi::record(&mut each, Decision::Finding(SubIndication::HashFailure));
    assert_eq!(each[0]["current"]["indication"], "FAILED");
    assert_eq!(each[0]["current"]["sub"], "HASH_FAILURE");
}

#[test]
fn tokens_a_failed_process_did_not_reach_stay_unjudged_beside_decided_ones() {
    // A process failure on the second token keeps the first token's result;
    // the second and every later one are listed as not judged.
    let declared = super::etsi::Declared {
        signature_timestamps: vec![vec![1], vec![2]],
        archive_timestamps: vec![vec![3]],
        ..super::etsi::Declared::default()
    };
    let decided = serde_json::json!({ "role": "Signature", "current": { "indication": "PASSED", "sub": null } });
    let failed = serde_json::json!({ "role": "Signature", "current": null });
    let rows = super::etsi::with_unjudged_rest(&declared, vec![decided.clone(), failed.clone()]);
    assert_eq!(
        rows,
        [
            decided,
            failed,
            serde_json::json!({ "role": "Archive", "current": null })
        ]
    );
}

#[test]
fn an_assessment_cut_short_lists_every_declared_token_unjudged() {
    // A chain search over its step budget ends the signature's assessment
    // before any token is placed: each declared token still has a row, so
    // the report tells an incomplete assessment from no timestamps at all.
    let declared = super::etsi::Declared {
        signature_timestamps: vec![vec![1]],
        archive_timestamps: vec![vec![3]],
        ..super::etsi::Declared::default()
    };
    let rendered = super::etsi::incomplete(&declared, "candidate steps exceeded");
    assert_eq!(rendered["sub"], "CUSTOM");
    assert_eq!(
        rendered["tokens"],
        serde_json::json!([
            { "role": "Signature", "current": null },
            { "role": "Archive", "current": null }
        ])
    );
}

#[test]
fn a_refs_only_timestamp_is_told_apart_from_a_sig_and_refs_one() {
    // A RefsOnlyTimeStamp covers the references alone, a SigAndRefs one also
    // the signature value and its timestamps (TS 101 903 V1.4.2 7.5.1,
    // 7.5.2): the two must reach the process under their own roles.
    use xml_sec_xades::TimestampRole;
    let declared = super::etsi::Declared {
        validation_timestamps: vec![vec![1], vec![2], vec![3]],
        refs_only: vec![false, true, false],
        ..super::etsi::Declared::default()
    };
    let roles: Vec<_> = declared
        .tokens()
        .into_iter()
        .map(|(role, occurrence, _)| (role, occurrence))
        .collect();
    assert_eq!(
        roles,
        [
            (TimestampRole::SignatureAndReferences, 0),
            (TimestampRole::ReferencesOnly, 0),
            (TimestampRole::SignatureAndReferences, 1),
        ]
    );
}

/// The B-T fixture: a signer issued by the levels Issuer, which the document
/// carries without its Root, and a timestamp of a TSA the Root issued.
const B_T: &str = include_str!("../../tests/fixtures/levels/b-t.xml");
const ISSUER: &[u8] = include_bytes!("../../tests/fixtures/levels/issuer.der");
const ROOT: &[u8] = include_bytes!("../../tests/fixtures/levels/root.der");
/// A self-signed certificate named like the levels Root, with another key.
const IMPOSTOR: &[u8] = include_bytes!("../../tests/fixtures/levels/impostor-root.der");

#[test]
fn the_anchor_is_the_top_of_the_signers_chain() {
    // The comparison anchors the topmost certificate of the signer chain the
    // document carries; the timestamp authority's certificate anchors no
    // signer, so it is no anchor of its own.
    let pool = super::pool(B_T);
    let (anchors, unread) = super::signer_anchors(B_T.as_bytes(), B_T, &pool).unwrap();
    assert_eq!(unread, None);
    assert_eq!(anchors, [ISSUER.to_vec()]);
    // The Root the signer chain reaches is its top once it is carried.
    let mut with_root = pool.clone();
    with_root.push(ROOT.to_vec());
    let (anchors, _) = super::signer_anchors(B_T.as_bytes(), B_T, &with_root).unwrap();
    assert_eq!(anchors, [ROOT.to_vec()]);
}

#[test]
fn a_ca_a_reference_names_is_never_the_signer() {
    // EN 319 102-1 V1.4.1 clause 5.2.3.4: the references are checked against
    // the signing certificate, the one whose key verifies the signature. A
    // reference to a CA of the path, with the signer itself unavailable,
    // identifies no signer; its key must not stand in for the signer's.
    let document = xml_sec::XmlDocument::parse(B_T).unwrap();
    let expected = super::expected_targets(&document, B_T);
    let pool = super::pool(B_T);
    let mut declared = declarations(B_T);
    super::settle_signers(&document, &expected, &mut declared, &pool, 1_700_000_000).unwrap();
    let signer = declared[0]
        .signer
        .clone()
        .expect("the signer's key verifies");
    assert_ne!(signer, ISSUER);
    // The references name the signer and its CA; only the CA is available.
    declared[0].signer = None;
    declared[0].certificate_references = [signer.as_slice(), ISSUER]
        .map(|certificate| {
            (
                Some(DigestAlgorithm::Sha256),
                xml_sec::xmldsig::compute_digest(DigestAlgorithm::Sha256, certificate),
            )
        })
        .to_vec();
    let issuer_only = [ISSUER.to_vec()];
    super::settle_signers(
        &document,
        &expected,
        &mut declared,
        &issuer_only,
        1_700_000_000,
    )
    .unwrap();
    assert_eq!(declared[0].signer, None);
}

#[test]
fn an_altered_value_keeps_the_signer_its_references_identify() {
    // No key verifies an altered SignatureValue, yet the references still
    // identify the signing certificate (EN 319 102-1 V1.4.1 clause 5.2.3.4):
    // the signature fails its value check (SIG_CRYPTO_FAILURE), never the
    // identification of its signer.
    let document = xml_sec::XmlDocument::parse(B_T).unwrap();
    let expected = super::expected_targets(&document, B_T);
    let pool = super::pool(B_T);
    let mut declared = declarations(B_T);
    super::settle_signers(&document, &expected, &mut declared, &pool, 1_700_000_000).unwrap();
    let signer = declared[0]
        .signer
        .clone()
        .expect("the signer's key verifies");
    let start = B_T.find("<ds:SignatureValue").unwrap();
    let value = start + B_T[start..].find('>').unwrap() + 1;
    let flipped = if B_T.as_bytes()[value] == b'A' {
        "B"
    } else {
        "A"
    };
    let altered = format!("{}{flipped}{}", &B_T[..value], &B_T[value + 1..]);
    let document = xml_sec::XmlDocument::parse(&altered).unwrap();
    let expected = super::expected_targets(&document, &altered);
    let mut declared = declarations(&altered);
    super::settle_signers(&document, &expected, &mut declared, &pool, 1_700_000_000).unwrap();
    assert_eq!(declared[0].signer, Some(signer));
}

#[test]
fn a_certificate_that_only_shares_the_issuers_name_issues_nothing() {
    // RFC 5280 6.1.3 (a)(1): the issuer's key verifies the certificate. A
    // certificate named like the absent Root must not end the chain in place
    // of the Issuer it does not sign.
    let mut pool = super::pool(B_T);
    pool.push(IMPOSTOR.to_vec());
    let (anchors, _) = super::signer_anchors(B_T.as_bytes(), B_T, &pool).unwrap();
    assert_eq!(anchors, [ISSUER.to_vec()]);
}

#[test]
fn an_issuer_the_provider_cannot_verify_establishes_no_edge() {
    // structured-pkix's chain-top search treats a verifier error as a failed
    // search and an Unsupported answer as no edge. An issuer signing with an
    // algorithm the provider does not implement (SHA3 RSA in a DSS input)
    // must end that branch, not the conditions of the whole document; a key
    // the profile's policy refuses is no edge either, and any other failure
    // still stops the search.
    use structured_pkix::path::{EffectiveKey, Verified, Verify};
    use xml_sec::provider::{ProviderError, ProviderOperation};
    use xml_sec::xmldsig::X509ChainError;
    struct Failing(fn() -> X509ChainError);
    impl<W: structured_asn1::memory::Work> Verify<W> for Failing {
        type Error = X509ChainError;
        fn verify(
            &self,
            _: &structured_pkix::algorithm::AlgorithmIdentifier<'_>,
            _: EffectiveKey<'_>,
            _: &[u8],
            _: structured_pkix::signature::SignatureValue<'_>,
            _: &W,
        ) -> Result<Verified, X509ChainError> {
            Err((self.0)())
        }
    }
    let memory = super::account();
    let parser = structured_asn1::Parser::der(memory.clone());
    let issuer = structured_pkix::Certificate::read(&parser, ISSUER, 0).unwrap();
    let ask = |inner: &Failing| {
        super::EdgeVerifier(inner).verify(
            &issuer.signature_algorithm(),
            EffectiveKey::standing(issuer.tbs().public_key()),
            issuer.signed_bytes(),
            issuer.signature_value(),
            &memory,
        )
    };
    let unsupported = Failing(|| {
        X509ChainError::Provider(ProviderError::Unsupported {
            operation: ProviderOperation::VerifyCertificate,
            algorithm: Some("2.16.840.1.101.3.4.3.14".into()),
        })
    });
    assert_eq!(ask(&unsupported).unwrap(), Verified::Unsupported);
    let other = Failing(|| X509ChainError::InvalidDepth);
    assert!(ask(&other).is_err());
}

#[test]
fn a_delta_crl_finding_keeps_its_complete_crl_as_provenance() {
    // A delta CRL's status stands only with the complete CRL it is read
    // against: the long-term process must prove both in the past, so the
    // base CRL and its signer travel with the finding, and a finding whose
    // base signer the comparison does not know cannot be used at all.
    let memory = super::account();
    let parser = structured_asn1::Parser::der(memory);
    let issuer = structured_pkix::Certificate::read(&parser, ISSUER, 0).unwrap();
    let root = structured_pkix::Certificate::read(&parser, ROOT, 0).unwrap();
    let catalogue = super::etsi::long_term::Catalogue {
        tokens: 0,
        certificates: vec![&issuer, &root],
        sources: 2,
        positions: Vec::new(),
    };
    let record = |base: Option<(usize, Vec<u8>)>| super::etsi::Record {
        source: 1,
        signer: ISSUER.to_vec(),
        base,
        issued: structured_pkix::temporal::Instant::new(1_700_000_000, 0).unwrap(),
        revoked: None,
    };
    let data = super::etsi::long_term::data(&[record(Some((0, ROOT.to_vec())))], &catalogue);
    let base = data[0].base.expect("the delta keeps its complete CRL");
    assert_eq!(base.object, catalogue.source(0));
    assert_ne!(base.issuer, data[0].issuer);
    assert!(
        super::etsi::long_term::data(&[record(None)], &catalogue)[0]
            .base
            .is_none()
    );
    let unknown = super::etsi::long_term::data(&[record(Some((0, b"other".to_vec())))], &catalogue);
    assert!(unknown.is_empty());
}

#[test]
fn a_chain_search_past_its_bound_is_an_error_not_an_absent_chain() {
    // Certificates sharing their names multiply the orderings the search
    // tries; one cut short must not read as "no valid path".
    let memory = super::account();
    let parser = structured_asn1::Parser::der(memory.clone());
    let carried = super::pool(B_T);
    let pool: Vec<_> = carried
        .iter()
        .map(|der| structured_pkix::Certificate::read(&parser, der, 0).unwrap())
        .collect();
    let anchors = [structured_pkix::Certificate::read(&parser, ROOT, 0).unwrap()];
    let declared = declarations(B_T);
    let signer = super::etsi::signing_certificate(&declared[0], &pool, &memory).unwrap();
    let issuers = [structured_pkix::Certificate::read(&parser, ISSUER, 0).unwrap()];
    let bounds = super::etsi::search_bounds();
    let found =
        super::etsi::candidates_within(signer, &issuers, &anchors, &memory, bounds).unwrap();
    assert_eq!(found.len(), 1);
    let tight = structured_pkix::path::Bounds { edges: 1, ..bounds };
    let cut =
        super::etsi::candidates_within(signer, &issuers, &anchors, &memory, tight).unwrap_err();
    assert!(cut.contains("stopped"), "{cut}");
}

#[test]
fn a_reference_digest_the_profile_refuses_is_unknown_to_the_process() {
    // The strict profiles admit RSA-SHA224 signatures but not a SHA-224
    // reference digest; the one hash list of the constraints holds SHA-224
    // for the suite, so the reference digest must not be presented as it.
    use structured_ltv::validation::Hash;
    let references = [Hash::Sha256, Hash::Sha384, Hash::Sha512];
    assert_eq!(
        super::etsi::reference_hash(Some(DigestAlgorithm::Sha224), &references),
        Hash::Other
    );
    assert_eq!(
        super::etsi::reference_hash(Some(DigestAlgorithm::Sha256), &references),
        Hash::Sha256
    );
    assert_eq!(super::etsi::reference_hash(None, &references), Hash::Other);
}

#[test]
fn certificate_values_join_the_pool() {
    // EN 319 132-1 section 5.5.1: CertificateValues carries the issuers as
    // EncapsulatedX509Certificate; without them a signer in KeyInfo would
    // look like the end of its own chain.
    let text = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" \
        xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\"><ds:KeyInfo><ds:X509Data>\
        <ds:X509Certificate>AQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>\
        <xades:CertificateValues><xades:EncapsulatedX509Certificate>Ag==\
        </xades:EncapsulatedX509Certificate></xades:CertificateValues></ds:Signature>";
    assert_eq!(super::pool(text), [vec![1], vec![2]]);
}

#[test]
fn a_readable_token_keeps_its_authorities_when_another_is_unreadable() {
    // An unreadable token is reported on its own; the certificates and policy
    // of a readable one after it still count.
    let readable = include_str!("../../tests/fixtures/levels/b-t.xml");
    let (alone, none) = tokens::token_authorities(readable, &[]);
    assert!(none.is_empty(), "{none:?}");
    assert_ne!(alone.len(), 0);
    let text = readable.replacen(
        "<xades:EncapsulatedTimeStamp>",
        "<xades:EncapsulatedTimeStamp>AQ==</xades:EncapsulatedTimeStamp>\
         <xades:EncapsulatedTimeStamp>",
        1,
    );
    let (authorities, failures) = tokens::token_authorities(&text, &[]);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(authorities, alone);
}

#[test]
fn only_an_elements_value_is_read_and_where_the_element_is() {
    // A certificate in a comment carries nothing and has no place in the
    // document, which archive coverage reads; the element's character
    // references (`&#13;` in base64) are part of its value.
    let text = "<a xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\
        <!-- <X509Certificate>AQ==</X509Certificate> -->\
        <b/><X509Certificate>A&#13;Q==</X509Certificate></a>";
    let found = tokens::values_at(text, tokens::Field::Certificate);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, vec![1]);
    let before = tokens::values_at(
        "<a xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\
         <X509Certificate>AQ==</X509Certificate><b/></a>",
        tokens::Field::Certificate,
    );
    assert!(before[0].0 < found[0].0, "{before:?} {found:?}");
}

#[test]
fn only_a_signature_certificate_field_carries_a_certificate() {
    // XMLDSig's X509Certificate and XAdES's EncapsulatedX509Certificate are
    // the certificate fields; an application element that only shares the
    // suffix, or the local name in another namespace, carries none, or it
    // could anchor a chain at a certificate the signature does not carry.
    let text = "<r xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" \
        xmlns:x=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:a=\"urn:app\">\
        <ds:X509Certificate>AQ==</ds:X509Certificate>\
        <x:EncapsulatedX509Certificate>Ag==</x:EncapsulatedX509Certificate>\
        <a:BackupX509Certificate>Aw==</a:BackupX509Certificate>\
        <a:X509Certificate>BA==</a:X509Certificate>\
        <x:Example xmlns:x=\"http://uri.etsi.org/01903/example\">\
        <x:EncapsulatedX509Certificate>BQ==</x:EncapsulatedX509Certificate></x:Example></r>";
    assert_eq!(
        tokens::values(text, tokens::Field::Certificate),
        [vec![1], vec![2]]
    );
}

#[test]
fn a_value_split_by_a_comment_is_read_whole() {
    // The XML Infoset gives an element its characters, comments left out: a
    // comment inside base64 or a date splits text nodes, not the value. An
    // element with element content carries no simple value.
    let split = "<ds:X509Certificate xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
        AQ<!-- c -->ID</ds:X509Certificate>";
    assert_eq!(
        tokens::values(split, tokens::Field::Certificate),
        [vec![1, 2, 3]]
    );
    let nested = "<ds:X509Certificate xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
        AQ<i>ID</i></ds:X509Certificate>";
    assert_eq!(
        tokens::values(nested, tokens::Field::Certificate),
        Vec::<Vec<u8>>::new()
    );
}

#[test]
fn a_token_whose_base64_does_not_decode_is_reported_not_dropped() {
    // A malformed EncapsulatedTimeStamp is this signature's token all the
    // same: the census declares it and the authority reader reports it, while
    // a readable sibling keeps its own result.
    let readable = include_str!("../../tests/fixtures/levels/b-t.xml");
    let text = readable.replacen(
        "<xades:EncapsulatedTimeStamp>",
        "<xades:EncapsulatedTimeStamp>!!</xades:EncapsulatedTimeStamp>\
         <xades:EncapsulatedTimeStamp>",
        1,
    );
    let (authorities, failures) = tokens::token_authorities(&text, &[]);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(failures[0].contains("base64"), "{failures:?}");
    assert_eq!(authorities, tokens::token_authorities(readable, &[]).0);
    let declared = declarations(&text);
    assert_eq!(declared[0].signature_timestamps.len(), 1);
    assert_eq!(declared[0].undecodable_timestamps.len(), 1);
}

#[test]
fn a_timestamp_property_counts_only_in_its_own_container() {
    // A SignatureTimeStamp is an unsigned signature property and a content
    // timestamp a signed data-object property (EN 319 132-1 sections 4.3.5,
    // 4.3.6); one placed in the other container is no timestamp of either.
    let text = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig">
  <ds:SignedInfo/>
  <ds:Object>
    <x:QualifyingProperties xmlns:x="http://uri.etsi.org/01903/v1.3.2#" Target="#sig">
      <x:SignedProperties><x:SignedDataObjectProperties>
        <x:SignatureTimeStamp><x:EncapsulatedTimeStamp>AQ==</x:EncapsulatedTimeStamp></x:SignatureTimeStamp>
        <x:AllDataObjectsTimeStamp><x:EncapsulatedTimeStamp>Ag==</x:EncapsulatedTimeStamp></x:AllDataObjectsTimeStamp>
      </x:SignedDataObjectProperties></x:SignedProperties>
      <x:UnsignedProperties><x:UnsignedSignatureProperties>
        <x:AllDataObjectsTimeStamp><x:EncapsulatedTimeStamp>Aw==</x:EncapsulatedTimeStamp></x:AllDataObjectsTimeStamp>
      </x:UnsignedSignatureProperties></x:UnsignedProperties>
    </x:QualifyingProperties>
  </ds:Object>
</ds:Signature>"##;
    let found = declarations(text);
    assert_eq!(found[0].signature_timestamps, Vec::<Vec<u8>>::new());
    assert_eq!(
        found[0].content_timestamps,
        [(xml_sec_xades::TimestampRole::AllDataObjects, vec![2])]
    );
}

#[test]
fn a_signing_time_counts_only_when_the_signature_signs_it() {
    // SignedProperties is signed only when a reference of the signature's own
    // SignedInfo names it (EN 319 132-1 section 4.3.2): an unreferenced one
    // claims no time the signature protects.
    let unreferenced = CLAIMS.replace("URI=\"#props\"", "URI=\"#other\"");
    assert_ne!(unreferenced, CLAIMS);
    assert_eq!(declarations(&unreferenced)[0].signing_time, None);
    assert_eq!(declarations(CLAIMS)[0].signing_time, Some(1_577_836_800));
}

#[test]
fn a_qualifying_properties_outside_the_xades_namespaces_is_not_the_signatures() {
    // EN 319 132-1 section 4.2 names the XAdES namespaces; a namespace that
    // only shares their prefix is another vocabulary, and its container must
    // not stand in for the genuine one.
    let decoy = CLAIMS.replace(
        "<ds:Object>\n    <x:QualifyingProperties",
        "<ds:Object><x:QualifyingProperties xmlns:x=\"http://uri.etsi.org/01903/example\" \
         Target=\"#sig\"><x:SignedProperties Id=\"props\"><x:SignedSignatureProperties>\
         <x:SigningTime>2030-01-01T00:00:00Z</x:SigningTime></x:SignedSignatureProperties>\
         </x:SignedProperties></x:QualifyingProperties></ds:Object>\n  <ds:Object>\n    <x:QualifyingProperties",
    );
    assert_ne!(decoy, CLAIMS);
    assert_eq!(declarations(&decoy)[0].signing_time, Some(1_577_836_800));
}

#[test]
fn an_entity_supplied_certificate_is_where_the_entity_is_referenced() {
    // EN 319 132-1 section 5.5.2: an archive timestamp covers the validation
    // data before it in the document. A certificate an internal entity
    // supplies after the timestamp is there, not at the entity declaration
    // before it.
    let text = "<!DOCTYPE a [<!ENTITY c \"<ds:X509Certificate>AQ==</ds:X509Certificate>\">]>\
        <a xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" \
        xmlns:x=\"http://uri.etsi.org/01903/v1.4.1#\">\
        <x:ArchiveTimeStamp><x:EncapsulatedTimeStamp>Ag==</x:EncapsulatedTimeStamp>\
        </x:ArchiveTimeStamp>&c;</a>";
    let certificate = tokens::values_at(text, tokens::Field::Certificate);
    let token = tokens::values_at(text, tokens::Field::TIMESTAMP);
    assert_eq!(certificate.len(), 1);
    assert!(token[0].0 < certificate[0].0, "{token:?} {certificate:?}");
}

/// A signature with two tokens in one `ArchiveTimeStamp` and one in a later
/// property, an RFC 3161 token in each V2 validation-data timestamp, and a
/// decoy `SignatureTimeStamp` in a foreign namespace inside a `ds:Object`.
const STAMPED: &str = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig">
  <ds:SignedInfo/>
  <ds:Object>
    <x:QualifyingProperties xmlns:x="http://uri.etsi.org/01903/v1.3.2#" xmlns:v="http://uri.etsi.org/01903/v1.4.1#" Target="#sig">
      <x:UnsignedProperties><x:UnsignedSignatureProperties>
        <x:SignatureTimeStamp><x:EncapsulatedTimeStamp>AQ==</x:EncapsulatedTimeStamp></x:SignatureTimeStamp>
        <v:SigAndRefsTimeStampV2><x:EncapsulatedTimeStamp>Ag==</x:EncapsulatedTimeStamp></v:SigAndRefsTimeStampV2>
        <v:RefsOnlyTimeStampV2><x:EncapsulatedTimeStamp>Aw==</x:EncapsulatedTimeStamp></v:RefsOnlyTimeStampV2>
        <v:ArchiveTimeStamp>
          <x:EncapsulatedTimeStamp>BA==</x:EncapsulatedTimeStamp>
          <x:EncapsulatedTimeStamp>BQ==</x:EncapsulatedTimeStamp>
        </v:ArchiveTimeStamp>
        <v:ArchiveTimeStamp><x:EncapsulatedTimeStamp>Bg==</x:EncapsulatedTimeStamp></v:ArchiveTimeStamp>
      </x:UnsignedSignatureProperties></x:UnsignedProperties>
    </x:QualifyingProperties>
  </ds:Object>
  <ds:Object>
    <y:SignatureTimeStamp xmlns:y="urn:other"><y:EncapsulatedTimeStamp>Bw==</y:EncapsulatedTimeStamp></y:SignatureTimeStamp>
  </ds:Object>
</ds:Signature>"##;

#[test]
fn only_the_signatures_own_timestamp_properties_are_counted_in_every_form() {
    // EN 319 132-1 Annex A: the V2 validation-data timestamps of the v1.4.1
    // namespace keep the references-only and signature-and-references
    // coverage apart. Only the XAdES properties of this signature's own
    // UnsignedSignatureProperties count, the path check_tokens reads; a
    // same-named element elsewhere would take a genuine token's result.
    let found = declarations(STAMPED);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].signature_timestamps, [vec![1]]);
    assert_eq!(found[0].validation_timestamps, [vec![2], vec![3]]);
    assert_eq!(found[0].refs_only, [false, true]);
    assert_eq!(found[0].archive_timestamps, [vec![4], vec![5], vec![6]]);
}

#[test]
fn a_certificate_only_the_caller_supplies_is_never_archived() {
    // An archive imprint authenticates what the document holds before the
    // property (EN 319 132-1 section 5.5.2); a trust anchor only the caller
    // supplies has no place there, so no archive timestamp covers it.
    let positions = [Some(3), None, Some(9)];
    let covered: Vec<usize> = super::etsi::long_term::archived_before(&positions, 3, 5).collect();
    assert_eq!(covered, [0]);
}

#[test]
fn tokens_of_one_archive_timestamp_do_not_cover_each_other() {
    // EN 319 132-1 section 5.5.2: every token of one ArchiveTimeStamp stamps
    // the same input, which neither of them is part of; a token of an earlier
    // ArchiveTimeStamp is part of a later one's input.
    let found = declarations(STAMPED);
    let positions = &found[0].archive_positions;
    assert_eq!(positions[0], positions[1]);
    assert!(positions[1] < positions[2]);
    assert_eq!(
        super::etsi::earlier_archives(positions, 0),
        Vec::<usize>::new()
    );
    assert_eq!(
        super::etsi::earlier_archives(positions, 1),
        Vec::<usize>::new()
    );
    assert_eq!(super::etsi::earlier_archives(positions, 2), [0, 1]);
}

#[test]
fn only_a_lexical_xs_date_time_reads_as_an_instant() {
    // XML Schema 1.1 Part 2 section 3.3.7: a dateTime names a day of its
    // month, with these separators and an optional zone of ±hh:mm or Z. An
    // impossible day used to roll over into the next month.
    assert_eq!(date_time("2026-02-28T12:00:00Z"), Some(1_772_280_000));
    assert_eq!(
        date_time("2026-02-28T13:00:00.25+01:00"),
        Some(1_772_280_000)
    );
    assert_eq!(date_time("2024-02-29T00:00:00"), Some(1_709_164_800));
    assert_eq!(date_time("2026-02-28T24:00:00.0Z"), Some(1_772_323_200));
    for invalid in [
        "2026-02-30T12:00:00Z",
        "2025-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026/02/28T12:00:00Z",
        "2026-02-28 12:00:00Z",
        "2026-02-28T24:00:01Z",
        "2026-02-28T12:60:00Z",
        "2026-02-28T12:00:00+0100",
        "2026-02-28T12:00:00Zjunk",
        "2026-02-28T12:00:00.Z",
        // Only 24:00:00 itself names the end of the day, no fraction past it.
        "2026-02-28T24:00:00.1Z",
        // Each zone field is two digits, without a sign of its own.
        "2026-02-28T12:00:00+-1:00",
        "2026-02-28T12:00:00+01:-1",
    ] {
        assert_eq!(date_time(invalid), None, "{invalid}");
    }
}
use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm};

/// A signature whose `ds:Object` carries elements named like the ones of its
/// `ds:SignedInfo`, in a foreign namespace and in `ds` itself.
const DECOYED: &str = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#o">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AA==</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
  <ds:Object Id="o">
    <x:SignatureMethod xmlns:x="urn:other" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Object>
</ds:Signature>"##;

/// A signature whose signed properties claim a time and a certificate, with
/// same-named elements outside them: in a foreign `ds:Object` and in the
/// unsigned `CompleteCertificateRefs`.
const CLAIMS: &str = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig">
  <ds:SignedInfo>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="#props" Type="http://uri.etsi.org/01903#SignedProperties"/>
  </ds:SignedInfo>
  <ds:Object>
    <x:QualifyingProperties xmlns:x="http://uri.etsi.org/01903/v1.3.2#" Target="#sig">
      <x:SignedProperties Id="props">
        <x:SignedSignatureProperties>
          <x:SigningTime>2020-01-01T00:00:00Z</x:SigningTime>
          <x:SigningCertificateV2><x:Cert><x:CertDigest>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>AQ==</ds:DigestValue>
          </x:CertDigest></x:Cert></x:SigningCertificateV2>
        </x:SignedSignatureProperties>
      </x:SignedProperties>
      <x:UnsignedProperties><x:UnsignedSignatureProperties>
        <x:CompleteCertificateRefs><x:CertRefs><x:Cert><x:CertDigest>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>Ag==</ds:DigestValue>
        </x:CertDigest></x:Cert></x:CertRefs></x:CompleteCertificateRefs>
      </x:UnsignedSignatureProperties></x:UnsignedProperties>
    </x:QualifyingProperties>
  </ds:Object>
  <ds:Object>
    <y:SigningTime xmlns:y="urn:other">2030-01-01T00:00:00Z</y:SigningTime>
    <y:CertDigest xmlns:y="urn:other"><ds:DigestValue>Aw==</ds:DigestValue></y:CertDigest>
  </ds:Object>
</ds:Signature>"##;

#[test]
fn a_double_quoted_xpointer_id_names_its_element() {
    // XPointer's id() takes either quote (XMLDSig 1.1 section 4.4.3.3); the
    // verifier resolves both, so the expected target must be the element.
    let text = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:Reference URI='#xpointer(id("payload"))'/>
    <ds:Reference URI="#xpointer(id('other'))"/>
  </ds:SignedInfo>
</ds:Signature>"##;
    assert_eq!(
        super::targets(text),
        [
            super::Target::Id("payload".into()),
            super::Target::Id("other".into())
        ]
    );
}

#[test]
fn an_escaped_fragment_names_the_element_the_verifier_resolves() {
    // XPointer Framework sections 3 and 4: URI escaping is reversed before
    // the pointer is evaluated, and `^` escapes a parenthesis in scheme data;
    // the compared profiles resolve same-document IDs so (Specification).
    let text = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:Reference URI='#xpointer(id("%70ayload"))'/>
    <ds:Reference URI="#%6Fther"/>
    <ds:Reference URI="#xpointer(id('a^(b^)'))"/>
  </ds:SignedInfo>
</ds:Signature>"##;
    assert_eq!(
        super::targets(text),
        [
            super::Target::Id("payload".into()),
            super::Target::Id("other".into()),
            super::Target::Id("a(b)".into())
        ]
    );
}

#[test]
fn every_expected_target_is_named_once_whatever_its_aliases() {
    // `URI=""` and the root's own Id name one node; the verification request
    // refuses a repeated target, so the root must stand once even when the
    // two references are not adjacent.
    let text = r##"<doc xmlns="urn:x" Id="doc"><payload Id="payload"/>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:Reference URI=""/>
    <ds:Reference URI="#payload"/>
    <ds:Reference URI="#doc"/>
  </ds:SignedInfo>
</ds:Signature></doc>"##;
    let document = xml_sec::XmlDocument::parse(text).unwrap();
    let found = super::expected_targets(&document, text);
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn a_certificate_outside_the_signatures_key_info_is_no_key_info_certificate() {
    // ds:KeyInfo is a direct child of ds:Signature (XMLDSig 1.1 section 4.5);
    // a KeyInfo inside a ds:Object identifies nothing about this signature.
    let text = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo/>
  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  <ds:Object><ds:KeyInfo><ds:X509Data><ds:X509Certificate>Ag==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Object>
</ds:Signature>"#;
    let found = declarations(text);
    assert_eq!(found[0].key_info, [vec![1]]);
}

#[test]
fn a_utf_16_document_is_read_as_the_parser_reads_it() {
    // XML 1.0 section 4.3.3: a byte order mark selects UTF-16, and the
    // verification parses the document so; its text view must hold the same
    // signing time, or the facts would miss what the signature claims.
    let mut bytes = vec![0xFF, 0xFE];
    for unit in CLAIMS.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    let text = super::ascii_view(&bytes);
    assert_eq!(super::signing_times(&text), [Some(1_577_836_800)]);
}

#[test]
fn claims_are_read_only_from_the_signatures_signed_properties() {
    // EN 319 132-1 sections 5.2.1 and 5.2.2: the claimed signing time and the
    // signing certificate are signed signature properties of this signature's
    // QualifyingProperties. An element of the same name elsewhere, signed or
    // not, claims nothing.
    let found = declarations(CLAIMS);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].signing_time, Some(1_577_836_800));
    assert_eq!(
        found[0].certificate_references,
        [(Some(DigestAlgorithm::Sha256), vec![1])]
    );
}

#[test]
fn the_declared_algorithms_are_read_from_the_signatures_own_signed_info() {
    // Only the signature's own ds:SignedInfo declares its algorithms (XMLDSig
    // 1.1 section 4.4): a later element of the same name elsewhere must not
    // replace them, or the compared profile's constraints judge another
    // algorithm than the one the signature uses.
    let found = declarations(DECOYED);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].method, Some(SignatureAlgorithm::RsaSha1));
    assert_eq!(found[0].digests, [Some(DigestAlgorithm::Sha1)]);
    // Nor does a SignedInfo inside an Object name a target the signature
    // must cover.
    assert_eq!(super::targets(DECOYED), [super::Target::Id("o".into())]);
}
