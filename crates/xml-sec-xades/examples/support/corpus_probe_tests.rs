use super::{date_time, declarations, tokens};

#[test]
fn a_token_copied_into_another_property_keeps_that_propertys_result() {
    // The same token bytes under an ArchiveTimeStamp stamp other input than
    // under the SignatureTimeStamp they were made for; each property's own
    // result applies, never the first one found for those bytes.
    use xml_sec_xades::TimestampRole;
    let token = vec![1, 2, 3];
    let declared = super::etsi::Declared {
        signature_timestamps: vec![token.clone()],
        archive_timestamps: vec![token.clone()],
        token_integrity: vec![
            (TimestampRole::Signature, token.clone(), Some(true)),
            (TimestampRole::Archive, token.clone(), Some(false)),
        ],
        ..super::etsi::Declared::default()
    };
    assert_eq!(
        declared.intact(TimestampRole::Signature, 0, &token),
        Some(true)
    );
    assert_eq!(
        declared.intact(TimestampRole::Archive, 0, &token),
        Some(false)
    );
    assert_eq!(declared.intact(TimestampRole::Archive, 0, &[9]), None);
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
    let found = super::etsi::candidates_within(signer, &issuers, &anchors, &memory, 100).unwrap();
    assert_eq!(found.len(), 1);
    let cut = super::etsi::candidates_within(signer, &issuers, &anchors, &memory, 2).unwrap_err();
    assert!(cut.contains("exceeded 2"), "{cut}");
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
    let text = "<a><!-- <X509Certificate>AQ==</X509Certificate> -->\
        <X509Certificate>A&#13;Q==</X509Certificate></a>";
    let found = tokens::values_at(text, "X509Certificate");
    assert_eq!(found, [(text.rfind("<X509Certificate").unwrap(), vec![1])]);
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
  </ds:SignedInfo>
  <ds:Object>
    <x:QualifyingProperties xmlns:x="http://uri.etsi.org/01903/v1.3.2#" Target="#sig">
      <x:SignedProperties>
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
    assert_eq!(super::signing_time(&text), Some(1_577_836_800));
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
