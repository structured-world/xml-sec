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
    let text = "<ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AQ==\
        </ds:X509Certificate></ds:X509Data></ds:KeyInfo><xades:CertificateValues>\
        <xades:EncapsulatedX509Certificate>Ag==</xades:EncapsulatedX509Certificate>\
        </xades:CertificateValues></ds:Signature>";
    assert_eq!(super::pool(text), [vec![1], vec![2]]);
}

#[test]
fn a_readable_token_keeps_its_authorities_when_another_is_unreadable() {
    // An unreadable token is reported on its own; the certificates of the
    // readable ones still count.
    let (authorities, failures) =
        tokens::token_authorities("<EncapsulatedTimeStamp>AQ==</EncapsulatedTimeStamp>", &[]);
    assert_eq!(authorities.len(), 0);
    assert_eq!(failures.len(), 1);
}

#[test]
fn an_unterminated_character_reference_is_kept_as_text_in_one_pass() {
    // Each `&#` without its `;` used to scan the rest of the value again.
    let text = "&#1".repeat(20_000) + "&#65;";
    let decoded = tokens::character_references(&text);
    assert!(decoded.ends_with('A'));
    assert_eq!(decoded.len(), 20_000 * 3 + 1);
    assert_eq!(
        tokens::character_references("a&#xD;b&#13;c&#x;d"),
        "a\rb\rc&#x;d"
    );
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
