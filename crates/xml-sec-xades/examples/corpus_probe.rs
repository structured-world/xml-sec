//! The facts the EU DSS corpus comparison reads, through the public API under
//! one of the `XAdES` policy profiles.
//!
//! `corpus_probe conditions XML ANCHORS_DIR` writes, as `0.der`, `1.der`, ...
//! in `ANCHORS_DIR`, which must be empty or absent, the topmost certificate of
//! each signer chain the document carries, and prints the document's claimed
//! signing time.
//!
//! `corpus_probe facts XML ANCHORS_DIR UNIX_TIME PROFILE` verifies the
//! document at that time with those certificates as the only trust anchors
//! and prints, for each Signature in document order, its verification outcome
//! and the `XAdES` facts of every baseline level. `PROFILE` is `xades`,
//! `xades-extended` or `xades-conformant`.
//!
//! The anchors, the time and the stated accuracy of tokens that omit theirs
//! (zero, the generation time read as exact) are conditions of the
//! comparison, the same ones the other validator receives, never a trust
//! decision. The policy is the compiled profile, narrowed only to check
//! X.509 chains at that time.

#[path = "support/etsi.rs"]
mod etsi;
#[cfg(test)]
#[path = "support/corpus_probe_tests.rs"]
mod tests;
#[path = "support/tokens.rs"]
mod tokens;

use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_ltv::validation::{Family, Hash};
use structured_pkix::Certificate;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::document::NodeIdentity;
use xml_sec::policy::{
    Instant, PolicyCompileContext, PolicyCompiler, PolicyProfile, SignatureConstraints,
    TrustAnchorSigner, VerificationPolicy,
};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::UriTypeSet;
use xml_sec::xmldsig::{
    CallerTrustedSignatureKey, DefaultKeyResolver, DigestAlgorithm, DsigError, KeyInfo,
    KeyInfoSource, KeyResolver, KeyResolverConfig, ResolvedVerificationKey, SignatureAlgorithm,
    SignatureEvidence, VerificationKey, VerificationRequest, VerifyContext, VerifyingKey,
    with_verified_request,
};
use xml_sec_xades::{
    EnclosingError, Inputs, Level, Outcome, Requirements, Syntax, TimestampRole, TokenIntegrity,
    ValidationError, check_tokens, validate, validate_basic, validate_ts101903,
};

type Failure = Box<dyn std::error::Error>;

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 27, 1 << 33)))
}

/// Whether the key of `certificate` decodes as its algorithm defines it. A
/// trust anchor's public key is part of its information (RFC 5280 §6.1.1
/// (d)), so a certificate whose key does not decode anchors nothing for
/// either validator.
fn readable_key(certificate: &Certificate<'_>, account: &Memory) -> bool {
    use structured_pkix::key::{ec, rsa};
    let info = certificate.tbs().public_key();
    let algorithm = info.algorithm().algorithm();
    if algorithm == structured_pkix::oid::EC_PUBLIC_KEY {
        ec::read(structured_pkix::path::EffectiveKey::standing(info), account).is_ok()
    } else if algorithm == structured_pkix::oid::RSA_ENCRYPTION
        || algorithm == structured_pkix::oid::RSASSA_PSS
    {
        rsa::read(info, account).is_ok()
    } else {
        true
    }
}

/// The top of every chain from `start` through `pool`, once each: along every
/// issuer `issues` confirms, the certificate past which no issuer outside its
/// own chain continues. Two issuers of one subordinate (a self-signed CA and
/// its cross-certificate, two cross-certificates) are two branches, and the
/// order the document carries them in prefers neither. More than `limit`
/// issuer tests is an error, not a shorter chain.
fn chain_tops<T: Copy + PartialEq>(
    start: T,
    pool: &[T],
    issues: impl Fn(T, T) -> bool,
    limit: usize,
) -> Result<Vec<T>, String> {
    let mut tops = Vec::new();
    let mut chains = vec![vec![start]];
    let mut steps = 0usize;
    while let Some(chain) = chains.pop() {
        let subject = *chain.last().expect("a chain starts with its subject");
        let mut continued = false;
        for &issuer in pool {
            if chain.contains(&issuer) {
                continue;
            }
            steps += 1;
            if steps > limit {
                return Err(format!("the chain search exceeded {limit} issuer tests"));
            }
            if issues(issuer, subject) {
                let mut longer = chain.clone();
                longer.push(issuer);
                chains.push(longer);
                continued = true;
            }
        }
        if !continued && !tops.contains(&subject) {
            tops.push(subject);
        }
    }
    Ok(tops)
}

/// The topmost certificate of each signature's signer chain the document
/// carries, once each: from the signing certificate, each issuer in `pool`
/// that the subject names and whose key verifies the subject's signature
/// (RFC 5280 6.1.3 (a)(1) and (a)(4)), up to a certificate with no such
/// issuer, the top of every such branch ([`chain_tops`]). A certificate that
/// only shares the issuer's name issues
/// nothing, and a timestamp authority's chain anchors no signer. Only a
/// certificate whose key decodes is such an end. The second value says why
/// the document's signatures could not be read, when they could not.
fn signer_anchors(
    bytes: &[u8],
    text: &str,
    pool: &[Vec<u8>],
) -> Result<(Vec<Vec<u8>>, Option<String>), Failure> {
    let document = match XmlDocument::parse_bytes(bytes) {
        Ok(document) => document,
        Err(error) => return Ok((Vec::new(), Some(error.to_string()))),
    };
    let declared = declarations(text);
    // The session lends its certificate-signature verifier; no key or chain
    // of the document's own is trusted for it.
    let resolver = DefaultKeyResolver::new(KeyResolverConfig::default());
    let context = VerifyContext::new()
        .policy(profile_policy(PolicyProfile::XadesConformant, 0, false)?)
        .key_resolver(&resolver);
    let operation = account();
    let expected = expected_targets(&document, text);
    let request = VerificationRequest {
        expected_targets: &expected,
        ..VerificationRequest::default()
    };
    let mut found: Vec<Vec<u8>> = Vec::new();
    // A chain search cut short is a failure of the conditions, never fewer
    // anchors.
    let mut search: Option<String> = None;
    let run = with_verified_request(&document, &context, &request, &operation, |session| {
        let memory = account();
        let parser = Parser::der(memory.clone());
        let certificates: Vec<Certificate<'_>> = pool
            .iter()
            .filter_map(|der| Certificate::read(&parser, der, 0).ok())
            .collect();
        let issues = |issuer: &Certificate<'_>, subject: &Certificate<'_>| {
            use structured_pkix::path::{EffectiveKey, Verified, Verify};
            let named = subject
                .tbs()
                .issuer()
                .matches(issuer.tbs().subject(), &memory)
                .unwrap_or(false);
            let chain = [subject];
            named
                && Verify::<Memory>::verify(
                    &session.certificate_path_verifier(&chain, issuer),
                    &subject.signature_algorithm(),
                    EffectiveKey::standing(issuer.tbs().public_key()),
                    subject.signed_bytes(),
                    subject.signature_value(),
                    &memory,
                )
                .is_ok_and(|answer| answer == Verified::Yes)
        };
        // Each certificate by its place in the pool, which tells two equal
        // certificates apart no better than their bytes do: the pool holds
        // each once.
        let places: Vec<usize> = (0..certificates.len()).collect();
        for signature in &declared {
            let Some(signer) = etsi::signing_certificate(signature, &certificates, &memory) else {
                continue;
            };
            let start = certificates
                .iter()
                .position(|certificate| certificate.as_bytes() == signer.as_bytes())
                .expect("the signing certificate is one of the pool");
            let tops = match chain_tops(
                start,
                &places,
                |issuer, subject| issues(&certificates[issuer], &certificates[subject]),
                etsi::CANDIDATE_STEPS,
            ) {
                Ok(tops) => tops,
                Err(error) => {
                    search = Some(error);
                    return Ok(());
                }
            };
            for top in tops.into_iter().map(|top| &certificates[top]) {
                if readable_key(top, &memory) && !found.iter().any(|known| known == top.as_bytes())
                {
                    found.push(top.as_bytes().to_vec());
                }
            }
        }
        Ok(())
    });
    if let Some(error) = search {
        return Err(error.into());
    }
    // A document whose signatures cannot be read carries no signer chain;
    // why it could not be read stays with the conditions.
    match run {
        Ok(()) => Ok((found, None)),
        Err(error) => Ok((Vec::new(), Some(error.to_string()))),
    }
}

/// Every certificate the document and its tokens carry, once.
fn pool(text: &str) -> Vec<Vec<u8>> {
    // Every element named *X509Certificate: XMLDSig's X509Certificate and
    // XAdES's EncapsulatedX509Certificate (CertificateValues) alike.
    let carried = tokens::values(text, "X509Certificate");
    // A token that cannot be read carries no certificate the comparison could
    // anchor; the facts report why it could not be read.
    let (authorities, _) = tokens::token_authorities(text, &carried);
    let mut pool = carried;
    pool.extend(authorities.into_iter().map(|(certificate, _)| certificate));
    pool.sort();
    pool.dedup();
    pool
}

/// The first place in document order at which `text` carries each
/// certificate, CRL and OCSP response: its own element, or the timestamp
/// token that carries the certificate. [`declarations`] places archive
/// timestamps in the same order of the same parse.
fn document_positions(text: &str) -> Vec<(Vec<u8>, usize)> {
    let mut found: Vec<(Vec<u8>, usize)> = Vec::new();
    let mut add =
        |value: Vec<u8>, at: usize| match found.iter_mut().find(|(known, _)| *known == value) {
            Some(known) => known.1 = known.1.min(at),
            None => found.push((value, at)),
        };
    for tag in [
        "X509Certificate",
        "EncapsulatedCRLValue",
        "EncapsulatedOCSPValue",
    ] {
        for (at, value) in tokens::values_at(text, tag) {
            add(value, at);
        }
    }
    for (at, token) in tokens::values_at(text, "EncapsulatedTimeStamp") {
        for certificate in etsi::token_details(&token)
            .map(|facts| facts.certificates)
            .unwrap_or_default()
        {
            add(certificate, at);
        }
    }
    found
}

/// The claimed signing time of the document's first signature that signs
/// one, as Unix seconds.
fn signing_time(text: &str) -> Option<i64> {
    declarations(text)
        .iter()
        .find_map(|declared| declared.signing_time)
}

/// An `xs:dateTime` value (XML Schema 1.1 Part 2 section 3.3.7) as Unix
/// seconds, in the four-digit-year form `YYYY-MM-DDThh:mm:ss[.s+][Z|±hh:mm]`;
/// none for any other lexical form or an impossible date or time.
fn date_time(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = value.get(range)?;
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let separated = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')]
        .iter()
        .all(|(at, separator)| bytes.get(*at) == Some(separator));
    if !separated {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    // 24:00:00 is the end of the day, the only time with hour 24.
    let midnight = hour == 24 && minute == 0 && second == 0;
    if !(1..=days_in_month).contains(&day) || !(hour < 24 || midnight) || minute > 59 || second > 59
    {
        return None;
    }
    let mut zone = &value[19..];
    if let Some(fraction) = zone.strip_prefix('.') {
        let end = fraction
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(fraction.len());
        // 24:00:00 has no time after it within the day: a fraction there
        // is zero only.
        if end == 0 || (midnight && fraction[..end].bytes().any(|digit| digit != b'0')) {
            return None;
        }
        zone = &fraction[end..];
    }
    let offset = match zone.as_bytes() {
        [] | [b'Z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2]
            if [h1, h2, m1, m2].iter().all(|byte| byte.is_ascii_digit()) =>
        {
            let (hours, minutes) = (
                i64::from((h1 - b'0') * 10 + (h2 - b'0')),
                i64::from((m1 - b'0') * 10 + (m2 - b'0')),
            );
            if hours > 14 || minutes > 59 || (hours == 14 && minutes != 0) {
                return None;
            }
            let sign = if *sign == b'-' { -1 } else { 1 };
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };
    // Days from the civil date (proleptic Gregorian), as Howard Hinnant's
    // days_from_civil computes them.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let of_cycle = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    let days = era * 146_097 + of_cycle - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// The document's text for reading its ASCII values (base64, `SigningTime`,
/// IDs), decoded by the encoding rules the verification parses it under
/// (XML 1.0 section 4.3.3: byte order mark or declaration). Bytes those rules
/// refuse are read as UTF-8 with U+FFFD for what is not, which none of those
/// values contains; the verification then refuses the document itself.
fn ascii_view(bytes: &[u8]) -> String {
    // One source octet decodes to at most three UTF-8 octets (a BMP code
    // point from a single-byte encoding); a length that bound overflows has
    // no decoding to fit.
    bytes
        .len()
        .checked_mul(3)
        .and_then(|maximum| xml_sec::encoding::decode_xml_octets(bytes, maximum).ok())
        .map_or_else(
            || String::from_utf8_lossy(bytes).into_owned(),
            std::borrow::Cow::into_owned,
        )
}

fn conditions(xml: &str, anchors: &Path) -> Result<Value, Failure> {
    let bytes = std::fs::read(xml)?;
    let text = ascii_view(&bytes);
    let pool = pool(&text);
    std::fs::create_dir_all(anchors)?;
    // `facts` trusts every file of the directory, so one left by another
    // input would be trusted for this one.
    if std::fs::read_dir(anchors)?.next().is_some() {
        return Err(format!("{} is not empty", anchors.display()).into());
    }
    let (ends, unread) = signer_anchors(&bytes, &text, &pool)?;
    for (index, certificate) in ends.iter().enumerate() {
        std::fs::write(anchors.join(format!("{index}.der")), certificate)?;
    }
    let mut found = json!({
        "anchors": ends.len(),
        "signing_time": signing_time(&text),
    });
    if let Some(unread) = unread {
        found["unread"] = unread.into();
    }
    Ok(found)
}

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The common prefix of every ETSI `XAdES` namespace (v1.1.1, v1.2.2, v1.3.2,
/// v1.4.1).
const XADES_NAMESPACES: &str = "http://uri.etsi.org/01903/";

/// Whether `node` is the `XAdES` element `name`, in any ETSI `XAdES` namespace.
fn is_xades(node: &roxmltree::Node<'_, '_>, name: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node
            .tag_name()
            .namespace()
            .is_some_and(|namespace| namespace.starts_with(XADES_NAMESPACES))
}

/// The first `XAdES` child `name` of `node`.
fn xades_child<'a, 'i>(
    node: roxmltree::Node<'a, 'i>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'i>> {
    node.children().find(|child| is_xades(child, name))
}

/// What each `ds:Signature` declares, in document order: the elements that
/// belong to it and to no signature nested inside it.
fn declarations(text: &str) -> Vec<etsi::Declared> {
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    let is = |node: &roxmltree::Node<'_, '_>, name: &str| {
        node.is_element() && node.tag_name().name() == name
    };
    let is_signature = |node: &roxmltree::Node<'_, '_>| {
        is(node, "Signature") && node.tag_name().namespace() == Some(DS)
    };
    let base64 = |node: roxmltree::Node<'_, '_>| -> Option<Vec<u8>> {
        let compact: String = node
            .text()
            .unwrap_or_default()
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        structured_base64::STANDARD.decode(compact.as_bytes()).ok()
    };
    let mut found = Vec::new();
    for signature in document.descendants().filter(is_signature) {
        let mut declared = etsi::Declared::default();
        // The signature's algorithms are those of its own ds:SignedInfo, the
        // direct child (XMLDSig 1.1 section 4.4); a same-named element in an
        // Object declares nothing about this signature.
        let is_ds = |node: &roxmltree::Node<'_, '_>, name: &str| {
            is(node, name) && node.tag_name().namespace() == Some(DS)
        };
        if let Some(info) = signature
            .children()
            .find(|child| is_ds(child, "SignedInfo"))
        {
            declared.method = info
                .children()
                .find(|child| is_ds(child, "SignatureMethod"))
                .and_then(|method| method.attribute("Algorithm"))
                .and_then(SignatureAlgorithm::from_uri);
            declared.digests = info
                .children()
                .filter(|child| is_ds(child, "Reference"))
                .filter_map(|reference| {
                    reference
                        .children()
                        .find(|child| is_ds(child, "DigestMethod"))
                })
                .map(|method| {
                    method
                        .attribute("Algorithm")
                        .and_then(DigestAlgorithm::from_uri)
                })
                .collect();
        }
        signed_claims(signature, &mut declared);
        // The signature's own ds:KeyInfo is its direct child (XMLDSig 1.1
        // section 4.5); a KeyInfo inside an Object identifies nothing here.
        for key_info in signature.children().filter(|child| is_ds(child, "KeyInfo")) {
            for data in key_info.children().filter(|child| is_ds(child, "X509Data")) {
                for certificate in data
                    .children()
                    .filter(|child| is_ds(child, "X509Certificate"))
                {
                    declared.key_info.extend(base64(certificate));
                }
            }
        }
        own_timestamps(signature, &mut declared);
        found.push(declared);
    }
    found
}

/// The timestamp tokens of `signature`, into `declared`. A token of this
/// signature is an `EncapsulatedTimeStamp` of a `XAdES` timestamp property
/// of its own `QualifyingProperties` (EN 319 132-1 sections 5.2.8, 5.3, 5.5
/// and Annex A), the properties `check_tokens` reads; the same names
/// anywhere else stamp nothing.
fn own_timestamps(signature: roxmltree::Node<'_, '_>, declared: &mut etsi::Declared) {
    let base64 = |node: roxmltree::Node<'_, '_>| -> Option<Vec<u8>> {
        let compact: String = node
            .text()
            .unwrap_or_default()
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        structured_base64::STANDARD.decode(compact.as_bytes()).ok()
    };
    let properties = qualifying_properties(signature);
    let unsigned = properties
        .and_then(|properties| xades_child(properties, "UnsignedProperties"))
        .and_then(|unsigned| xades_child(unsigned, "UnsignedSignatureProperties"));
    let content = properties
        .and_then(|properties| xades_child(properties, "SignedProperties"))
        .and_then(|signed| xades_child(signed, "SignedDataObjectProperties"));
    let stamps = unsigned
        .into_iter()
        .chain(content)
        .flat_map(|container| container.children())
        .filter(roxmltree::Node::is_element);
    for property in stamps {
        let name = property.tag_name().name();
        if !is_xades(&property, name) {
            continue;
        }
        let encapsulated = property
            .children()
            .filter(|token| is_xades(token, "EncapsulatedTimeStamp"))
            .filter_map(base64);
        for token in encapsulated {
            match name {
                "SignatureTimeStamp" => declared.signature_timestamps.push(token),
                "SigAndRefsTimeStamp" | "SigAndRefsTimeStampV2" => {
                    declared.validation_timestamps.push(token);
                    declared.refs_only.push(false);
                }
                "RefsOnlyTimeStamp" | "RefsOnlyTimeStampV2" => {
                    declared.validation_timestamps.push(token);
                    declared.refs_only.push(true);
                }
                "AllDataObjectsTimeStamp" => declared
                    .content_timestamps
                    .push((TimestampRole::AllDataObjects, token)),
                "IndividualDataObjectsTimeStamp" => declared
                    .content_timestamps
                    .push((TimestampRole::IndividualDataObjects, token)),
                "ArchiveTimeStamp" => {
                    declared.archive_timestamps.push(token);
                    // Every token of one property stamps the same input: the
                    // property's place decides what each covers.
                    declared
                        .archive_positions
                        .push(tokens::node_order(property));
                }
                _ => {}
            }
        }
    }
}

/// The `QualifyingProperties` of `signature`: in one of its own `ds:Object`s,
/// targeting its `Id` when it has one (EN 319 132-1 section 4.3).
fn qualifying_properties<'a, 'i>(
    signature: roxmltree::Node<'a, 'i>,
) -> Option<roxmltree::Node<'a, 'i>> {
    let target = signature.attribute("Id").map(|id| format!("#{id}"));
    signature
        .children()
        .filter(|object| {
            object.is_element()
                && object.tag_name().name() == "Object"
                && object.tag_name().namespace() == Some(DS)
        })
        .flat_map(|object| object.children())
        .find(|properties| {
            is_xades(properties, "QualifyingProperties")
                && target
                    .as_deref()
                    .is_none_or(|target| properties.attribute("Target") == Some(target))
        })
}

/// The claimed signing time and the signing certificate references of
/// `signature`, into `declared`. Both are signed signature properties of the
/// signature's own `QualifyingProperties` (EN 319 132-1 sections 4.3, 5.2.1,
/// 5.2.2; TS 101 903 V1.2.2 7.2.1, 7.2.2); the same names anywhere else claim
/// nothing.
fn signed_claims(signature: roxmltree::Node<'_, '_>, declared: &mut etsi::Declared) {
    let ds = |node: &roxmltree::Node<'_, '_>, name: &str| {
        node.is_element()
            && node.tag_name().name() == name
            && node.tag_name().namespace() == Some(DS)
    };
    let Some(signed) = qualifying_properties(signature)
        .and_then(|properties| xades_child(properties, "SignedProperties"))
        .and_then(|signed| xades_child(signed, "SignedSignatureProperties"))
    else {
        return;
    };
    declared.signing_time = xades_child(signed, "SigningTime")
        .and_then(|time| date_time(time.text().unwrap_or_default().trim()));
    let certificates = xades_child(signed, "SigningCertificateV2")
        .or_else(|| xades_child(signed, "SigningCertificate"));
    for digest in certificates
        .into_iter()
        .flat_map(|certificates| certificates.children())
        .filter(|cert| is_xades(cert, "Cert"))
        .filter_map(|cert| xades_child(cert, "CertDigest"))
    {
        let method = digest
            .children()
            .find(|node| ds(node, "DigestMethod"))
            .and_then(|method| method.attribute("Algorithm"))
            .and_then(DigestAlgorithm::from_uri);
        let value = digest
            .children()
            .find(|node| ds(node, "DigestValue"))
            .and_then(|node| {
                let compact: String = node
                    .text()
                    .unwrap_or_default()
                    .chars()
                    .filter(|character| !character.is_ascii_whitespace())
                    .collect();
                structured_base64::STANDARD.decode(compact.as_bytes()).ok()
            });
        if let Some(value) = value {
            declared.certificate_references.push((method, value));
        }
    }
}

/// The profile's constraints in the ETSI process's vocabulary, owned: none
/// of them expires, as the profiles have no time dimension.
struct Rules {
    hashes: Vec<structured_ltv::validation::HashRule>,
    schemes: Vec<structured_ltv::validation::SchemeRule>,
    suites: Vec<(Family, Vec<Hash>)>,
    /// The digests the profile accepts in a `Reference`. The ETSI
    /// vocabulary, like DSS's, has one hash list for every material, so it
    /// also holds the suites' hashes; a reference digest outside this list
    /// is presented to it as unknown.
    reference_digests: Vec<Hash>,
}

impl Rules {
    /// `then` over these rules as the ETSI process's requirements.
    fn lend<R>(&self, then: impl FnOnce(&structured_ltv::validation::Requirements<'_>) -> R) -> R {
        let suites: Vec<structured_ltv::validation::SuiteRule<'_>> = self
            .suites
            .iter()
            .map(|(family, hashes)| structured_ltv::validation::SuiteRule {
                family: *family,
                key_bits: None,
                hashes,
            })
            .collect();
        then(&structured_ltv::validation::Requirements {
            crypto: structured_ltv::validation::Constraints {
                hashes: &self.hashes,
                schemes: &self.schemes,
                suites: &suites,
                rsa_exponent_bits: None,
            },
            // DSS's policy fails a signature without a claimed signing time
            // (`SigningTime Level="FAIL"`); no other element is required.
            elements: structured_ltv::validation::Elements::NONE
                .with(structured_ltv::validation::Element::ClaimedSigningTime),
            timestamp_delay: None,
        })
    }
}

fn rules(catalogue: &Catalogue) -> Rules {
    let mut hashes: Vec<Hash> = catalogue.digests.clone();
    hashes.extend(catalogue.suites.iter().filter_map(|(_, hash)| *hash));
    hashes.dedup();
    let mut suites: Vec<(Family, Vec<Hash>)> = Vec::new();
    for (family, hash) in &catalogue.suites {
        let entry = if let Some(entry) = suites.iter_mut().find(|(known, _)| known == family) {
            entry
        } else {
            suites.push((*family, Vec::new()));
            suites.last_mut().expect("just pushed")
        };
        entry.1.extend(*hash);
    }
    Rules {
        hashes: hashes
            .into_iter()
            .map(|hash| structured_ltv::validation::HashRule { hash, until: None })
            .collect(),
        // Every family keeps its minimum: certificates are restricted by key
        // size alone, while the suites below restrict the signature itself.
        schemes: catalogue
            .minimum_bits
            .iter()
            .map(|(family, bits)| structured_ltv::validation::SchemeRule {
                family: *family,
                min_bits: *bits,
                // DSA's subgroup is sized as TS 119 312 Table D.2 sizes the
                // discontinued 1024-bit tier.
                min_subgroup_bits: if *family == Family::Dsa { 160 } else { 0 },
                until: None,
            })
            .collect(),
        suites,
        reference_digests: catalogue.digests.clone(),
    }
}

/// The variant name of a debug rendering: its first identifier.
fn kind(debug: &str) -> String {
    debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// The `Id` of every `ds:Signature` in document order.
fn signature_ids(text: &str) -> Vec<Option<String>> {
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "Signature"
                && node.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
        })
        .map(|node| node.attribute("Id").map(str::to_owned))
        .collect()
}

/// A same-document object a data `Reference` names.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// The whole document: `URI=""` or `#xpointer(/)`.
    Root,
    /// The element with this ID: `#name` or `#xpointer(id('name'))`.
    Id(String),
}

/// `fragment` with its URI escaping reversed, as the verifier reads a
/// same-document fragment before evaluating it under the compared profiles'
/// `Specification` semantics (`XPointer` Framework sections 3 and 4); none when
/// an escape is malformed or decodes to no UTF-8, which the verifier refuses.
fn unescaped(fragment: &str) -> Option<String> {
    let bytes = fragment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut position = 0;
    while position < bytes.len() {
        if bytes[position] == b'%' {
            let hex = fragment.get(position + 1..position + 3)?;
            if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            position += 3;
        } else {
            decoded.push(bytes[position]);
            position += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// What every `Signature`'s data `Reference`s name in the document, the
/// `SignedProperties` reference excluded: the objects a validator reports as
/// the signature's scope, which the strict profile needs as expected targets.
fn targets(text: &str) -> Vec<Target> {
    const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let references = document.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Reference"
            && node.tag_name().namespace() == Some(DS)
            // A Signature's own SignedInfo only (XMLDSig 1.1 section 4.4); one
            // inside an Object signs nothing.
            && node.parent_element().is_some_and(|parent| {
                parent.tag_name().name() == "SignedInfo"
                    && parent.tag_name().namespace() == Some(DS)
                    && parent.parent_element().is_some_and(|signature| {
                        signature.tag_name().name() == "Signature"
                            && signature.tag_name().namespace() == Some(DS)
                    })
            })
            // EN 319 132-1 §4.4.2 and TS 101 903 V1.2.2 §6.3.1 type it.
            && !matches!(
                node.attribute("Type"),
                Some(
                    "http://uri.etsi.org/01903#SignedProperties"
                        | "http://uri.etsi.org/01903/v1.2.2#SignedProperties"
                )
            )
    });
    for reference in references {
        let target = match reference.attribute("URI") {
            Some("" | "#xpointer(/)") => Target::Root,
            Some(uri) => {
                let Some(fragment) = uri.strip_prefix('#').and_then(unescaped) else {
                    continue;
                };
                // XPointer's id() takes either quote, as the verifier reads it;
                // `^` escapes a parenthesis or itself in its scheme data
                // (XPointer Framework section 3.1).
                let id = ["'", "\""].iter().find_map(|quote| {
                    fragment
                        .strip_prefix(&format!("xpointer(id({quote}"))
                        .and_then(|rest| rest.strip_suffix(&format!("{quote}))")))
                });
                let id = match id {
                    Some(id) => {
                        let mut literal = String::with_capacity(id.len());
                        let mut characters = id.chars();
                        while let Some(character) = characters.next() {
                            literal.extend(if character == '^' {
                                characters.next()
                            } else {
                                Some(character)
                            });
                        }
                        literal
                    }
                    None => fragment,
                };
                if id == "xpointer(/)" {
                    Target::Root
                } else {
                    Target::Id(id)
                }
            }
            None => continue,
        };
        if !found.contains(&target) {
            found.push(target);
        }
    }
    found
}

/// Whether every requirement of the requested level holds.
fn met(level: &Level<'_>) -> bool {
    level.all_requirements_met()
}

/// A level outcome, or the typed refusal that stopped it.
fn level<E: std::fmt::Debug>(result: Result<Outcome<bool>, E>) -> Value {
    match result {
        Ok(Outcome::Assessed(met)) => json!({ "assessed": met }),
        Ok(outcome) => {
            json!({ "negative": kind(&format!("{outcome:?}")), "detail": format!("{outcome:?}") })
        }
        Err(error) => {
            let debug = format!("{error:?}");
            json!({ "error": kind(&debug), "detail": debug })
        }
    }
}

/// The `XAdES` profile a comparison names.
fn named_profile(name: &str) -> Result<PolicyProfile, Failure> {
    Ok(match name {
        "xades" => PolicyProfile::Xades,
        "xades-extended" => PolicyProfile::XadesExtended,
        "xades-conformant" => PolicyProfile::XadesConformant,
        _ => return Err(format!("unknown profile {name}").into()),
    })
}

/// The compiled `profile` at time `at`, narrowed to check X.509 chains when
/// `chains` is set; without it a key the resolver trusts directly is the only
/// key accepted, which establishes integrity apart from any path.
fn profile_policy(
    profile: PolicyProfile,
    at: i64,
    chains: bool,
) -> Result<VerificationPolicy, Failure> {
    let profile = PolicyCompiler::new(profile, &RustCryptoProvider, None)?;
    let mut layer = profile.policies().clone();
    if let Some(verification) = layer.verification.as_mut() {
        verification.key_trust.verify_x509_chains = chains;
        verification.key_trust.verification_time =
            Some(Instant::new(at, 0).ok_or("the time is out of range")?);
    }
    let snapshot = profile.restrict(&layer)?.compile(&PolicyCompileContext {
        external_resources: false,
        target_evidence: true,
    })?;
    Ok(snapshot
        .verification()
        .ok_or("the XAdES profiles verify")?
        .clone())
}

/// One signature's `XMLDSig` outcome: its status, key trust and references,
/// or the typed refusal that stopped it.
fn verification(entry: &SignatureEvidence) -> Value {
    match entry.result() {
        Ok(result) => json!({
            "status": format!("{:?}", result.status),
            "trust": kind(&format!("{:?}", result.key_trust)),
            "references": result
                .signed_info_references
                .iter()
                .map(|reference| format!("{:?}", reference.status))
                .collect::<Vec<_>>(),
        }),
        Err(error) => {
            let debug = format!("{error:?}");
            json!({ "error": kind(&debug), "detail": error.to_string() })
        }
    }
}

/// Every DER anchor `conditions` wrote into `directory`, in a fixed order.
fn read_anchors(directory: &Path) -> Result<Vec<Vec<u8>>, Failure> {
    let mut trusted = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        trusted.push(std::fs::read(entry?.path())?);
    }
    trusted.sort();
    Ok(trusted)
}

/// One signature's verification, its ETSI decision under the compared
/// profile and what its tokens established, from the widest profile's
/// integrity facts (`own`, `computed`) and what it declares.
fn signature_row(
    entry: &SignatureEvidence,
    (own, mut computed): (Value, Value),
    declared: Option<&etsi::Declared>,
) -> Value {
    let trust = verification(entry);
    // Each token's own timestamp validation, apart from the signature's: the
    // comparison sets it against DSS's per token.
    let timestamps = computed
        .as_object_mut()
        .and_then(|computed| computed.remove("tokens"))
        .unwrap_or(Value::Null);
    let mut row = json!({
        "etsi": etsi::under_profile(computed, &trust),
        "verification": trust,
        "integrity": own,
        "timestamps": timestamps,
    });
    if let Some(declared) = declared {
        row["declared_timestamps"] = declared.tokens().len().into();
        if let Some(refusal) = &declared.token_refusal {
            row["token_refusal"] = refusal.clone().into();
        }
    }
    row
}

fn facts(xml: &str, anchors: &Path, at: i64, profile: PolicyProfile) -> Result<Value, Failure> {
    let bytes = std::fs::read(xml)?;
    let text = ascii_view(&bytes);
    let trusted = read_anchors(anchors)?;
    let carried = pool(&text);
    let policy = profile_policy(profile, at, true)?;
    let direct_trust = policy.key_trust.trust_anchor_signer == TrustAnchorSigner::Accepted;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: trusted.clone(),
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = match XmlDocument::parse_bytes(&bytes) {
        Ok(document) => document,
        Err(error) => return Ok(json!({ "parse": error.to_string() })),
    };
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    // An unreadable token carries no authority; why it could not be read
    // stays in the facts, since no later step reports it.
    let (authorities, unreadable) = tokens::token_authorities(&text, &carried);
    let accuracies = tokens::stated(&authorities, 0)?;
    let anchor_refs: Vec<&[u8]> = trusted.iter().map(Vec::as_slice).collect();
    let others: Vec<&[u8]> = carried.iter().map(Vec::as_slice).collect();
    let caller: Vec<&[u8]> = anchor_refs.iter().chain(&others).copied().collect();
    let inputs = |requirements| Inputs {
        requirements,
        anchors: &anchor_refs,
        certificates: &others,
        utc: &utc,
        accuracies: &accuracies,
        responders: &[],
        crls: &[],
        responses: &[],
    };
    let ids = signature_ids(&text);
    let mut signatures = Vec::new();
    let account = account();
    let expected = expected_targets(&document, &text);
    let request = VerificationRequest {
        expected_targets: &expected,
        ..VerificationRequest::default()
    };
    let mut declared = declarations(&text);
    establish_timestamps(
        &document,
        &request,
        &account,
        &inputs(Requirements::Timestamped),
        &mut declared,
    )?;
    let rules = rules(&catalogue(&profile_policy(profile, at, true)?)?);
    let crls = tokens::values(&text, "EncapsulatedCRLValue");
    let responses = tokens::values(&text, "EncapsulatedOCSPValue");
    let positions = document_positions(&text);
    let (integrity, integrity_refusal) = rules.lend(|requirements| {
        let etsi_inputs = etsi::Inputs {
            pool: &carried,
            anchors: &trusted,
            crls: &crls,
            responses: &responses,
            now: at,
            requirements,
            utc: &utc,
            direct_trust,
            positions: &positions,
            reference_digests: &rules.reference_digests,
        };
        integrity(&document, &request, &account, at, &declared, &etsi_inputs)
    })?;
    let verified = with_verified_request(&document, &context, &request, &account, |session| {
        let entries = session.evidence().signatures();
        // Ids are reported only when both readings see the same signatures.
        let aligned = ids.len() == entries.len();
        for (index, entry) in entries.iter().enumerate() {
            let mut row = signature_row(
                entry,
                integrity.get(index).cloned().unwrap_or_default(),
                declared.get(index),
            );
            row["index"] = index.into();
            row["id"] = json!(if aligned { ids[index].clone() } else { None });
            if entry.result().is_ok() {
                let id = entry.identity();
                for (name, value) in level_facts(&document, &session, id, &caller, &inputs) {
                    row[name] = value;
                }
            }
            signatures.push(row);
        }
        Ok(())
    });
    let mut facts = json!({ "signatures": signatures });
    if !unreadable.is_empty() {
        facts["unreadable_timestamps"] = json!(unreadable);
    }
    if let Some(refusal) = integrity_refusal {
        facts["integrity_request"] = refusal;
    }
    if let Err(error) = verified {
        let debug = format!("{error:?}");
        facts["request"] = json!({ "error": kind(&debug), "detail": error.to_string() });
    }
    Ok(facts)
}

/// Sets each signature's [`etsi::Declared::token_integrity`], or why none of
/// its tokens was checked: xml-sec-xades establishes each token's imprint and
/// TSA signature once, at no time of its own, for the ETSI process to place
/// against the validation time.
fn establish_timestamps(
    document: &XmlDocument,
    request: &VerificationRequest<'_>,
    account: &Memory,
    level_inputs: &Inputs<'_>,
    declared: &mut [etsi::Declared],
) -> Result<(), Failure> {
    let Some(at) = declared
        .iter()
        .flat_map(etsi::Declared::tokens)
        .filter_map(|(_, _, token)| etsi::token_details(token).map(|token| token.generated))
        .max()
    else {
        return Ok(());
    };
    // A token's own checks need neither the signer's path nor its validity
    // when the token was generated, so no chain is checked here: each
    // signature is verified with its signing certificate's key as the
    // caller's own key for it, an archive timestamp made after that
    // certificate expired stays checkable, and one signature's newer token
    // never decides another's.
    let carried: Vec<Vec<u8>> = level_inputs
        .certificates
        .iter()
        .map(|certificate| certificate.to_vec())
        .collect();
    let direct = SigningKeys::new(declared, &carried);
    let context = VerifyContext::new()
        .policy(profile_policy(PolicyProfile::XadesConformant, at, false)?)
        .key_resolver(&direct);
    let bound = direct.bound(&context.signature_identities(document)?, declared);
    let trusted: Vec<CallerTrustedSignatureKey<'_>> = bound
        .iter()
        .map(|(signature, key)| CallerTrustedSignatureKey {
            signature: *signature,
            key,
        })
        .collect();
    let request = VerificationRequest {
        expected_targets: request.expected_targets,
        trusted_keys: &trusted,
        ..VerificationRequest::default()
    };
    let run = with_verified_request(document, &context, &request, account, |session| {
        for (index, entry) in session.evidence().signatures().iter().enumerate() {
            let Some(declared) = declared.get_mut(index) else {
                continue;
            };
            if declared.tokens().is_empty() {
                continue;
            }
            // Each token's own imprint and signature, checked token by token
            // (EN 319 102-1 V1.4.1 clause 5.4); its paths, statuses and the
            // level's requirements are the ETSI process's to judge. The
            // archive level prepares every timestamp property; a signature
            // without archive timestamps is read at B-T.
            let levels = if declared.archive_timestamps.is_empty() {
                &[Requirements::Timestamped][..]
            } else {
                &[Requirements::Archival, Requirements::Timestamped][..]
            };
            let mut refusals = Vec::new();
            for requirements in levels {
                let checked = check_tokens(
                    &session,
                    entry.identity(),
                    &Inputs {
                        requirements: *requirements,
                        ..*level_inputs
                    },
                    |results| {
                        results
                            .iter()
                            .map(|result| {
                                let intact = match result.integrity() {
                                    TokenIntegrity::Intact => Some(true),
                                    TokenIntegrity::Rejected => Some(false),
                                    TokenIntegrity::MissingSigner => None,
                                };
                                (result.role(), result.token().to_vec(), intact)
                            })
                            .collect::<Vec<_>>()
                    },
                );
                match checked {
                    Ok(Outcome::Assessed(found)) => {
                        declared.token_integrity = found;
                        refusals.clear();
                        break;
                    }
                    Ok(outcome) => refusals.push(format!("{requirements:?}: {outcome:?}")),
                    Err(error) => refusals.push(format!("{requirements:?}: {error:?}")),
                }
            }
            if !refusals.is_empty() {
                declared.token_refusal = Some(refusals.join("; "));
            }
        }
        Ok(())
    });
    // A refused request establishes no token of any signature.
    if let Err(error) = run {
        for declared in declared.iter_mut() {
            declared.token_integrity.clear();
            declared.token_refusal = Some(format!("{error:?}"));
        }
    }
    Ok(())
}

/// The local name of the element `node` names in `document`.
fn local_name(document: &XmlDocument, node: NodeIdentity) -> Option<String> {
    document.with_view(|view| {
        view.document()
            .descendants()
            .find(|candidate| {
                view.identity_of(*candidate)
                    .is_ok_and(|found| found == node)
            })
            .map(|found| found.tag_name().name().to_owned())
    })
}

/// The `XAdES` facts of every baseline level of one verified signature of
/// `document`.
fn level_facts<'i, W: structured_asn1::memory::Work>(
    document: &XmlDocument,
    session: &xml_sec::xmldsig::VerifiedSession<'_, '_, '_, W>,
    identity: NodeIdentity,
    caller: &[&[u8]],
    inputs: &impl Fn(Requirements) -> Inputs<'i>,
) -> Vec<(&'static str, Value)> {
    let basic = validate_basic(session, identity, caller, |report| {
        (
            report.inputs().certificate.is_bound(),
            report.included().is_some(),
            report.all_root_requirements_met(),
        )
    });
    // A repeated timestamp field is a schema refusal, a repeated token of one
    // SignatureTimeStamp a baseline one (EN 319 132-1 V1.3.1 clauses 5.3 and
    // 6.3 (n)); the refusal names the node, whose name tells them apart.
    let duplicate = match &basic {
        Err(xml_sec_xades::ValidationError::Prepare(error)) => match error.as_ref() {
            structured_xades::prepare::Error::Timestamp(
                structured_xades::timestamp::InputError::Duplicate { node },
            ) => local_name(document, *node),
            _ => None,
        },
        _ => None,
    };
    let basic = match basic {
        Ok(Outcome::Assessed((bound, included, met))) => {
            json!({ "bound": bound, "included": included, "assessed": met })
        }
        // EN 319 132-1 levels do not apply to a TS 101 903 V1.2.2 signature;
        // its BES form (V1.2.2 section 4.4.1) is what it can meet.
        Ok(Outcome::Syntax {
            syntax: Syntax::Ts101903V122,
            ..
        }) => {
            return vec![(
                "ts101903_bes",
                level(validate_ts101903(session, identity, caller, |report| {
                    report.bes_met()
                })),
            )];
        }
        other => level(other.map(|outcome| outcome.map(|_| false))),
    };
    let mut basic = basic;
    if let Some(name) = duplicate {
        basic["duplicate"] = name.into();
    }
    let mut found = vec![("basic", basic)];
    for (name, requirements) in [
        ("timestamped", Requirements::Timestamped),
        ("long_term", Requirements::LongTerm),
        ("archival", Requirements::Archival),
    ] {
        found.push((
            name,
            level(validate(session, identity, &inputs(requirements), met)),
        ));
    }
    found
}

/// The nodes the data `Reference`s of `text` name in `document`. A target
/// the document does not resolve, or a signature over detached data alone,
/// leaves the whole document as the expected target.
fn expected_targets(document: &XmlDocument, text: &str) -> Vec<NodeIdentity> {
    document.with_view(|view| {
        let mut found: Vec<_> = targets(text)
            .into_iter()
            .filter_map(|target| match target {
                Target::Root => Some(view.root_element()),
                Target::Id(id) => view.node_for_id(&id, &[]),
            })
            .collect();
        if found.is_empty() {
            found.push(view.root_element());
        }
        found.dedup();
        found
    })
}

/// The signing certificate of each signature, identified as clause 5.2.3.4
/// identifies it, in document order. Its key is handed to verification as the
/// caller's own trusted key for that very signature: clause 5.2.7.4 step 3
/// verifies "using the public key extracted from the signing certificate", so
/// `KeyInfo` is neither read nor required. A signature whose certificate is
/// not identified is resolved by a `KeyInfo` that carries one of the others.
struct SigningKeys {
    signers: Vec<Option<Vec<u8>>>,
}

impl SigningKeys {
    fn new(declared: &[etsi::Declared], carried: &[Vec<u8>]) -> Self {
        let parser = Parser::der(account());
        let pool: Vec<Certificate<'_>> = carried
            .iter()
            .filter_map(|bytes| Certificate::read(&parser, bytes, 0).ok())
            .collect();
        let signers = declared
            .iter()
            .map(|declared| {
                etsi::signing_certificate(declared, &pool, parser.memory())
                    .map(|certificate| certificate.as_bytes().to_vec())
            })
            .collect();
        Self { signers }
    }

    /// The verification key of the certificate `der`, for `algorithm` as the
    /// signature declares it.
    fn key(der: &[u8], algorithm: SignatureAlgorithm) -> Option<VerificationKey> {
        let parser = Parser::der(account());
        let parsed = Certificate::read(&parser, der, 0).ok()?;
        Some(VerificationKey {
            algorithm,
            public_key_bytes: parsed.tbs().public_key().as_bytes().to_vec(),
            certificate_der: Some(der.to_vec()),
            name: None,
        })
    }

    /// Each identified signer's key, bound to the identity of its own
    /// signature, never to the order in which verification asks: a signature
    /// refused before its key is resolved must not shift the others.
    fn bound(
        &self,
        identities: &[NodeIdentity],
        declared: &[etsi::Declared],
    ) -> Vec<(NodeIdentity, VerificationKey)> {
        identities
            .iter()
            .zip(&self.signers)
            .zip(declared)
            .filter_map(|((identity, signer), declared)| {
                Some((*identity, Self::key(signer.as_ref()?, declared.method?)?))
            })
            .collect()
    }
}

impl KeyResolver for SigningKeys {
    fn resolve<'a>(
        &'a self,
        _key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        Ok(None)
    }

    fn resolve_for_verification<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        _policy: &VerificationPolicy,
        _provider: &dyn xml_sec::provider::CryptoProvider,
    ) -> Result<Option<ResolvedVerificationKey<'a>>, DsigError> {
        // Only a signature without its own identified signer comes here.
        let named = key_info.and_then(|key_info| {
            key_info.sources.iter().find_map(|source| match source {
                KeyInfoSource::X509Data(data) => self
                    .signers
                    .iter()
                    .flatten()
                    .find(|signer| data.certificates.iter().any(|carried| carried == *signer)),
                _ => None,
            })
        });
        Ok(named
            .and_then(|certificate| Self::key(certificate, algorithm))
            .map(|key| ResolvedVerificationKey::CallerTrusted(Box::new(key))))
    }
}

/// Per signature, its integrity and its ETSI indication; then the refusal of
/// the whole request, if any.
type Established = (Vec<(Value, Value)>, Option<Value>);

/// Each signature's integrity (EN 319 102-1 5.2.7) and its ETSI indication
/// under the compared profile's constraints (`inputs`). Integrity is
/// established under the widest profile with the signing certificate's key
/// and no chain checked, so the references and value are known even where
/// no path validates at `at` or the compared profile refuses the signature.
fn integrity(
    document: &XmlDocument,
    request: &VerificationRequest<'_>,
    account: &Memory,
    at: i64,
    declared: &[etsi::Declared],
    inputs: &etsi::Inputs<'_>,
) -> Result<Established, Failure> {
    let direct = SigningKeys::new(declared, inputs.pool);
    // Format checking covers the base format only; conformance to a signature
    // profile such as XAdES is signature acceptance (EN 319 102-1 5.2.2 NOTE,
    // 5.2.8), so integrity is established over plain XMLDSig. External
    // references are admitted: their bytes are supplied to neither validator,
    // so they are signed data that cannot be obtained (5.2.7.4 step 1).
    let mut policy = profile_policy(PolicyProfile::XadesConformant, at, false)?;
    policy.signature_constraints = SignatureConstraints::General;
    policy.uris.references = UriTypeSet::new(true, true, true);
    let context = VerifyContext::new().policy(policy).key_resolver(&direct);
    let bound = direct.bound(&context.signature_identities(document)?, declared);
    let trusted: Vec<CallerTrustedSignatureKey<'_>> = bound
        .iter()
        .map(|(signature, key)| CallerTrustedSignatureKey {
            signature: *signature,
            key,
        })
        .collect();
    let request = VerificationRequest {
        expected_targets: request.expected_targets,
        trusted_keys: &trusted,
        ..VerificationRequest::default()
    };
    let mut found = Vec::new();
    let unknown = etsi::Declared::default();
    let run = with_verified_request(document, &context, &request, account, |session| {
        for (index, entry) in session.evidence().signatures().iter().enumerate() {
            let declared = declared.get(index).unwrap_or(&unknown);
            // EN 319 132-1 §5.2.7.2: a CounterSignature property's signature
            // signs the embedding signature's SignatureValue. Its format
            // still lets it be verified (EN 319 102-1 §5.2.2.1), so one that
            // covers no such value fails that data item's hash instead.
            let uncountersigned = matches!(
                validate_basic(&session, entry.identity(), &[], |_| ()),
                Err(ValidationError::Enclosing(error))
                    if matches!(*error, EnclosingError::Counter(_))
            );
            let at = |now| {
                let inputs = etsi::Inputs { now, ..*inputs };
                etsi::indication(&session, entry.result(), declared, &inputs, uncountersigned)
            };
            let mut computed = at(inputs.now);
            if computed["indication"] == "TOTAL_PASSED" {
                computed["valid_until"] = valid_until(
                    &etsi::validity_bounds(&session.certificate_parser(), inputs),
                    at,
                );
            }
            found.push((verification(entry), computed));
        }
        Ok(())
    });
    let refusal = run.err().map(|error| {
        let debug = format!("{error:?}");
        json!({ "error": kind(&debug), "detail": error.to_string() })
    });
    Ok((found, refusal))
}

/// Until when a signature that passes now keeps passing over the evidence it
/// carries: the last of `bounds` before the first one past which the ETSI
/// process `at` no longer reaches `TOTAL_PASSED`, as Unix seconds. `null`
/// when it passes past every bound, so no certificate limits it.
fn valid_until(bounds: &[i64], at: impl Fn(i64) -> Value) -> Value {
    bounds
        .iter()
        .find(|bound| at(**bound + 1)["indication"] != "TOTAL_PASSED")
        .map_or(Value::Null, |bound| json!(bound))
}

/// The hash a digest method computes, when both constraint vocabularies
/// name it.
fn hash_of(digest: DigestAlgorithm) -> Option<Hash> {
    Some(etsi::hash_of(digest)).filter(|hash| *hash != Hash::Other)
}

/// The family and message hash of a fixed asymmetric signature method.
/// Parameterized RSA-PSS, HMAC, the prehashed and context `EdDSA` variants
/// and post-quantum methods have no entry in either constraint vocabulary.
fn suite_of(algorithm: SignatureAlgorithm) -> Option<(Family, Option<Hash>)> {
    use SignatureAlgorithm as S;
    let (family, digest) = match algorithm {
        S::Ed25519 => return Some((Family::Ed25519, None)),
        S::Ed448 => return Some((Family::Ed448, None)),
        S::DsaSha1 => (Family::Dsa, DigestAlgorithm::Sha1),
        S::DsaSha256 => (Family::Dsa, DigestAlgorithm::Sha256),
        S::RsaSha1 => (Family::RsaPkcs1, DigestAlgorithm::Sha1),
        S::RsaSha224 => (Family::RsaPkcs1, DigestAlgorithm::Sha224),
        S::RsaSha256 => (Family::RsaPkcs1, DigestAlgorithm::Sha256),
        S::RsaSha384 => (Family::RsaPkcs1, DigestAlgorithm::Sha384),
        S::RsaSha512 => (Family::RsaPkcs1, DigestAlgorithm::Sha512),
        S::RsaPssSha1 => (Family::RsaPss, DigestAlgorithm::Sha1),
        S::RsaPssSha224 => (Family::RsaPss, DigestAlgorithm::Sha224),
        S::RsaPssSha256 => (Family::RsaPss, DigestAlgorithm::Sha256),
        S::RsaPssSha384 => (Family::RsaPss, DigestAlgorithm::Sha384),
        S::RsaPssSha512 => (Family::RsaPss, DigestAlgorithm::Sha512),
        S::RsaPssSha3_256 => (Family::RsaPss, DigestAlgorithm::Sha3_256),
        S::RsaPssSha3_384 => (Family::RsaPss, DigestAlgorithm::Sha3_384),
        S::RsaPssSha3_512 => (Family::RsaPss, DigestAlgorithm::Sha3_512),
        S::EcdsaSha1 => (Family::Ecdsa, DigestAlgorithm::Sha1),
        S::EcdsaSha224 => (Family::Ecdsa, DigestAlgorithm::Sha224),
        S::EcdsaSha256 => (Family::Ecdsa, DigestAlgorithm::Sha256),
        S::EcdsaSha384 => (Family::Ecdsa, DigestAlgorithm::Sha384),
        S::EcdsaSha512 => (Family::Ecdsa, DigestAlgorithm::Sha512),
        S::EcdsaSha3_256 => (Family::Ecdsa, DigestAlgorithm::Sha3_256),
        S::EcdsaSha3_384 => (Family::Ecdsa, DigestAlgorithm::Sha3_384),
        S::EcdsaSha3_512 => (Family::Ecdsa, DigestAlgorithm::Sha3_512),
        _ => return None,
    };
    Some((family, Some(hash_of(digest)?)))
}

/// What a compiled profile accepts, in the vocabulary both comparisons
/// share: the `SignatureValue` suites, the `Reference` digests and the
/// smallest key of each family, signer and issuer keys alike.
struct Catalogue {
    suites: Vec<(Family, Option<Hash>)>,
    digests: Vec<Hash>,
    minimum_bits: Vec<(Family, u32)>,
}

fn catalogue(policy: &VerificationPolicy) -> Result<Catalogue, Failure> {
    let mut suites: Vec<_> = SignatureAlgorithm::ALL
        .into_iter()
        .filter(|algorithm| policy.check_signature_algorithm(*algorithm).is_ok())
        .filter_map(suite_of)
        .collect();
    suites.dedup();
    let digests = DigestAlgorithm::ALL
        .into_iter()
        .filter(|digest| policy.check_digest_algorithm(*digest).is_ok())
        .filter_map(hash_of)
        .collect();
    let rsa = u32::try_from(policy.key_trust.rsa_keys.minimum_modulus_bits)?;
    let dsa = u32::try_from(policy.key_trust.dsa_keys.minimum_modulus_bits)?;
    Ok(Catalogue {
        suites,
        digests,
        // The provider implements P-256 and larger curves only, and the fixed
        // EdDSA variants have no size dimension.
        minimum_bits: vec![
            (Family::RsaPkcs1, rsa),
            (Family::RsaPss, rsa),
            (Family::Dsa, dsa),
            (Family::Ecdsa, 256),
            (Family::Ed25519, 0),
            (Family::Ed448, 0),
        ],
    })
}

/// DSS's name of a signature family (`EncryptionAlgorithm`).
fn dss_family(family: Family) -> &'static str {
    match family {
        Family::RsaPkcs1 => "RSA",
        Family::RsaPss => "RSASSA-PSS",
        Family::Dsa => "DSA",
        Family::Ecdsa => "ECDSA",
        Family::Ed25519 | Family::Ed448 => "EdDSA",
        Family::Other => "other",
    }
}

/// DSS's name of a hash function (`DigestAlgorithm`).
fn dss_hash(hash: Hash) -> &'static str {
    match hash {
        Hash::Md5 => "MD5",
        Hash::Sha1 => "SHA1",
        Hash::Sha224 => "SHA224",
        Hash::Sha256 => "SHA256",
        Hash::Sha384 => "SHA384",
        Hash::Sha512 => "SHA512",
        Hash::Sha3_256 => "SHA3-256",
        Hash::Sha3_384 => "SHA3-384",
        Hash::Sha3_512 => "SHA3-512",
        Hash::Ripemd160 => "RIPEMD160",
        Hash::Whirlpool => "WHIRLPOOL",
        Hash::Other => "other",
    }
}

/// The profile's constraints in DSS's policy vocabulary, for the harness to
/// write the DSS validation policy both comparisons run under.
fn constraints(profile: PolicyProfile) -> Result<Value, Failure> {
    let catalogue = catalogue(&profile_policy(profile, INSTANT_ANY, true)?)?;
    let mut families: Vec<&str> = catalogue
        .suites
        .iter()
        .map(|(family, _)| dss_family(*family))
        .collect();
    families.sort_unstable();
    families.dedup();
    let mut hashes: Vec<&str> = catalogue
        .suites
        .iter()
        .filter_map(|(_, hash)| *hash)
        .chain(catalogue.digests.iter().copied())
        .map(dss_hash)
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    let minimum: Map<String, Value> = catalogue
        .minimum_bits
        .iter()
        .filter(|(family, _)| families.contains(&dss_family(*family)))
        .map(|(family, bits)| (dss_family(*family).to_owned(), json!(bits)))
        .collect();
    Ok(json!({
        "signature": { "families": families, "hashes": hashes },
        "minimum_bits": minimum,
    }))
}

/// Any time inside the compiled policies' range: the constraints a profile
/// accepts do not depend on it.
const INSTANT_ANY: i64 = 1_800_000_000;

fn main() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().collect();
    let result = match &args[1..] {
        [mode, profile] if mode == "constraints" => constraints(named_profile(profile)?)?,
        [mode, xml, anchors] if mode == "conditions" => conditions(xml, Path::new(anchors))?,
        [mode, xml, anchors, at, profile] if mode == "facts" => facts(
            xml,
            Path::new(anchors),
            at.parse()?,
            named_profile(profile)?,
        )?,
        _ => {
            return Err("usage: corpus_probe constraints PROFILE | conditions XML ANCHORS_DIR | facts XML ANCHORS_DIR UNIX_TIME PROFILE, PROFILE xades|xades-extended|xades-conformant".into());
        }
    };
    println!("{result}");
    Ok(())
}
