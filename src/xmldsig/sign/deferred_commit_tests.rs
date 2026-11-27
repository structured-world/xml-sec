use super::*;
use crate::policy::PolicyViolation;
use std::sync::Mutex;

/// Records the canonical `SignedInfo` it is asked to sign.
#[derive(Default)]
struct RecordingSigningKey {
    canonical_signed_info: Mutex<Vec<u8>>,
}

impl RecordingSigningKey {
    fn recorded(&self) -> Vec<u8> {
        self.canonical_signed_info
            .lock()
            .expect("recording lock is never poisoned")
            .clone()
    }
}

impl SigningKey for RecordingSigningKey {
    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        canonical_signed_info.clone_into(
            &mut self
                .canonical_signed_info
                .lock()
                .expect("recording lock is never poisoned"),
        );
        Ok(vec![0x5a; 256])
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Rsa {
            spki_der: Vec::new(),
            modulus: vec![0x80; 256],
            exponent: vec![1, 0, 1],
        })
    }
}

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const INCLUSIVE: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn reference(uri: &str, transforms: &str, digest_value: &str) -> String {
    let transforms = if transforms.is_empty() {
        String::new()
    } else {
        format!("<ds:Transforms>{transforms}</ds:Transforms>")
    };
    format!(
        r#"<ds:Reference URI="{uri}">{transforms}<ds:DigestMethod Algorithm="{SHA256}"/>{digest_value}</ds:Reference>"#
    )
}

fn template(c14n: &str, references: &str, signature_value: &str, object: &str) -> String {
    format!(
        r#"<root xmlns:a="urn:a"><payload Id="payload" a:note="x &lt; y">text &amp; more</payload><other Id="other"><a:leaf/></other><ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{c14n}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/>{references}</ds:SignedInfo>{signature_value}{object}</ds:Signature></root>"#
    )
}

fn enveloped() -> String {
    format!(
        r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="{EXCLUSIVE}"/>"#
    )
}

/// Templates covering every digest path: deferred digests with tree-based
/// dependency analysis, deferred digests after placeholder analysis (`XPath`),
/// committed levels (nested `Manifest`s) and pre-filled `DigestValue`s.
fn cases() -> Vec<(&'static str, String, crate::policy::SigningPolicy)> {
    let default_policy = crate::policy::SigningPolicy::default();
    let manifest_policy = crate::policy::SigningPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        ..crate::policy::SigningPolicy::default()
    };
    let subtree_references = [
        reference("", &enveloped(), "<ds:DigestValue/>"),
        reference("#payload", "", "<ds:DigestValue></ds:DigestValue>"),
        reference(
            "#other",
            &format!(r#"<ds:Transform Algorithm="{INCLUSIVE}"/>"#),
            "<ds:DigestValue/>",
        ),
    ]
    .concat();
    let xpath_reference = reference(
        "#payload",
        r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"#,
        "<ds:DigestValue/>",
    );
    let manifests = format!(
        r#"<ds:Object><ds:Manifest Id="outer">{}</ds:Manifest><ds:Manifest Id="inner">{}</ds:Manifest></ds:Object>"#,
        reference("#inner", "", "<ds:DigestValue/>"),
        reference("#payload", "", "<ds:DigestValue/>"),
    );
    vec![
        (
            "exclusive subtree references",
            template(EXCLUSIVE, &subtree_references, "<ds:SignatureValue/>", ""),
            default_policy.clone(),
        ),
        (
            "inclusive subtree references",
            template(INCLUSIVE, &subtree_references, "<ds:SignatureValue/>", ""),
            default_policy.clone(),
        ),
        (
            "xpath reference",
            template(EXCLUSIVE, &xpath_reference, "<ds:SignatureValue/>", ""),
            default_policy.clone(),
        ),
        (
            "nested manifests",
            template(
                EXCLUSIVE,
                &reference("#outer", "", "<ds:DigestValue/>"),
                "<ds:SignatureValue/>",
                &manifests,
            ),
            manifest_policy,
        ),
        (
            "pre-filled values",
            template(
                EXCLUSIVE,
                &reference("", &enveloped(), "<ds:DigestValue>AAAA</ds:DigestValue>"),
                "<ds:SignatureValue>AAAA</ds:SignatureValue>",
                "",
            ),
            default_policy,
        ),
    ]
}

fn independent_canonical_signed_info(
    signed: &str,
    policy: &crate::policy::SigningPolicy,
) -> Vec<u8> {
    let document = XmlDocument::parse(signed).expect("signed output must parse");
    let mut budgets = SigningOperationBudgets::from_resources(&policy.resources);
    canonicalize_signed_info(&document, policy, &mut budgets, 0, &[], &[])
        .expect("signed output SignedInfo must canonicalize")
        .2
}

#[test]
fn text_projection_matches_the_committed_document() {
    // String entry points serialize the final generation without parsing it,
    // while retained documents commit through a parse. Both must yield the
    // same bytes for every digest path.
    for (name, xml, policy) in cases() {
        let key = RecordingSigningKey::default();
        let context = SignContext::new(&key).policy(policy);
        let signed = context
            .sign_template(&xml)
            .unwrap_or_else(|error| panic!("{name}: text signing failed: {error:?}"));
        let mut document = XmlDocument::parse(xml.as_str()).expect("fixture must parse");
        let audit = context
            .sign_document(&mut document)
            .unwrap_or_else(|error| panic!("{name}: document signing failed: {error:?}"));
        let text = signed.output;
        assert_eq!(text, document.as_xml(), "{name}");
        // Both entry points run the same operation, so its policy decided alike.
        assert_eq!(signed.policy, audit, "{name}");
        assert!(!text.contains("<ds:DigestValue/>"), "{name}");
        assert!(!text.contains("AAAA"), "{name}");
    }
}

#[test]
fn kept_signing_inputs_are_the_bytes_the_operation_digested_and_signed() {
    // A caller keeping the signing inputs gets them from the one run that
    // produced the signature, on every digest path: each Reference's kept
    // bytes hash to the DigestValue written for it, and the kept SignedInfo
    // is the one the key signed. Nothing is recomputed outside the operation.
    // Values wrapped in lines narrower than a SHA-256 digest's 44 characters
    // put line feeds into the Manifests a later level digests, so the kept
    // bytes of that level must hold the wrapped values the document holds.
    let widths = [None, core::num::NonZeroUsize::new(16)];
    for ((name, xml, policy), width) in cases()
        .into_iter()
        .flat_map(|case| widths.map(|width| (case.clone(), width)))
    {
        let key = RecordingSigningKey::default();
        let context = SignContext::new(&key)
            .policy(policy)
            .base64_line_size(width);
        let mut document = XmlDocument::parse(xml.as_str()).expect("fixture must parse");
        let (_, inputs) = context
            .sign_document_keeping_inputs(&mut document)
            .unwrap_or_else(|error| panic!("{name}: signing failed: {error:?}"));
        assert_eq!(
            inputs.signed_info.as_deref(),
            Some(key.recorded().as_slice()),
            "{name}"
        );
        // Every fixture's SignedInfo precedes its Manifests, so the
        // DigestValues in document order follow the reported order.
        let written = document.with_view(|view| {
            view.document()
                .descendants()
                .filter(|node| node.has_tag_name((DS, "DigestValue")))
                .map(|node| node.text().unwrap_or("").to_owned())
                .collect::<Vec<_>>()
        });
        let kept = inputs
            .signed_info_references
            .iter()
            .chain(&inputs.manifest_references)
            .collect::<Vec<_>>();
        assert_eq!(kept.len(), written.len(), "{name}");
        for (bytes, value) in kept.into_iter().zip(&written) {
            assert!(!bytes.is_empty(), "{name}: every Reference kept its bytes");
            let digest = crate::xmldsig::digest::compute_digest(
                crate::xmldsig::DigestAlgorithm::Sha256,
                bytes,
            );
            // The written value is compared decoded: its line feeds are
            // layout, the kept bytes are hashed exactly as returned.
            let unwrapped = value
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<String>();
            assert_eq!(
                crate::base64::encode(&digest),
                unwrapped,
                "{name} at width {width:?}"
            );
        }
    }
}

#[test]
fn reference_inputs_are_the_signing_inputs_without_a_signature() {
    // The inputs a signing would digest, Manifest levels included, come from
    // the same operation stopped before the signature value: the key signs
    // nothing and the document keeps its text and generation.
    for (name, xml, policy) in cases() {
        let key = RecordingSigningKey::default();
        let context = SignContext::new(&key).policy(policy);
        let mut document = XmlDocument::parse(xml.as_str()).expect("fixture must parse");
        let generation = document.generation();
        let inputs = context
            .reference_inputs(&mut document, crate::xmldsig::KeptInputs::ALL)
            .unwrap_or_else(|error| panic!("{name}: reference inputs failed: {error:?}"));
        assert!(key.recorded().is_empty(), "{name}: nothing was signed");
        assert_eq!(document.as_xml(), xml, "{name}");
        assert_eq!(document.generation(), generation, "{name}");
        assert_eq!(inputs.signed_info, None, "{name}");
        let (_, signed) = context
            .sign_document_keeping_inputs(&mut document)
            .unwrap_or_else(|error| panic!("{name}: signing failed: {error:?}"));
        assert_eq!(
            inputs.signed_info_references, signed.signed_info_references,
            "{name}"
        );
        assert_eq!(
            inputs.manifest_references, signed.manifest_references,
            "{name}"
        );
    }
}

#[test]
fn builder_reference_inputs_are_the_inputs_of_the_appended_signature() {
    // The signature a builder appends digests, before any signature value,
    // the bytes it digests when signed; the dry run appends nothing.
    let xml = r#"<root><payload Id="payload">text</payload></root>"#;
    let builder = crate::xmldsig::SignatureBuilder::new(
        crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(
        crate::xmldsig::ReferenceBuilder::new(crate::xmldsig::DigestAlgorithm::Sha256)
            .uri("#payload"),
    )
    .add_reference(
        crate::xmldsig::ReferenceBuilder::new(crate::xmldsig::DigestAlgorithm::Sha256)
            .uri("")
            .transform(crate::xmldsig::Transform::Enveloped),
    );
    let key = RecordingSigningKey::default();
    let context = SignContext::new(&key);
    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    let generation = document.generation();
    let inputs = context
        .reference_inputs_with_builder(&mut document, &builder, crate::xmldsig::KeptInputs::ALL)
        .expect("reference inputs");
    assert!(key.recorded().is_empty(), "nothing was signed");
    assert_eq!(document.as_xml(), xml);
    assert_eq!(document.generation(), generation);
    let (_, signed) = context
        .sign_document_with_builder_keeping(
            &mut document,
            &builder,
            crate::xmldsig::KeptInputs::ALL,
        )
        .expect("signing");
    assert_eq!(inputs.signed_info_references.len(), 2);
    assert_eq!(inputs.signed_info_references, signed.signed_info_references);
    assert_eq!(
        signed.signed_info.as_deref(),
        Some(key.recorded().as_slice())
    );
}

#[test]
fn kept_binary_digest_inputs_are_charged_to_the_retention_limit() {
    // Bytes a Reference digests without canonicalizing them are copied only
    // for a caller keeping the signing inputs, so they count against the
    // operation's canonicalized-bytes limit then, and only then: signing
    // without keeping them is not refused.
    let payload = vec![0x41_u8; 4096];
    let resources = BTreeMap::from([("urn:payload".to_owned(), payload.clone())]);
    let xml = template(
        EXCLUSIVE,
        &reference("urn:payload", "", "<ds:DigestValue/>"),
        "<ds:SignatureValue/>",
        "",
    );
    let policy = |max_canonicalized_bytes: usize| {
        let mut policy = crate::policy::SigningPolicy::default();
        policy.uris.references = crate::xmldsig::UriTypeSet::ALL;
        policy.resources.max_canonicalized_bytes = max_canonicalized_bytes;
        policy
    };
    let key = RecordingSigningKey::default();
    let sign = |max_canonicalized_bytes: usize, keep: bool| {
        let context = SignContext::new(&key)
            .policy(policy(max_canonicalized_bytes))
            .external_resources(&resources);
        let mut document = XmlDocument::parse(xml.as_str()).expect("fixture must parse");
        if keep {
            context
                .sign_document_keeping_inputs(&mut document)
                .map(|(_, inputs)| Some(inputs))
        } else {
            context.sign_document(&mut document).map(|_| None)
        }
    };
    assert!(
        sign(1024, false).is_ok(),
        "nothing is kept, nothing charged"
    );
    assert!(
        matches!(
            sign(1024, true),
            Err(SigningError::Policy(PolicyViolation::ResourceLimit { .. })
                | SigningError::Digest(
                    SigningDigestError::Policy(PolicyViolation::ResourceLimit { .. })
                        | SigningDigestError::Transform(TransformError::Policy(
                            PolicyViolation::ResourceLimit { .. }
                        ))
                ))
        ),
        "the kept payload exceeds the limit"
    );
    let kept = sign(64 * 1024, true)
        .expect("the kept payload fits")
        .expect("inputs are kept");
    assert_eq!(kept.signed_info_references, [payload]);
}

#[test]
fn an_external_uri_resolving_to_a_fragment_stays_external() {
    // `./#payload` is an external reference: removing its dot segment leaves
    // `#payload` (RFC 3986 section 5.2.4), which still names a fragment of the
    // resource the reference points at, not an element of this document. It
    // is refused as verification refuses it, never signed as `#payload`.
    let xml = template(
        EXCLUSIVE,
        &reference("./#payload", "", "<ds:DigestValue/>"),
        "<ds:SignatureValue/>",
        "",
    );
    let mut policy = crate::policy::SigningPolicy::default();
    policy.uris.references = crate::xmldsig::UriTypeSet::ALL;
    let key = RecordingSigningKey::default();
    let resources = BTreeMap::new();
    let result = SignContext::new(&key)
        .policy(policy)
        .external_resources(&resources)
        .sign_template(&xml);
    assert!(
        matches!(
            result,
            Err(SigningError::Digest(SigningDigestError::Transform(
                TransformError::ExternalResourceFragment(_)
            )))
        ),
        "{result:?}"
    );
}

#[test]
fn a_customized_snapshot_no_longer_claims_the_published_identity() {
    // The identity names the published settings; once a builder changes them,
    // an audit carrying that identity would misattribute the decision.
    let (name, xml, _) = cases().swap_remove(0);
    let policy = alloc::sync::Arc::new(crate::policy::SigningPolicy::default());
    let identity =
        alloc::sync::Arc::new(crate::policy::PolicyIdentity::new("modern", 1, 3, [7; 32]));
    let key = FixedSigningKeyForLimits;
    let published = SignContext::new(&key)
        .snapshot(&policy, Some(&identity))
        .sign_template(&xml)
        .unwrap_or_else(|error| panic!("{name}: signing failed: {error:?}"));
    assert_eq!(published.policy.identity.as_ref(), Some(&identity));
    let customized = SignContext::new(&key)
        .snapshot(&policy, Some(&identity))
        .xpath_here_semantics(XPathHereSemantics::XmlSecLegacy)
        .sign_template(&xml)
        .unwrap_or_else(|error| panic!("{name}: signing failed: {error:?}"));
    assert_eq!(customized.policy.identity, None);
    // Copy on write: the published snapshot itself is left untouched.
    assert_eq!(
        policy.transforms.xpath_here_semantics,
        crate::policy::SigningPolicy::default()
            .transforms
            .xpath_here_semantics
    );
}

#[test]
fn signed_canonical_signed_info_matches_the_final_document() {
    // Deferred digests are spliced into the canonical SignedInfo instead of
    // being committed first. The bytes handed to the key must equal the
    // canonical SignedInfo of the document that is finally emitted, which
    // is what a verifier reconstructs.
    for (name, xml, policy) in cases() {
        let key = RecordingSigningKey::default();
        let signed = SignContext::new(&key)
            .policy(policy.clone())
            .sign_template(&xml)
            .unwrap_or_else(|error| panic!("{name}: signing failed: {error:?}"))
            .output;
        let signed_bytes = key.recorded();
        assert!(!signed_bytes.is_empty(), "{name}");
        assert_eq!(
            String::from_utf8(signed_bytes).expect("canonical XML is UTF-8"),
            String::from_utf8(independent_canonical_signed_info(&signed, &policy))
                .expect("canonical XML is UTF-8"),
            "{name}"
        );
    }
}

#[test]
fn projected_node_count_matches_the_commit_parse() {
    // The text projection replaces the commit parse's node-limit check. At
    // the smallest limit the committed document accepts, the projection must
    // accept too, and one node below it both must refuse with the node limit.
    let (_, xml, policy) = cases().swap_remove(0);
    let sign = |max_xml_nodes: usize, text: bool| {
        let mut limited = policy.clone();
        limited.resources.max_xml_nodes = max_xml_nodes;
        let context = SignContext::new(&FixedSigningKeyForLimits).policy(limited);
        if text {
            context.sign_template(&xml).map(|_| ())
        } else {
            let mut document = XmlDocument::parse(xml.as_str()).expect("fixture must parse");
            context.sign_document(&mut document).map(|_| ())
        }
    };
    let (mut low, mut high) = (1, 10_000);
    while low < high {
        let middle = low + (high - low) / 2;
        if sign(middle, false).is_ok() {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let minimum = low;
    sign(minimum, true).expect("projection must accept the committed node count");
    for text in [true, false] {
        let error = sign(minimum - 1, text).expect_err("one node below the commit must refuse");
        assert!(
            matches!(
                error,
                SigningError::Policy(PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    ..
                })
            ),
            "text={text}: {error:?}"
        );
    }
}

#[test]
fn signing_refuses_a_reference_to_content_the_signature_value_replaces() {
    // Filling SignatureValue removes its element content, so a Reference to
    // that content has no target in the signed document and must fail.
    let xml = template(
        EXCLUSIVE,
        &reference("#p", "", "<ds:DigestValue/>"),
        r#"<ds:SignatureValue><held Id="p"/></ds:SignatureValue>"#,
        "",
    );
    let result = SignContext::new(&FixedSigningKeyForLimits).sign_template(&xml);
    assert!(result.is_err(), "signed output lost its target: {result:?}");
}

#[cfg(feature = "xml-backend-roxmltree")]
#[test]
fn deferred_digest_may_replace_longer_lexical_content() {
    // References to an empty internal entity leave a DigestValue without
    // semantic children but with more source bytes than the digest that
    // replaces them, so filling it shrinks the document.
    let digest_value = format!("<ds:DigestValue>{}</ds:DigestValue>", "&empty;".repeat(10));
    let xml = format!(
        r#"<!DOCTYPE root [<!ENTITY empty "">]>{}"#,
        template(
            EXCLUSIVE,
            &reference("#payload", "", &digest_value),
            "<ds:SignatureValue/>",
            ""
        )
    );
    let mut policy = crate::policy::SigningPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let signed = SignContext::new(&FixedSigningKeyForLimits)
        .policy(policy)
        .xml_backend(crate::XmlBackend::Roxmltree)
        .sign_template(&xml)
        .expect("a shrinking DigestValue replacement must sign")
        .output;
    assert!(!signed.contains("&empty;"));
}

struct FixedSigningKeyForLimits;

impl SigningKey for FixedSigningKeyForLimits {
    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        _canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        Ok(vec![0x5a; 256])
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Rsa {
            spki_der: Vec::new(),
            modulus: vec![0x80; 256],
            exponent: vec![1, 0, 1],
        })
    }
}
