use super::*;
use core::cell::RefCell;

const C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// A key that keeps the bytes it was asked to sign.
#[derive(Default)]
struct RecordingKey {
    signed: RefCell<Vec<u8>>,
}

impl SigningKey for RecordingKey {
    fn sign(&self, _: SignatureAlgorithm, canonical: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        self.signed.borrow_mut().extend_from_slice(canonical);
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

/// `xml` signed through the text entry point and through the retained one,
/// which must agree, with the canonical `SignedInfo` the key received.
fn signed(xml: &str, policy: &crate::policy::SigningPolicy) -> (String, Vec<u8>) {
    let key = RecordingKey::default();
    let text = SignContext::new(&key)
        .policy(policy.clone())
        .sign_template(xml)
        .unwrap_or_else(|error| panic!("{error}: {xml}"));
    let canonical = key.signed.take();
    let mut document = XmlDocument::parse(xml).expect("fixture parses");
    SignContext::new(&key)
        .policy(policy.clone())
        .sign_document(&mut document)
        .unwrap_or_else(|error| panic!("{error}: {xml}"));
    assert_eq!(document.as_xml(), text);
    assert_eq!(key.signed.take(), canonical);
    (text, canonical)
}

/// A template over `reference`, in the namespace form `open` declares.
fn template(canonicalization: &str, open: &str, q: &str, reference: &str) -> String {
    format!(
        concat!(
            "<root xml:lang=\"en\"><payload Id=\"payload\">content</payload>",
            "<{q}Signature {open}><{q}SignedInfo>",
            "<{q}CanonicalizationMethod Algorithm=\"{canonicalization}\"/>",
            "<{q}SignatureMethod ",
            "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>",
            "{reference}</{q}SignedInfo><{q}SignatureValue/></{q}Signature></root>",
        ),
        q = q,
        open = open,
        canonicalization = canonicalization,
        reference = reference,
    )
}

fn reference(q: &str, uri: &str, transforms: &str) -> String {
    format!(
        concat!(
            "<{q}Reference URI=\"{uri}\">{transforms}",
            "<{q}DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
            "<{q}DigestValue/></{q}Reference>",
        ),
        q = q,
        uri = uri,
        transforms = transforms,
    )
}

#[test]
fn a_generated_canonicalization_signs_exactly_like_an_explicit_one() {
    // XMLDSig Second Edition generation makes C14N 1.1 explicit. Whether that
    // transform is committed first or joins the final mutation, the document
    // and the signed bytes must be the ones a template already stating it gives.
    let policy = crate::policy::SigningPolicy::default();
    for canonicalization in [
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        C14N11,
    ] {
        for (open, q) in [
            ("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"", "ds:"),
            ("xmlns=\"http://www.w3.org/2000/09/xmldsig#\"", ""),
        ] {
            let last = format!("<{q}Transform Algorithm=\"{C14N11}\"/>");
            let enveloped = format!("<{q}Transform Algorithm=\"{ENVELOPED}\"/>");
            let cases = [
                (
                    "#payload",
                    String::new(),
                    format!("<{q}Transforms>{last}</{q}Transforms>"),
                ),
                (
                    "#payload",
                    format!("<{q}Transforms/>"),
                    format!("<{q}Transforms>{last}</{q}Transforms>"),
                ),
                (
                    "#payload",
                    format!("<{q}Transforms />"),
                    format!("<{q}Transforms >{last}</{q}Transforms>"),
                ),
                (
                    "#payload",
                    format!("<{q}Transforms>\n  </{q}Transforms>\n  "),
                    format!("<{q}Transforms>\n  {last}</{q}Transforms>\n  "),
                ),
                (
                    "",
                    format!("<{q}Transforms>{enveloped}</{q}Transforms>"),
                    format!("<{q}Transforms>{enveloped}{last}</{q}Transforms>"),
                ),
                (
                    "",
                    format!("<{q}Transforms>{enveloped}\n</{q}Transforms><!-- </x> -->"),
                    format!("<{q}Transforms>{enveloped}\n{last}</{q}Transforms><!-- </x> -->"),
                ),
                (
                    "#payload",
                    "<!-- </x> -->\n".to_owned(),
                    format!("<!-- </x> -->\n<{q}Transforms>{last}</{q}Transforms>"),
                ),
            ];
            for (uri, generated, explicit) in &cases {
                let generated = template(canonicalization, open, q, &reference(q, uri, generated));
                let explicit = template(canonicalization, open, q, &reference(q, uri, explicit));
                assert_eq!(
                    signed(&generated, &policy),
                    signed(&explicit, &policy),
                    "{generated}"
                );
            }
        }
    }
}

#[test]
fn a_generated_canonicalization_covers_every_reference_of_a_signature() {
    // Several edits, with the KeyInfo writer's splice after them in the document.
    struct NameWriter;

    impl KeyInfoWriter for NameWriter {
        fn write_key_info(&self, _: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
            Ok(format!(r#"<KeyName xmlns="{XMLDSIG_NS}">signer</KeyName>"#))
        }
    }

    let q = "ds:";
    let open = "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";
    let exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#";
    let last = format!("<{q}Transforms><{q}Transform Algorithm=\"{C14N11}\"/></{q}Transforms>");
    let build = |transforms: &str| {
        let references =
            reference(q, "#payload", transforms) + &reference(q, "#payload", transforms);
        template(exclusive, open, q, &references)
            .replace("<ds:SignatureValue/>", "<ds:SignatureValue/><ds:KeyInfo/>")
    };
    let sign = |xml: &str| {
        let key = RecordingKey::default();
        let text = SignContext::new(&key)
            .key_info_writer(&NameWriter)
            .sign_template(xml)
            .expect("signing succeeds");
        (text, key.signed.take())
    };
    assert_eq!(sign(&build("")), sign(&build(&last)));
}

#[test]
fn a_generated_canonicalization_read_by_another_reference_commits_first() {
    // The outer Reference digests the Manifest holding the edited inner one, so
    // it must see the transform: a deferred insertion would sign other bytes.
    let policy = crate::policy::SigningPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        ..crate::policy::SigningPolicy::default()
    };
    let q = "ds:";
    let open = "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";
    let exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#";
    let outer = format!("<{q}Transforms><{q}Transform Algorithm=\"{exclusive}\"/></{q}Transforms>");
    let last = format!("<{q}Transforms><{q}Transform Algorithm=\"{C14N11}\"/></{q}Transforms>");
    let build = |inner: &str| {
        template(exclusive, open, q, &reference(q, "#manifest", &outer)).replace(
            "<ds:SignatureValue/>",
            &format!(
                "<ds:SignatureValue/><ds:Object><ds:Manifest Id=\"manifest\">{}</ds:Manifest></ds:Object>",
                reference(q, "#payload", inner)
            ),
        )
    };
    assert_eq!(signed(&build(""), &policy), signed(&build(&last), &policy));
}

#[test]
fn a_generated_canonicalization_takes_the_prefix_of_foreign_transforms() {
    // Exclusive C14N renders a namespace only where it is visibly used
    // (section 3): the new child reuses the declaration on its parent.
    let policy = crate::policy::SigningPolicy::default();
    let declared = "<x:Transforms xmlns:x=\"http://www.w3.org/2000/09/xmldsig#\"";
    let open = "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";
    let exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#";
    let generated = template(
        exclusive,
        open,
        "ds:",
        &reference("ds:", "#payload", &format!("{declared}/>")),
    );
    let explicit = template(
        exclusive,
        open,
        "ds:",
        &reference(
            "ds:",
            "#payload",
            &format!("{declared}><x:Transform Algorithm=\"{C14N11}\"/></x:Transforms>"),
        ),
    );
    assert_eq!(signed(&generated, &policy), signed(&explicit, &policy));
}

#[test]
fn a_chain_read_through_a_placeholder_parses_no_more_for_generation() {
    // XPath analysis needs placeholder text, which rules deferral out. That must
    // be known before the placeholder document is parsed: one analysis parse,
    // one for the generated transform, one for the signed generation.
    let policy = crate::policy::SigningPolicy::default();
    let xpath = "<ds:Transforms><ds:Transform \
        Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">\
        <ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms>";
    let xml = template(
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
        "ds:",
        &reference("ds:", "#payload", xpath),
    )
    .replace("content", &"x".repeat(16 * 1024));
    let key = RecordingKey::default();
    let mut document = XmlDocument::parse(xml.as_str()).expect("fixture parses");
    let mut measured = SigningOperationBudgets::from_resources(&policy.resources);
    SignContext::new(&key)
        .policy(policy.clone())
        .sign_document_in_place::<CommitDocument>(&mut document, &mut measured)
        .expect("signing succeeds");
    let once = XmlParseWorkBudget::from_resources(&policy.resources);
    XmlDocument::parse_with_settings_and_budget(
        document.as_xml().to_owned(),
        DocumentParseSettings::from_policy(policy.xml, &policy.resources),
        &once,
    )
    .expect("the signed generation parses");
    let consumed = measured.transforms.xml_parse_work().consumed();
    assert!(consumed <= once.consumed() * 3, "{consumed}");
}

#[test]
fn a_generated_canonicalization_adds_no_document_parse() {
    // The document is parsed for the signed generation alone. A DOCTYPE keeps
    // the committed path, as a declared default could reach the new element.
    let padding = "x".repeat(16 * 1024);
    let xml = template(
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
        "ds:",
        &reference("ds:", "#payload", ""),
    )
    .replace("content", &padding);
    let policy = crate::policy::SigningPolicy::default();
    let key = RecordingKey::default();
    let context = SignContext::new(&key).policy(policy.clone());
    let mut document = XmlDocument::parse(xml.as_str()).expect("fixture parses");
    let mut measured = SigningOperationBudgets::from_resources(&policy.resources);
    context
        .sign_document_in_place::<CommitDocument>(&mut document, &mut measured)
        .expect("signing succeeds");
    assert!(document.as_xml().contains(C14N11));
    let once = XmlParseWorkBudget::from_resources(&policy.resources);
    XmlDocument::parse_with_settings_and_budget(
        document.as_xml().to_owned(),
        DocumentParseSettings::from_policy(policy.xml, &policy.resources),
        &once,
    )
    .expect("the signed generation parses");
    assert_eq!(
        measured.transforms.xml_parse_work().consumed(),
        once.consumed()
    );
}
