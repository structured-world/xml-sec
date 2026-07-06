//! Streaming XML mutation helpers for the XMLDSig signing pipeline.
//!
//! Signing cannot mutate `roxmltree`'s read-only DOM. These helpers validate
//! structure with `roxmltree`, then rewrite the document with `quick-xml`.

use std::io::Write;

use quick_xml::events::{BytesText, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use quick_xml::{Reader, Writer};

use super::parse::XMLDSIG_NS;

/// Errors produced by XMLDSig XML mutation helpers.
#[derive(Debug, thiserror::Error)]
pub enum XmlMutationError {
    /// Input XML or generated template is not parseable XML.
    #[error("XML parsing error: {0}")]
    XmlParse(#[from] roxmltree::Error),
    /// The streaming XML reader failed.
    #[error("XML read error: {0}")]
    Read(#[from] quick_xml::Error),
    /// The streaming XML writer failed.
    #[error("XML write error: {0}")]
    Write(#[from] std::io::Error),
    /// The writer unexpectedly emitted non-UTF-8 bytes.
    #[error("XML writer emitted invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    /// A template did not contain exactly one XMLDSig `<Signature>` root.
    #[error("signature template root must be one XMLDSig Signature element")]
    InvalidSignatureTemplate,
    /// A replacement call supplied a different number of values than matching elements.
    #[error("expected {expected} XMLDSig {element} values, got {actual}")]
    ValueCountMismatch {
        /// XMLDSig element local name.
        element: &'static str,
        /// Number of matching XMLDSig elements in the document.
        expected: usize,
        /// Number of values supplied by the caller.
        actual: usize,
    },
    /// The source XML did not contain a root element that can receive a signature.
    #[error("source XML must contain a root element")]
    MissingRootElement,
}

/// Append a generated XMLDSig `<Signature>` template as the last child of the
/// source document root.
pub fn append_signature_to_root(
    xml: &str,
    signature_template: &str,
) -> Result<String, XmlMutationError> {
    validate_signature_template(signature_template)?;
    let source = roxmltree::Document::parse(xml)?;
    if !source.root().children().any(|node| node.is_element()) {
        return Err(XmlMutationError::MissingRootElement);
    }

    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    let mut root_depth = 0usize;
    let mut saw_root = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(element) if root_depth == 0 => {
                saw_root = true;
                root_depth = 1;
                writer.write_event(Event::Start(element))?;
            }
            Event::Start(element) => {
                root_depth += 1;
                writer.write_event(Event::Start(element))?;
            }
            Event::Empty(element) if root_depth == 0 => {
                saw_root = true;
                writer.write_event(Event::Start(element.borrow()))?;
                writer.get_mut().write_all(signature_template.as_bytes())?;
                writer.write_event(Event::End(element.to_end()))?;
            }
            Event::End(element) if root_depth == 1 => {
                writer.get_mut().write_all(signature_template.as_bytes())?;
                writer.write_event(Event::End(element))?;
                root_depth = 0;
            }
            Event::End(element) => {
                root_depth = root_depth.saturating_sub(1);
                writer.write_event(Event::End(element))?;
            }
            Event::Eof => break,
            event => writer.write_event(event)?,
        }
        buf.clear();
    }

    if !saw_root {
        return Err(XmlMutationError::MissingRootElement);
    }

    let output = String::from_utf8(writer.into_inner())?;
    roxmltree::Document::parse(&output)?;
    Ok(output)
}

/// Fill XMLDSig `<DigestValue>` elements in document order.
pub fn fill_digest_values<I, S>(xml: &str, values: I) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    fill_dsig_values(xml, "DigestValue", values)
}

/// Fill XMLDSig `<SignatureValue>` elements in document order.
pub fn fill_signature_values<I, S>(xml: &str, values: I) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    fill_dsig_values(xml, "SignatureValue", values)
}

fn fill_dsig_values<I, S>(
    xml: &str,
    local_name: &'static str,
    values: I,
) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values: Vec<String> = values
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    let expected = count_dsig_elements(xml, local_name)?;
    if expected != values.len() {
        return Err(XmlMutationError::ValueCountMismatch {
            element: local_name,
            expected,
            actual: values.len(),
        });
    }

    let mut reader = NsReader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    let mut value_index = 0usize;
    let mut replacing_depth: Option<usize> = None;

    loop {
        let (namespace, event) = reader.read_resolved_event_into(&mut buf)?;
        if let Some(depth) = replacing_depth.as_mut() {
            match event {
                Event::Start(_) | Event::Empty(_) => *depth += 1,
                Event::End(end) if *depth == 0 => {
                    writer.write_event(Event::End(end))?;
                    replacing_depth = None;
                }
                Event::End(_) => *depth -= 1,
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
            continue;
        }

        match event {
            Event::Start(element)
                if is_dsig_element(&namespace, element.local_name().as_ref(), local_name) =>
            {
                writer.write_event(Event::Start(element))?;
                writer.write_event(Event::Text(BytesText::new(&values[value_index])))?;
                value_index += 1;
                replacing_depth = Some(0);
            }
            Event::Empty(element)
                if is_dsig_element(&namespace, element.local_name().as_ref(), local_name) =>
            {
                writer.write_event(Event::Start(element.borrow()))?;
                writer.write_event(Event::Text(BytesText::new(&values[value_index])))?;
                value_index += 1;
                writer.write_event(Event::End(element.to_end()))?;
            }
            Event::Eof => break,
            event => writer.write_event(event)?,
        }
        buf.clear();
    }

    let output = String::from_utf8(writer.into_inner())?;
    roxmltree::Document::parse(&output)?;
    Ok(output)
}

fn validate_signature_template(signature_template: &str) -> Result<(), XmlMutationError> {
    let document = roxmltree::Document::parse(signature_template)?;
    let root = document.root_element();
    if root.tag_name().namespace() == Some(XMLDSIG_NS) && root.tag_name().name() == "Signature" {
        Ok(())
    } else {
        Err(XmlMutationError::InvalidSignatureTemplate)
    }
}

fn count_dsig_elements(xml: &str, local_name: &str) -> Result<usize, XmlMutationError> {
    let document = roxmltree::Document::parse(xml)?;
    Ok(document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == local_name
        })
        .count())
}

fn is_dsig_element(namespace: &ResolveResult<'_>, local: &[u8], expected_local: &str) -> bool {
    matches!(namespace, ResolveResult::Bound(Namespace(ns)) if *ns == XMLDSIG_NS.as_bytes())
        && local == expected_local.as_bytes()
}

#[cfg(test)]
mod tests {
    use crate::c14n::{C14nAlgorithm, C14nMode};
    use crate::xmldsig::{
        DigestAlgorithm, ReferenceBuilder, SignatureAlgorithm, SignatureBuilder, Transform,
    };

    use super::*;

    fn template(reference_count: usize) -> String {
        let mut builder = SignatureBuilder::new(
            C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
            SignatureAlgorithm::RsaSha256,
        )
        .ns_prefix("ds");
        for index in 0..reference_count {
            builder = builder.add_reference(
                ReferenceBuilder::new(DigestAlgorithm::Sha256)
                    .uri(format!("#ref-{index}"))
                    .transform(Transform::Enveloped),
            );
        }
        builder.build_template().expect("valid template")
    }

    #[test]
    fn appends_signature_template_to_non_empty_root() {
        let signed = append_signature_to_root("<root><payload ID=\"ref-0\"/></root>", &template(1))
            .expect("append signature");
        let document = roxmltree::Document::parse(&signed).expect("parse output");
        let root = document.root_element();
        let children: Vec<_> = root
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|node| node.tag_name().name())
            .collect();
        assert_eq!(children, ["payload", "Signature"]);
        assert_eq!(
            root.last_element_child()
                .expect("signature")
                .tag_name()
                .namespace(),
            Some(XMLDSIG_NS)
        );
    }

    #[test]
    fn appends_signature_template_to_empty_root() {
        let signed = append_signature_to_root("<root/>", &template(1)).expect("append signature");
        let document = roxmltree::Document::parse(&signed).expect("parse output");
        let root = document.root_element();
        assert_eq!(
            root.first_element_child()
                .expect("signature")
                .tag_name()
                .name(),
            "Signature"
        );
    }

    #[test]
    fn rejects_non_signature_template() {
        let err = append_signature_to_root("<root/>", "<NotSignature/>")
            .expect_err("template must be a Signature");
        assert!(matches!(err, XmlMutationError::InvalidSignatureTemplate));
    }

    #[test]
    fn fills_digest_values_in_xml_dsig_document_order() {
        let signed = append_signature_to_root("<root/>", &template(2)).expect("append signature");
        let filled =
            fill_digest_values(&signed, ["digest-one", "digest-two"]).expect("fill digest values");
        let document = roxmltree::Document::parse(&filled).expect("parse output");
        let values: Vec<_> = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "DigestValue")))
            .map(|node| node.text())
            .collect();
        assert_eq!(values, [Some("digest-one"), Some("digest-two")]);
    }

    #[test]
    fn fills_signature_value_without_touching_digest_values() {
        let signed = append_signature_to_root("<root/>", &template(1)).expect("append signature");
        let filled =
            fill_signature_values(&signed, ["signature&bytes"]).expect("fill signature value");
        let document = roxmltree::Document::parse(&filled).expect("parse output");
        let signature_value = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignatureValue")))
            .expect("SignatureValue");
        assert_eq!(signature_value.text(), Some("signature&bytes"));
        let digest_value = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestValue")))
            .expect("DigestValue");
        assert_eq!(digest_value.text(), None);
    }

    #[test]
    fn replacement_count_must_match_dsig_elements() {
        let signed = append_signature_to_root("<root/>", &template(2)).expect("append signature");
        let err = fill_digest_values(&signed, ["only-one"]).expect_err("mismatch");
        assert!(matches!(
            err,
            XmlMutationError::ValueCountMismatch {
                element: "DigestValue",
                expected: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn does_not_replace_foreign_same_local_name_elements() {
        let source = r#"<root xmlns:foreign="urn:test"><foreign:DigestValue>keep</foreign:DigestValue></root>"#;
        let signed = append_signature_to_root(source, &template(1)).expect("append signature");
        let filled = fill_digest_values(&signed, ["digest"]).expect("fill digest");
        let document = roxmltree::Document::parse(&filled).expect("parse output");
        let foreign = document
            .descendants()
            .find(|node| node.has_tag_name(("urn:test", "DigestValue")))
            .expect("foreign DigestValue");
        assert_eq!(foreign.text(), Some("keep"));
        let dsig = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestValue")))
            .expect("dsig DigestValue");
        assert_eq!(dsig.text(), Some("digest"));
    }
}
