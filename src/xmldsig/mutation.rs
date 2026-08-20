//! Streaming XML mutation helpers for the XMLDSig signing pipeline.
//!
//! Signing cannot mutate `roxmltree`'s read-only DOM. These helpers validate
//! structure with `roxmltree`, then rewrite the document with `quick-xml`.

use std::{collections::HashSet, io::Write, ops::Range};

use quick_xml::events::{BytesText, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use quick_xml::{Reader, Writer};

use super::parse::XMLDSIG_NS;
use super::whitespace::is_xml_whitespace_only;

pub(super) fn parse_with_options<'a>(
    xml: &'a str,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<roxmltree::Document<'a>, roxmltree::Error> {
    let Some(policy) = policy else {
        return roxmltree::Document::parse(xml);
    };
    roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: policy.xml.allow_internal_dtd,
            nodes_limit: policy.resources.effective_xml_nodes(),
            entity_resolver: None,
        },
    )
}

fn parse_synthesized_xml_with_options<'a>(
    xml: &'a str,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<roxmltree::Document<'a>, XmlMutationError> {
    if let Some(policy) = policy {
        policy.resources.validate_xml_document_len(xml.len())?;
    }
    parse_with_options(xml, policy).map_err(Into::into)
}

/// Errors produced by XMLDSig XML mutation helpers.
#[derive(Debug, thiserror::Error)]
pub enum XmlMutationError {
    /// The compiled signing policy rejected an intermediate XML document.
    #[error("signing policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),
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
    /// The selected source element cannot receive an appended signature.
    #[error("selected source element cannot receive a signature")]
    InvalidAppendTarget,
    /// A key-info writer emitted no element child to merge.
    #[error("key-info writer emitted no element child")]
    EmptyKeyInfoSource,
    /// A reusable placeholder binds a generated namespace prefix differently.
    #[error("key-info placeholder conflicts with generated namespace prefix {prefix}")]
    ConflictingKeyInfoNamespace {
        /// The prefix whose namespace URI differs.
        prefix: String,
    },
    /// A reusable placeholder carries a different value for a generated attribute.
    #[error("key-info placeholder conflicts with generated attribute {name}")]
    ConflictingKeyInfoAttribute {
        /// The expanded-name local component of the conflicting attribute.
        name: String,
    },
}

/// Append a generated XMLDSig `<Signature>` template as the last child of the
/// source document root.
pub fn append_signature_to_root(
    xml: &str,
    signature_template: &str,
) -> Result<String, XmlMutationError> {
    append_signature_to_root_with_options(xml, signature_template, None)
}

pub(super) fn append_signature_to_root_with_options(
    xml: &str,
    signature_template: &str,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    validate_signature_template(signature_template)?;
    let source = parse_with_options(xml, policy)?;
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
    parse_synthesized_xml_with_options(&output, policy)?;
    Ok(output)
}

pub(super) fn append_signature_to_element_with_options(
    xml: &str,
    signature_template: &str,
    target: Range<usize>,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    validate_signature_template(signature_template)?;
    let _source = parse_with_options(xml, policy)?;
    let fragment = xml
        .get(target.clone())
        .ok_or(XmlMutationError::InvalidAppendTarget)?;
    let opening_end = opening_tag_end(fragment).ok_or(XmlMutationError::InvalidAppendTarget)?;
    let mut output = xml.to_owned();
    if fragment[..opening_end].trim_end().ends_with('/') {
        let slash = fragment[..opening_end]
            .trim_end()
            .strip_suffix('/')
            .map(str::len)
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        let name_end = fragment[1..]
            .find(|character: char| character.is_whitespace() || matches!(character, '/' | '>'))
            .map(|offset| offset + 1)
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        let qualified_name = &fragment[1..name_end];
        let replacement = format!(
            "{}>{signature_template}</{qualified_name}>",
            &fragment[..slash]
        );
        output.replace_range(target, &replacement);
    } else {
        let closing_start = fragment
            .rfind("</")
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        output.insert_str(target.start + closing_start, signature_template);
    }
    parse_synthesized_xml_with_options(&output, policy)?;
    Ok(output)
}

fn opening_tag_end(fragment: &str) -> Option<usize> {
    let mut quote = None;
    for (offset, character) in fragment.char_indices() {
        match (quote, character) {
            (None, '\'' | '"') => quote = Some(character),
            (Some(delimiter), current) if delimiter == current => quote = None,
            (None, '>') => return Some(offset),
            _ => {}
        }
    }
    None
}

/// Fill XMLDSig `<DigestValue>` elements in document order.
pub fn fill_digest_values<I, S>(xml: &str, values: I) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    fill_dsig_values(xml, "DigestValue", values)
}

/// Fill `<DigestValue>` elements for direct `<SignedInfo>/<Reference>` children.
pub fn fill_signed_info_digest_values<I, S>(
    xml: &str,
    values: I,
) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    fill_signed_info_digest_values_with_options(xml, values, None)
}

pub(super) fn fill_signed_info_digest_values_with_options<I, S>(
    xml: &str,
    values: I,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let target_signature = last_signature_index(xml, policy)?;
    fill_signed_info_digest_values_at_index_with_options(xml, values, target_signature, policy)
}

pub(super) fn fill_signed_info_digest_values_at_index_with_options<I, S>(
    xml: &str,
    values: I,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values: Vec<String> = values
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    let expected = count_signed_info_digest_values(xml, target_signature, policy)?;
    if expected != values.len() {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "DigestValue",
            expected,
            actual: values.len(),
        });
    }

    fill_dsig_values_matching(xml, "DigestValue", values, policy, |stack, namespace| {
        is_signed_info_reference_context(stack, namespace, target_signature)
    })
}

pub(super) fn fill_selected_manifest_digest_values_at_index_with_options<I, S>(
    xml: &str,
    replacements: I,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = (usize, S)>,
    S: AsRef<str>,
{
    let replacements = replacements
        .into_iter()
        .map(|(index, value)| (index, value.as_ref().to_owned()))
        .collect::<Vec<_>>();
    let expected = count_manifest_digest_values(xml, target_signature, policy)?;
    if replacements
        .iter()
        .enumerate()
        .any(|(position, (index, _))| {
            *index >= expected
                || position
                    .checked_sub(1)
                    .is_some_and(|previous| replacements[previous].0 >= *index)
        })
    {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "DigestValue",
            expected,
            actual: replacements.len(),
        });
    }

    let replacement_indices = replacements
        .iter()
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    let values = replacements
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    let mut manifest_index = 0usize;
    let mut replacement_index = 0usize;
    fill_dsig_values_matching(xml, "DigestValue", values, policy, |stack, namespace| {
        if !is_manifest_reference_context(stack, namespace, target_signature) {
            return false;
        }
        let selected = replacement_indices.get(replacement_index) == Some(&manifest_index);
        manifest_index += 1;
        if selected {
            replacement_index += 1;
        }
        selected
    })
}

/// Fill XMLDSig `<SignatureValue>` elements in document order.
pub fn fill_signature_values<I, S>(xml: &str, values: I) -> Result<String, XmlMutationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    fill_dsig_values(xml, "SignatureValue", values)
}

/// Fill the direct `<Signature>/<SignatureValue>` child for a signing template.
pub fn fill_signature_value(xml: &str, value: &str) -> Result<String, XmlMutationError> {
    fill_signature_value_with_options(xml, value, None)
}

pub(super) fn fill_signature_value_with_options(
    xml: &str,
    value: &str,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    let target_signature = last_signature_index(xml, policy)?;
    fill_signature_value_at_index_with_options(xml, value, target_signature, policy)
}

pub(super) fn fill_signature_value_at_index_with_options(
    xml: &str,
    value: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    let expected = count_direct_signature_values(xml, target_signature, policy)?;
    if expected != 1 {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "SignatureValue",
            expected,
            actual: 1,
        });
    }

    fill_dsig_values_matching(
        xml,
        "SignatureValue",
        vec![value.to_owned()],
        policy,
        |stack, namespace| is_direct_signature_context(stack, namespace, target_signature),
    )
}

/// Fill the direct `<Signature>/<KeyInfo>` child with XML child content.
pub fn fill_key_info(xml: &str, key_info_content: &str) -> Result<String, XmlMutationError> {
    fill_key_info_with_options(xml, key_info_content, None)
}

pub(super) fn fill_key_info_with_options(
    xml: &str,
    key_info_content: &str,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    let target_signature = last_signature_index(xml, policy)?;
    fill_key_info_at_index_with_options(xml, key_info_content, target_signature, policy)
}

pub(super) fn fill_key_info_at_index_with_options(
    xml: &str,
    key_info_content: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    let actual = count_direct_key_infos(xml, target_signature, policy)?;
    if actual != 1 {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "KeyInfo",
            expected: 1,
            actual,
        });
    }

    fill_dsig_element_raw_matching(
        xml,
        "KeyInfo",
        key_info_content,
        policy,
        |stack, namespace| is_direct_signature_context(stack, namespace, target_signature),
    )
}

pub(super) fn merge_key_info_source_at_index_with_options(
    xml: &str,
    key_info_source: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    let document = parse_with_options(xml, policy)?;
    let Some(signature) = signature_node(&document, target_signature) else {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "Signature",
            expected: 1,
            actual: 0,
        });
    };
    let key_infos = signature
        .children()
        .filter(|node| is_dsig_node(*node, "KeyInfo"))
        .collect::<Vec<_>>();
    if key_infos.len() != 1 {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "KeyInfo",
            expected: 1,
            actual: key_infos.len(),
        });
    }
    let key_info = key_infos[0];

    // The writer contract is XML child content, not a standalone document.
    // Parse it under the template's namespace context so multiple siblings and
    // inherited prefixes have exactly the semantics they will have in KeyInfo.
    let wrapped_source = wrap_key_info_children(key_info_source, key_info);
    let source_document = parse_synthesized_xml_with_options(&wrapped_source, policy)?;
    let sources = source_document
        .root_element()
        .children()
        .filter(|node| node.is_element())
        .map(|node| {
            Ok((
                node.tag_name().namespace().map(str::to_owned),
                node.tag_name().name().to_owned(),
                standalone_element(&wrapped_source, node)?,
            ))
        })
        .collect::<Result<Vec<_>, XmlMutationError>>()?;
    if sources.is_empty() {
        return Err(XmlMutationError::EmptyKeyInfoSource);
    }

    let generated_key_material_sources = sources
        .iter()
        .filter(|(namespace, name, _)| is_cryptographic_key_info_source(namespace.as_deref(), name))
        .map(|(namespace, name, _)| (namespace.as_deref(), name.as_str()))
        .collect::<Vec<_>>();
    let generated_key_name = sources
        .iter()
        .any(|(namespace, name, _)| is_dsig_key_name(namespace.as_deref(), name));
    let generated_x509_data = generated_key_material_sources
        .iter()
        .any(|(namespace, name)| is_dsig_x509_data(*namespace, name));
    let mut output = xml.to_owned();
    if !generated_key_material_sources.is_empty() || generated_key_name {
        // Writer-provided identity is authoritative within its own group.
        // Generated key material replaces stale material, while KeyName is
        // replaced only by a generated KeyName; extension elements remain.
        let mut stale_ranges = key_info
            .children()
            .filter(|node| node.is_element())
            .flat_map(|node| {
                let replaces_key_material = !generated_key_material_sources.is_empty()
                    && is_cryptographic_key_info_source(
                        node.tag_name().namespace(),
                        node.tag_name().name(),
                    );
                let replaces_key_name = generated_key_name
                    && is_dsig_key_name(node.tag_name().namespace(), node.tag_name().name());
                if !(replaces_key_material || replaces_key_name)
                    || !has_cryptographic_identity_content(node)
                    || is_matching_empty_placeholder(node, &generated_key_material_sources)
                {
                    return Vec::new();
                }
                if generated_x509_data
                    && is_dsig_x509_data(node.tag_name().namespace(), node.tag_name().name())
                {
                    return node
                        .children()
                        .filter(|child| child.is_element() && is_x509_identity_child(*child))
                        .map(|child| child.range())
                        .collect();
                }
                vec![node.range()]
            })
            .collect::<Vec<_>>();
        stale_ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
        for range in stale_ranges {
            output.replace_range(range, "");
        }
    }

    for (_, _, source) in sources {
        output = merge_one_key_info_source_at_index_with_options(
            &output,
            &source,
            target_signature,
            policy,
        )?;
    }
    Ok(output)
}

fn merge_one_key_info_source_at_index_with_options(
    xml: &str,
    key_info_source: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<String, XmlMutationError> {
    let document = parse_with_options(xml, policy)?;
    let source_document = parse_with_options(key_info_source, policy)?;
    let source = source_document.root_element();
    let source_content = element_inner_xml(key_info_source, source.range())?;
    let Some(signature) = signature_node(&document, target_signature) else {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "Signature",
            expected: 1,
            actual: 0,
        });
    };
    let key_infos = signature
        .children()
        .filter(|node| is_dsig_node(*node, "KeyInfo"))
        .collect::<Vec<_>>();
    if key_infos.len() != 1 {
        return Err(XmlMutationError::ValueCountMismatch {
            element: "KeyInfo",
            expected: 1,
            actual: key_infos.len(),
        });
    }
    let key_info = key_infos[0];

    let source_is_x509_data =
        is_dsig_x509_data(source.tag_name().namespace(), source.tag_name().name());
    if let Some(placeholder) = key_info.children().find(|node| {
        node.is_element()
            && node.tag_name() == source.tag_name()
            && (is_reusable_placeholder(*node)
                || (source_is_x509_data && has_x509_mergeable_metadata(*node)))
    }) {
        let placeholder_fragment = &xml[placeholder.range()];
        let placeholder_opening_end = element_opening_end(placeholder_fragment)
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        let placeholder_owned_namespaces =
            owned_namespace_declarations(&placeholder_fragment[..placeholder_opening_end - 1])?;
        let generated_namespace_attributes =
            source
                .namespaces()
                .try_fold(String::new(), |mut attributes, namespace| {
                    let prefix = namespace.name().unwrap_or_default();
                    if placeholder_owned_namespaces.contains(prefix) {
                        let declared = placeholder
                            .namespaces()
                            .find(|declared| declared.name() == namespace.name())
                            .ok_or(XmlMutationError::InvalidAppendTarget)?;
                        if declared.uri() != namespace.uri() {
                            return Err(XmlMutationError::ConflictingKeyInfoNamespace {
                                prefix: prefix.to_owned(),
                            });
                        }
                        return Ok(attributes);
                    }
                    if placeholder
                        .parent_element()
                        .and_then(|parent| parent.lookup_namespace_uri(namespace.name()))
                        == Some(namespace.uri())
                    {
                        return Ok(attributes);
                    }
                    let attribute = namespace
                        .name()
                        .map_or_else(|| "xmlns".to_owned(), |prefix| format!("xmlns:{prefix}"));
                    attributes.push_str(&format!(
                        " {attribute}=\"{}\"",
                        quick_xml::escape::escape(namespace.uri())
                    ));
                    Ok(attributes)
                })?;
        let generated_attributes =
            source
                .attributes()
                .try_fold(String::new(), |mut attributes, attribute| {
                    let existing = placeholder.attributes().find(|candidate| {
                        candidate.namespace() == attribute.namespace()
                            && candidate.name() == attribute.name()
                    });
                    if let Some(existing) = existing {
                        if existing.value() != attribute.value() {
                            return Err(XmlMutationError::ConflictingKeyInfoAttribute {
                                name: attribute.name().to_owned(),
                            });
                        }
                        return Ok(attributes);
                    }
                    let qualified_name = match attribute.namespace() {
                        None => attribute.name().to_owned(),
                        Some("http://www.w3.org/XML/1998/namespace") => {
                            format!("xml:{}", attribute.name())
                        }
                        Some(namespace) => {
                            let prefix = source
                                .lookup_prefix(namespace)
                                .ok_or(XmlMutationError::InvalidAppendTarget)?;
                            format!("{prefix}:{}", attribute.name())
                        }
                    };
                    attributes.push_str(&format!(
                        " {qualified_name}=\"{}\"",
                        quick_xml::escape::escape(attribute.value())
                    ));
                    Ok(attributes)
                })?;
        let generated_attributes =
            format!("{generated_namespace_attributes}{generated_attributes}");
        let output = if is_reusable_placeholder(placeholder) {
            replace_element_content(
                xml,
                placeholder.range(),
                source_content,
                &generated_attributes,
            )?
        } else {
            append_element_content(
                xml,
                placeholder.range(),
                source_content,
                &generated_attributes,
            )?
        };
        parse_synthesized_xml_with_options(&output, policy)?;
        return Ok(output);
    }

    let range = key_info.range();
    let raw_key_info = &xml[range.clone()];
    let mut output = xml.to_owned();
    if raw_key_info.trim_end().ends_with("/>") {
        let name_end = raw_key_info[1..]
            .find(|character: char| {
                character.is_ascii_whitespace() || character == '/' || character == '>'
            })
            .map(|offset| offset + 1)
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        let qualified_name = &raw_key_info[1..name_end];
        let empty_end = raw_key_info
            .rfind("/>")
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        let expanded = format!(
            "{}>{}</{}>",
            &raw_key_info[..empty_end],
            key_info_source,
            qualified_name
        );
        output.replace_range(range, &expanded);
    } else {
        let closing = raw_key_info
            .rfind("</")
            .map(|offset| range.start + offset)
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        output.insert_str(closing, key_info_source);
    }
    parse_synthesized_xml_with_options(&output, policy)?;
    Ok(output)
}

fn wrap_key_info_children(source: &str, key_info: roxmltree::Node<'_, '_>) -> String {
    let mut wrapper = String::from("<KeyInfoFragment");
    for namespace in key_info.namespaces() {
        let declaration = namespace
            .name()
            .map_or_else(|| "xmlns".to_owned(), |prefix| format!("xmlns:{prefix}"));
        wrapper.push_str(&format!(
            " {declaration}=\"{}\"",
            quick_xml::escape::escape(namespace.uri())
        ));
    }
    wrapper.push('>');
    wrapper.push_str(source);
    wrapper.push_str("</KeyInfoFragment>");
    wrapper
}

fn standalone_element(
    source: &str,
    node: roxmltree::Node<'_, '_>,
) -> Result<String, XmlMutationError> {
    let fragment = &source[node.range()];
    let opening_end = element_opening_end(fragment).ok_or(XmlMutationError::InvalidAppendTarget)?;
    let opening = &fragment[..opening_end - 1];
    let namespace_insertion = opening.strip_suffix('/').map_or(opening.len(), str::len);
    let mut output = opening[..namespace_insertion].to_owned();
    let owned_namespaces = owned_namespace_declarations(opening)?;
    for namespace in node.namespaces() {
        let declaration = namespace
            .name()
            .map_or_else(|| "xmlns".to_owned(), |prefix| format!("xmlns:{prefix}"));
        if !owned_namespaces.contains(namespace.name().unwrap_or_default()) {
            output.push_str(&format!(
                " {declaration}=\"{}\"",
                quick_xml::escape::escape(namespace.uri())
            ));
        }
    }
    output.push_str(&opening[namespace_insertion..]);
    output.push_str(&fragment[opening_end - 1..]);
    Ok(output)
}

fn owned_namespace_declarations(opening: &str) -> Result<HashSet<String>, XmlMutationError> {
    let standalone = format!("{} />", opening.trim_end_matches('/'));
    let mut reader = Reader::from_str(&standalone);
    let event = reader.read_event()?;
    let element = match event {
        Event::Start(element) | Event::Empty(element) => element,
        _ => return Err(XmlMutationError::InvalidAppendTarget),
    };
    element
        .attributes()
        .map(|attribute| {
            let attribute = attribute.map_err(|_| XmlMutationError::InvalidAppendTarget)?;
            let name = std::str::from_utf8(attribute.key.as_ref())
                .map_err(|_| XmlMutationError::InvalidAppendTarget)?;
            Ok(match name {
                "xmlns" => Some(String::new()),
                _ => name.strip_prefix("xmlns:").map(str::to_owned),
            })
        })
        .filter_map(|result| result.transpose())
        .collect()
}

fn is_matching_empty_placeholder(
    node: roxmltree::Node<'_, '_>,
    generated_sources: &[(Option<&str>, &str)],
) -> bool {
    generated_sources.iter().any(|(namespace, name)| {
        node.tag_name().namespace() == *namespace
            && node.tag_name().name() == *name
            && is_reusable_placeholder(node)
    })
}

fn is_reusable_placeholder(node: roxmltree::Node<'_, '_>) -> bool {
    node.children()
        .all(|child| child.is_text() && child.text().is_some_and(is_xml_whitespace_only))
}

fn has_cryptographic_identity_content(node: roxmltree::Node<'_, '_>) -> bool {
    if is_dsig_x509_data(node.tag_name().namespace(), node.tag_name().name()) {
        return node
            .children()
            .any(|child| child.is_element() && is_x509_identity_child(child));
    }
    if node.children().any(|child| child.is_element()) {
        return true;
    }
    match (node.tag_name().namespace(), node.tag_name().name()) {
        (Some(XMLDSIG_NS), "KeyName") => node
            .children()
            .filter_map(|child| child.text())
            .any(|text| !is_xml_whitespace_only(text)),
        (Some(XMLDSIG_NS), "RetrievalMethod") => node.attribute("URI").is_some(),
        (Some("http://www.w3.org/2009/xmldsig11#"), "DEREncodedKeyValue") => node
            .children()
            .filter_map(|child| child.text())
            .any(|text| !is_xml_whitespace_only(text)),
        _ => false,
    }
}

fn is_dsig_x509_data(namespace: Option<&str>, name: &str) -> bool {
    namespace == Some(XMLDSIG_NS) && name == "X509Data"
}

fn is_x509_identity_child(node: roxmltree::Node<'_, '_>) -> bool {
    matches!(
        (node.tag_name().namespace(), node.tag_name().name()),
        (
            Some(XMLDSIG_NS),
            "X509IssuerSerial" | "X509SKI" | "X509SubjectName" | "X509Certificate"
        ) | (Some("http://www.w3.org/2009/xmldsig11#"), "X509Digest")
    )
}

fn has_x509_mergeable_metadata(node: roxmltree::Node<'_, '_>) -> bool {
    node.children().any(|child| child.is_element()) && !has_cryptographic_identity_content(node)
}

fn is_cryptographic_key_info_source(namespace: Option<&str>, name: &str) -> bool {
    matches!(
        (namespace, name),
        (
            Some(XMLDSIG_NS),
            "KeyValue" | "RetrievalMethod" | "X509Data" | "PGPData" | "SPKIData"
        ) | (
            Some("http://www.w3.org/2009/xmldsig11#"),
            "DEREncodedKeyValue" | "KeyInfoReference"
        )
    )
}

fn is_dsig_key_name(namespace: Option<&str>, name: &str) -> bool {
    namespace == Some(XMLDSIG_NS) && name == "KeyName"
}

fn element_inner_xml(xml: &str, range: Range<usize>) -> Result<&str, XmlMutationError> {
    let element = &xml[range];
    if element.trim_end().ends_with("/>") {
        return Ok("");
    }
    let content_start =
        element_opening_end(element).ok_or(XmlMutationError::InvalidAppendTarget)?;
    let content_end = element
        .rfind("</")
        .ok_or(XmlMutationError::InvalidAppendTarget)?;
    Ok(&element[content_start..content_end])
}

fn replace_element_content(
    xml: &str,
    range: Range<usize>,
    content: &str,
    namespace_attributes: &str,
) -> Result<String, XmlMutationError> {
    let element = &xml[range.clone()];
    let mut output = xml.to_owned();
    if element.trim_end().ends_with("/>") {
        let name_end = element[1..]
            .find(|character: char| {
                character.is_ascii_whitespace() || character == '/' || character == '>'
            })
            .map(|offset| offset + 1)
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        let qualified_name = &element[1..name_end];
        let empty_end = element
            .rfind("/>")
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        output.replace_range(
            range,
            &format!(
                "{}{}>{}</{}>",
                &element[..empty_end],
                namespace_attributes,
                content,
                qualified_name
            ),
        );
    } else {
        let content_start =
            element_opening_end(element).ok_or(XmlMutationError::InvalidAppendTarget)?;
        let content_end = element
            .rfind("</")
            .ok_or(XmlMutationError::InvalidAppendTarget)?;
        let replacement = format!(
            "{}{}>{}{}",
            &element[..content_start - 1],
            namespace_attributes,
            content,
            &element[content_end..]
        );
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn append_element_content(
    xml: &str,
    range: Range<usize>,
    content: &str,
    namespace_attributes: &str,
) -> Result<String, XmlMutationError> {
    let element = &xml[range.clone()];
    let content_start =
        element_opening_end(element).ok_or(XmlMutationError::InvalidAppendTarget)?;
    let content_end = element
        .rfind("</")
        .ok_or(XmlMutationError::InvalidAppendTarget)?;
    let replacement = format!(
        "{}{}>{}{}{}",
        &element[..content_start - 1],
        namespace_attributes,
        &element[content_start..content_end],
        content,
        &element[content_end..]
    );
    let mut output = xml.to_owned();
    output.replace_range(range, &replacement);
    Ok(output)
}

fn element_opening_end(fragment: &str) -> Option<usize> {
    let mut quote = None;
    for (offset, character) in fragment.char_indices() {
        match (quote, character) {
            (None, '\'' | '"') => quote = Some(character),
            (Some(delimiter), current) if delimiter == current => quote = None,
            (None, '>') => return Some(offset + 1),
            _ => {}
        }
    }
    None
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

    fill_dsig_values_matching(xml, local_name, values, None, |_, _| true)
}

fn fill_dsig_values_matching(
    xml: &str,
    local_name: &'static str,
    values: Vec<String>,
    policy: Option<&crate::policy::SigningPolicy>,
    mut should_replace: impl FnMut(&[(bool, Vec<u8>, Option<usize>)], &ResolveResult<'_>) -> bool,
) -> Result<String, XmlMutationError> {
    let mut reader = NsReader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    let mut value_index = 0usize;
    let mut replacing_depth: Option<usize> = None;
    let mut element_stack: Vec<(bool, Vec<u8>, Option<usize>)> = Vec::new();
    let mut signature_index = 0usize;

    loop {
        let (namespace, event) = reader.read_resolved_event_into(&mut buf)?;
        if let Some(depth) = replacing_depth.as_mut() {
            match event {
                Event::Start(_) => *depth += 1,
                Event::End(end) if *depth == 0 => {
                    writer.write_event(Event::End(end))?;
                    replacing_depth = None;
                    element_stack.pop();
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
                if is_dsig_element(&namespace, element.local_name().as_ref(), local_name)
                    && should_replace(&element_stack, &namespace) =>
            {
                let signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                element_stack.push((
                    is_dsig_namespace(&namespace),
                    element.local_name().as_ref().to_vec(),
                    signature,
                ));
                writer.write_event(Event::Start(element))?;
                writer.write_event(Event::Text(BytesText::new(&values[value_index])))?;
                value_index += 1;
                replacing_depth = Some(0);
            }
            Event::Empty(element)
                if is_dsig_element(&namespace, element.local_name().as_ref(), local_name)
                    && should_replace(&element_stack, &namespace) =>
            {
                let _signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                writer.write_event(Event::Start(element.borrow()))?;
                writer.write_event(Event::Text(BytesText::new(&values[value_index])))?;
                value_index += 1;
                writer.write_event(Event::End(element.to_end()))?;
            }
            Event::Start(element) => {
                let signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                element_stack.push((
                    is_dsig_namespace(&namespace),
                    element.local_name().as_ref().to_vec(),
                    signature,
                ));
                writer.write_event(Event::Start(element))?;
            }
            Event::Empty(element) => {
                let _signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                writer.write_event(Event::Empty(element))?
            }
            Event::End(element) => {
                element_stack.pop();
                writer.write_event(Event::End(element))?;
            }
            Event::Eof => break,
            event => writer.write_event(event)?,
        }
        buf.clear();
    }

    if value_index != values.len() {
        return Err(XmlMutationError::ValueCountMismatch {
            element: local_name,
            expected: values.len(),
            actual: value_index,
        });
    }

    let output = String::from_utf8(writer.into_inner())?;
    parse_synthesized_xml_with_options(&output, policy)?;
    Ok(output)
}

fn fill_dsig_element_raw_matching(
    xml: &str,
    local_name: &'static str,
    content: &str,
    policy: Option<&crate::policy::SigningPolicy>,
    mut should_replace: impl FnMut(&[(bool, Vec<u8>, Option<usize>)], &ResolveResult<'_>) -> bool,
) -> Result<String, XmlMutationError> {
    let mut reader = NsReader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    let mut replacing_depth: Option<usize> = None;
    let mut element_stack: Vec<(bool, Vec<u8>, Option<usize>)> = Vec::new();
    let mut signature_index = 0usize;

    loop {
        let (namespace, event) = reader.read_resolved_event_into(&mut buf)?;
        if let Some(depth) = replacing_depth.as_mut() {
            match event {
                Event::Start(_) => *depth += 1,
                Event::End(end) if *depth == 0 => {
                    writer.write_event(Event::End(end))?;
                    replacing_depth = None;
                    element_stack.pop();
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
                if is_dsig_element(&namespace, element.local_name().as_ref(), local_name)
                    && should_replace(&element_stack, &namespace) =>
            {
                let signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                element_stack.push((
                    is_dsig_namespace(&namespace),
                    element.local_name().as_ref().to_vec(),
                    signature,
                ));
                writer.write_event(Event::Start(element))?;
                writer.get_mut().write_all(content.as_bytes())?;
                replacing_depth = Some(0);
            }
            Event::Empty(element)
                if is_dsig_element(&namespace, element.local_name().as_ref(), local_name)
                    && should_replace(&element_stack, &namespace) =>
            {
                let _signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                writer.write_event(Event::Start(element.borrow()))?;
                writer.get_mut().write_all(content.as_bytes())?;
                writer.write_event(Event::End(element.to_end()))?;
            }
            Event::Start(element) => {
                let signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                element_stack.push((
                    is_dsig_namespace(&namespace),
                    element.local_name().as_ref().to_vec(),
                    signature,
                ));
                writer.write_event(Event::Start(element))?;
            }
            Event::Empty(element) => {
                let _signature = signature_stack_index(
                    &namespace,
                    element.local_name().as_ref(),
                    &mut signature_index,
                );
                writer.write_event(Event::Empty(element))?
            }
            Event::End(element) => {
                element_stack.pop();
                writer.write_event(Event::End(element))?;
            }
            Event::Eof => break,
            event => writer.write_event(event)?,
        }
        buf.clear();
    }

    let output = String::from_utf8(writer.into_inner())?;
    parse_synthesized_xml_with_options(&output, policy)?;
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

fn count_signed_info_digest_values(
    xml: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<usize, XmlMutationError> {
    let document = parse_with_options(xml, policy)?;
    let Some(signature) = signature_node(&document, target_signature) else {
        return Ok(0);
    };
    Ok(document
        .descendants()
        .filter(|node| is_direct_signed_info_reference_digest(*node, signature))
        .count())
}

fn count_direct_signature_values(
    xml: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<usize, XmlMutationError> {
    let document = parse_with_options(xml, policy)?;
    let Some(signature) = signature_node(&document, target_signature) else {
        return Ok(0);
    };
    Ok(document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == "SignatureValue"
                && node.parent().is_some_and(|parent| parent == signature)
        })
        .count())
}

fn count_direct_key_infos(
    xml: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<usize, XmlMutationError> {
    let document = parse_with_options(xml, policy)?;
    let Some(signature) = signature_node(&document, target_signature) else {
        return Ok(0);
    };
    Ok(document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == "KeyInfo"
                && node.parent().is_some_and(|parent| parent == signature)
        })
        .count())
}

fn count_manifest_digest_values(
    xml: &str,
    target_signature: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<usize, XmlMutationError> {
    let document = parse_with_options(xml, policy)?;
    let Some(signature) = signature_node(&document, target_signature) else {
        return Ok(0);
    };
    Ok(signature
        .children()
        .filter(|node| is_dsig_node(*node, "Object"))
        .flat_map(|object| {
            object
                .children()
                .filter(|node| is_dsig_node(*node, "Manifest"))
        })
        .flat_map(|manifest| {
            manifest
                .children()
                .filter(|node| is_dsig_node(*node, "Reference"))
        })
        .flat_map(|reference| {
            reference
                .children()
                .filter(|node| is_dsig_node(*node, "DigestValue"))
        })
        .count())
}

fn signature_node<'a>(
    document: &'a roxmltree::Document<'a>,
    target_signature: usize,
) -> Option<roxmltree::Node<'a, 'a>> {
    document
        .descendants()
        .filter(|node| is_dsig_node(*node, "Signature"))
        .nth(target_signature)
}

fn last_signature_index(
    xml: &str,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<usize, XmlMutationError> {
    let document = parse_with_options(xml, policy)?;
    document
        .descendants()
        .filter(|node| is_dsig_node(*node, "Signature"))
        .enumerate()
        .last()
        .map(|(index, _)| index)
        .ok_or(XmlMutationError::ValueCountMismatch {
            element: "Signature",
            expected: 1,
            actual: 0,
        })
}

fn is_direct_signed_info_reference_digest(
    node: roxmltree::Node<'_, '_>,
    signature: roxmltree::Node<'_, '_>,
) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(XMLDSIG_NS)
        && node.tag_name().name() == "DigestValue"
        && node
            .parent()
            .is_some_and(|parent| is_dsig_node(parent, "Reference"))
        && node
            .parent()
            .and_then(|parent| parent.parent())
            .is_some_and(|grandparent| is_dsig_node(grandparent, "SignedInfo"))
        && node
            .parent()
            .and_then(|parent| parent.parent())
            .and_then(|grandparent| grandparent.parent())
            .is_some_and(|parent| parent == signature)
}

fn is_dsig_node(node: roxmltree::Node<'_, '_>, expected_local: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(XMLDSIG_NS)
        && node.tag_name().name() == expected_local
}

fn is_signed_info_reference_context(
    element_stack: &[(bool, Vec<u8>, Option<usize>)],
    namespace: &ResolveResult<'_>,
    target_signature: usize,
) -> bool {
    is_dsig_namespace(namespace)
        && is_in_target_signature(element_stack, target_signature)
        && matches!(
            element_stack,
            [.., (true, signed_info, _), (true, reference, _)]
                if signed_info.as_slice() == b"SignedInfo"
                    && reference.as_slice() == b"Reference"
        )
}

fn is_direct_signature_context(
    element_stack: &[(bool, Vec<u8>, Option<usize>)],
    namespace: &ResolveResult<'_>,
    target_signature: usize,
) -> bool {
    is_dsig_namespace(namespace)
        && is_in_target_signature(element_stack, target_signature)
        && matches!(
            element_stack,
            [.., (true, signature, Some(index))]
                if signature.as_slice() == b"Signature" && *index == target_signature
        )
}

fn is_manifest_reference_context(
    element_stack: &[(bool, Vec<u8>, Option<usize>)],
    namespace: &ResolveResult<'_>,
    target_signature: usize,
) -> bool {
    is_dsig_namespace(namespace)
        && matches!(
            element_stack,
            [..,
                (true, signature, Some(index)),
                (true, object, _),
                (true, manifest, _),
                (true, reference, _)
            ] if *index == target_signature
                && signature.as_slice() == b"Signature"
                && object.as_slice() == b"Object"
                && manifest.as_slice() == b"Manifest"
                && reference.as_slice() == b"Reference"
        )
}

fn is_in_target_signature(
    element_stack: &[(bool, Vec<u8>, Option<usize>)],
    target_signature: usize,
) -> bool {
    element_stack
        .iter()
        .rev()
        .find(|(is_dsig, local_name, _)| *is_dsig && local_name.as_slice() == b"Signature")
        .is_some_and(|(_, _, signature)| *signature == Some(target_signature))
}

fn is_dsig_element(namespace: &ResolveResult<'_>, local: &[u8], expected_local: &str) -> bool {
    is_dsig_namespace(namespace) && local == expected_local.as_bytes()
}

fn is_dsig_namespace(namespace: &ResolveResult<'_>) -> bool {
    matches!(namespace, ResolveResult::Bound(Namespace(ns)) if *ns == XMLDSIG_NS.as_bytes())
}

fn signature_stack_index(
    namespace: &ResolveResult<'_>,
    local_name: &[u8],
    next_signature_index: &mut usize,
) -> Option<usize> {
    if is_dsig_namespace(namespace) && local_name == b"Signature" {
        let index = *next_signature_index;
        *next_signature_index += 1;
        Some(index)
    } else {
        None
    }
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
    fn appends_signature_template_to_selected_empty_element() {
        // Selected builder targets may be self-closing; insertion must expand
        // the element without dropping its qualified name or attributes.
        let source = r#"<root xmlns:s="urn:scope"><s:scope Id="urn:selected/item"/></root>"#;
        let document = roxmltree::Document::parse(source).expect("source must parse");
        let scope = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("urn:selected/item"))
            .expect("selected scope");
        let signed =
            append_signature_to_element_with_options(source, &template(1), scope.range(), None)
                .expect("selected empty element must accept a signature");
        let output = roxmltree::Document::parse(&signed).expect("output must parse");
        let scope = output
            .descendants()
            .find(|node| node.has_tag_name(("urn:scope", "scope")))
            .expect("qualified scope must remain");

        assert!(
            scope
                .children()
                .any(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
        );
        assert_eq!(scope.attribute("Id"), Some("urn:selected/item"));
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

    #[test]
    fn replacement_preserves_target_end_after_self_closing_child() {
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference><ds:DigestValue><marker/></ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature>"#;
        let filled = fill_digest_values(source, ["digest"]).expect("fill digest");
        let document = roxmltree::Document::parse(&filled).expect("parse output");
        let digest_value = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestValue")))
            .expect("DigestValue");
        assert_eq!(digest_value.text(), Some("digest"));
        assert_eq!(
            digest_value
                .next_sibling_element()
                .map(|node| node.tag_name().name()),
            None
        );
    }

    #[test]
    fn replacement_fails_when_nested_dsig_values_are_skipped() {
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference><ds:DigestValue><ds:DigestValue>nested</ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature>"#;
        let err =
            fill_digest_values(source, ["outer", "nested"]).expect_err("nested target skipped");
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
    fn indexed_digest_replacement_ignores_nested_signatures() {
        // Digest counts and replacements must use the same nearest-Signature
        // boundary or a nested Object signature can exhaust the value list.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference><ds:DigestValue>outer-old</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Signature><ds:SignedInfo><ds:Reference><ds:DigestValue>inner-keep</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></ds:Object></ds:Signature>"#;
        let filled =
            fill_signed_info_digest_values_at_index_with_options(source, ["outer-new"], 0, None)
                .expect("outer signature replacement must ignore nested signatures");
        let document = roxmltree::Document::parse(&filled).expect("filled XML must parse");
        let values = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "DigestValue")))
            .filter_map(|node| node.text())
            .collect::<Vec<_>>();

        assert_eq!(values, ["outer-new", "inner-keep"]);
    }

    #[test]
    fn key_info_source_merge_preserves_placeholder_attributes() {
        // Placeholder identity can be referenced from SignedInfo, so filling
        // its children must not replace the element that owns the ID.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data Id="key-info"/></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:example:key-info"><X509Certificate>Y2VydA==</X509Certificate><ext:Metadata/></X509Data>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("matching source must populate the placeholder");
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        let x509_data = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "X509Data")))
            .expect("X509Data");

        assert_eq!(x509_data.attribute("Id"), Some("key-info"));
        assert_eq!(
            x509_data
                .children()
                .find(|node| node.has_tag_name((XMLDSIG_NS, "X509Certificate")))
                .and_then(|node| node.text()),
            Some("Y2VydA==")
        );
        assert!(
            x509_data
                .children()
                .any(|node| node.has_tag_name(("urn:example:key-info", "Metadata")))
        );
    }

    #[test]
    fn key_info_source_merge_preserves_comment_and_processing_instruction() {
        // Comments and processing instructions are caller-owned content, not an
        // empty placeholder that the generated identity may silently replace.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data><!--keep--><?audit preserve?></ds:X509Data></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate>Y2VydA==</X509Certificate></X509Data>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("generated identity must be appended without erasing caller content");

        assert!(merged.contains("<!--keep-->"));
        assert!(merged.contains("<?audit preserve?>"));
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        let x509_sources = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "X509Data")))
            .collect::<Vec<_>>();
        assert_eq!(x509_sources.len(), 2);
        assert!(x509_sources.iter().any(|source| {
            source
                .children()
                .any(|node| node.has_tag_name((XMLDSIG_NS, "X509Certificate")))
        }));
    }

    #[test]
    fn key_info_source_merge_preserves_non_xml_whitespace_text() {
        // XML only classifies space, tab, CR, and LF as whitespace. A non-breaking
        // space is caller-owned character data and must not turn X509Data into a
        // reusable placeholder that signing silently overwrites.
        let source = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyInfo><ds:X509Data>\u{00a0}</ds:X509Data></ds:KeyInfo></ds:Signature>";
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate>Y2VydA==</X509Certificate></X509Data>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("generated identity must not replace non-whitespace character data");
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        let x509_sources = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "X509Data")))
            .collect::<Vec<_>>();

        assert_eq!(x509_sources.len(), 2);
        assert!(
            x509_sources
                .iter()
                .any(|source| source.text() == Some("\u{00a0}"))
        );
    }

    #[test]
    fn key_info_source_merge_replaces_populated_key_name_identity() {
        // A generated key name is authoritative identity metadata. Retaining a
        // populated template value would let document-order resolvers select it.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:KeyName>stale</ds:KeyName></ds:KeyInfo></ds:Signature>"#;
        let generated =
            r#"<ds:KeyName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">generated</ds:KeyName>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("generated KeyName must replace stale template identity");
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        let key_names = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "KeyName")))
            .filter_map(|node| node.text())
            .collect::<Vec<_>>();

        assert_eq!(key_names, ["generated"]);
    }

    #[test]
    fn key_info_source_merge_preserves_x509_revocation_metadata() {
        // A generated certificate replaces stale identity assertions, but the
        // caller's CRL and extension metadata still apply to that X509 source.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:example:x509"><ds:KeyInfo><ds:X509Data Id="caller"><ds:X509Certificate>c3RhbGU=</ds:X509Certificate><ds:X509SubjectName>CN=stale</ds:X509SubjectName><ds:X509CRL>Y3Js</ds:X509CRL><ext:Policy>keep</ext:Policy></ds:X509Data></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate>Z2VuZXJhdGVk</X509Certificate></X509Data>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("generated identity must preserve revocation metadata");
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        let x509_sources = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "X509Data")))
            .collect::<Vec<_>>();

        assert_eq!(x509_sources.len(), 1);
        let x509_data = x509_sources[0];
        assert_eq!(x509_data.attribute("Id"), Some("caller"));
        assert_eq!(
            x509_data
                .children()
                .find(|node| node.has_tag_name((XMLDSIG_NS, "X509Certificate")))
                .and_then(|node| node.text()),
            Some("Z2VuZXJhdGVk")
        );
        assert!(!merged.contains("c3RhbGU="));
        assert!(!merged.contains("CN=stale"));
        assert_eq!(
            x509_data
                .children()
                .find(|node| node.has_tag_name((XMLDSIG_NS, "X509CRL")))
                .and_then(|node| node.text()),
            Some("Y3Js")
        );
        assert_eq!(
            x509_data
                .children()
                .find(|node| node.has_tag_name(("urn:example:x509", "Policy")))
                .and_then(|node| node.text()),
            Some("keep")
        );
    }

    #[test]
    fn key_info_source_merge_reports_required_and_observed_counts() {
        // Mutation diagnostics are a structured API: expected is the required
        // singleton count and actual is the number observed in the template.
        for (source, actual) in [
            (
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#,
                0,
            ),
            (
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo/><ds:KeyInfo/></ds:Signature>"#,
                2,
            ),
        ] {
            let error = merge_key_info_source_at_index_with_options(
                source,
                r#"<ds:KeyName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">key</ds:KeyName>"#,
                0,
                None,
            )
            .expect_err("KeyInfo must be a singleton");
            assert!(matches!(
                error,
                XmlMutationError::ValueCountMismatch {
                    element: "KeyInfo",
                    expected: 1,
                    actual: observed,
                } if observed == actual
            ));
        }
    }

    #[test]
    fn key_info_source_merge_rejects_conflicting_placeholder_namespaces() {
        // A generated child cannot reuse a prefix that the placeholder owns
        // with another URI; emitting both declarations would create invalid XML.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data xmlns:ext="urn:template"/></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:writer"><ext:Metadata/></X509Data>"#;

        let error = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect_err("conflicting namespace bindings must fail before serialization");

        assert!(matches!(
            error,
            XmlMutationError::ConflictingKeyInfoNamespace { prefix } if prefix == "ext"
        ));
    }

    #[test]
    fn key_info_source_merge_allows_shadowing_inherited_namespaces() {
        // An ancestor binding is context, not an attribute owned by the empty
        // placeholder. The generated source may validly shadow it locally.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:inherited"><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:generated"><ext:Metadata/></X509Data>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("generated source may shadow an inherited namespace");
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        let x509_data = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "X509Data")))
            .expect("X509Data");

        assert_eq!(
            x509_data.lookup_namespace_uri(Some("ext")),
            Some("urn:generated")
        );
        assert!(
            x509_data
                .children()
                .any(|node| node.has_tag_name(("urn:generated", "Metadata")))
        );
    }

    #[test]
    fn key_info_source_merge_detects_redundant_owned_namespace_conflicts() {
        // A direct declaration remains owned by the placeholder even when it
        // repeats the parent binding; replacing it would duplicate xmlns:ext.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo xmlns:ext="urn:template"><ds:X509Data xmlns:ext="urn:template"/></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:writer"><ext:Metadata/></X509Data>"#;

        let error = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect_err("placeholder-owned namespace conflicts must be typed");

        assert!(matches!(
            error,
            XmlMutationError::ConflictingKeyInfoNamespace { prefix } if prefix == "ext"
        ));
    }

    #[test]
    fn key_info_source_merge_preserves_generated_attributes() {
        // Writer-owned identity must survive placeholder reuse so later
        // reference resolution observes the same element the writer emitted.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:key-info" Id="generated" ext:role="signing"><X509Certificate>Y2VydA==</X509Certificate></X509Data>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("generated attributes must populate the placeholder");
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        let x509_data = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "X509Data")))
            .expect("X509Data");

        assert_eq!(x509_data.attribute("Id"), Some("generated"));
        assert_eq!(
            x509_data.attribute(("urn:key-info", "role")),
            Some("signing")
        );
    }

    #[test]
    fn key_info_source_merge_accepts_whitespace_around_namespace_equals() {
        // XML permits whitespace around '='. Namespace ownership must come
        // from the parsed element rather than an exact lexical substring.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo/></ds:Signature>"#;
        let generated = r#"<ext:Metadata xmlns:ext = "urn:key-info">value</ext:Metadata>"#;

        let merged = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect("valid namespace declaration whitespace must be preserved");
        let document = roxmltree::Document::parse(&merged).expect("merged XML must parse");
        assert!(
            document
                .descendants()
                .any(|node| node.has_tag_name(("urn:key-info", "Metadata")))
        );
    }

    #[test]
    fn key_info_source_merge_rejects_conflicting_generated_attributes() {
        // Silently choosing template or writer identity would make signed
        // references ambiguous, so incompatible expanded attributes fail.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data Id="template"/></ds:KeyInfo></ds:Signature>"#;
        let generated = r#"<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#" Id="generated"><X509Certificate>Y2VydA==</X509Certificate></X509Data>"#;

        let error = merge_key_info_source_at_index_with_options(source, generated, 0, None)
            .expect_err("conflicting attributes must fail before serialization");

        assert!(matches!(
            error,
            XmlMutationError::ConflictingKeyInfoAttribute { name } if name == "Id"
        ));
    }

    #[test]
    fn key_info_source_merge_rejects_empty_writer_output() {
        // An empty writer result is a writer-contract violation, not a malformed
        // signature append target, and callers need to distinguish the two.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo/></ds:Signature>"#;

        let error = merge_key_info_source_at_index_with_options(source, "  ", 0, None)
            .expect_err("a key-info writer must emit an element child");

        assert!(matches!(error, XmlMutationError::EmptyKeyInfoSource));
    }

    #[test]
    fn key_info_source_merge_applies_policy_to_writer_fragments() {
        // A custom writer is an untrusted allocation boundary: its wrapper must
        // obey the same node ceiling as the caller's signing template.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo/></ds:Signature>"#;
        let children = (0..64).map(|_| "<part/>").collect::<String>();
        let generated = format!(
            r#"<ds:KeyName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{children}</ds:KeyName>"#
        );
        let policy = crate::policy::SigningPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: 32,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::SigningPolicy::default()
        };

        let error =
            merge_key_info_source_at_index_with_options(source, &generated, 0, Some(&policy))
                .expect_err("writer fragment must obey the signing node ceiling");

        assert!(matches!(error, XmlMutationError::XmlParse(_)));
        assert!(error.to_string().contains("nodes limit"));
    }

    #[test]
    fn key_info_source_merge_bounds_synthesized_wrapper_before_parsing() {
        // The template and writer fragment can each fit while the namespace-
        // complete wrapper synthesized for fragment parsing crosses the byte
        // ceiling. Report that allocation boundary before parsing or merging.
        let source = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:inherited"><ds:KeyInfo/></ds:Signature>"#;
        let generated =
            r#"<ds:KeyName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">recipient</ds:KeyName>"#;
        let document = roxmltree::Document::parse(source).expect("source must parse");
        let key_info = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .expect("KeyInfo");
        let wrapped = wrap_key_info_children(generated, key_info);
        let maximum = wrapped.len() - 1;
        assert!(source.len() <= maximum);
        assert!(generated.len() <= maximum);
        let policy = crate::policy::SigningPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_document_bytes: maximum,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::SigningPolicy::default()
        };

        let error =
            merge_key_info_source_at_index_with_options(source, generated, 0, Some(&policy))
                .expect_err("synthesized wrapper must be bounded before parsing");

        assert!(matches!(
            error,
            XmlMutationError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "XML document",
                maximum: observed_maximum,
                actual,
            }) if observed_maximum == maximum && actual == wrapped.len()
        ));
    }
}
