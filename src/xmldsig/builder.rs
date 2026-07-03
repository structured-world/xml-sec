//! Builders for deterministic XMLDSig signature templates.

use std::io::Write;

use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};

use crate::c14n::{C14nAlgorithm, C14nMode};

use super::{
    DigestAlgorithm, ENVELOPED_SIGNATURE_URI, SignatureAlgorithm, Transform, XPATH_TRANSFORM_URI,
};

const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const XPATH_EXCLUDE_ALL_SIGNATURES: &str = "not(ancestor-or-self::dsig:Signature)";

/// Errors produced while validating or serializing an XMLDSig template.
#[derive(Debug, thiserror::Error)]
pub enum SignatureBuilderError {
    /// A namespace prefix was not a supported XML NCName.
    #[error("invalid XML namespace prefix: {0}")]
    InvalidNamespacePrefix(String),
    /// An XMLDSig Id attribute was not a valid XML NCName.
    #[error("invalid {element} Id: {value}")]
    InvalidId {
        /// XMLDSig element carrying the Id attribute.
        element: &'static str,
        /// Rejected attribute value.
        value: String,
    },
    /// XMLDSig requires at least one reference in SignedInfo.
    #[error("a signature template requires at least one Reference")]
    MissingReference,
    /// SHA-1 algorithms are available for verification but not new signatures.
    #[error("algorithm is not allowed for signing: {0}")]
    SigningAlgorithmDisabled(&'static str),
    /// The XML writer failed.
    #[error("XML serialization error: {0}")]
    Serialization(#[from] std::io::Error),
    /// The writer unexpectedly emitted bytes that are not UTF-8.
    #[error("XML writer emitted invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

/// Builder for a single XMLDSig `<Reference>` template.
#[derive(Debug, Clone)]
pub struct ReferenceBuilder {
    uri: Option<String>,
    id: Option<String>,
    ref_type: Option<String>,
    transforms: Vec<Transform>,
    digest_method: DigestAlgorithm,
}

impl ReferenceBuilder {
    /// Create a reference using the required digest algorithm.
    #[must_use]
    pub fn new(digest_method: DigestAlgorithm) -> Self {
        Self {
            uri: None,
            id: None,
            ref_type: None,
            transforms: Vec::new(),
            digest_method,
        }
    }

    /// Set the optional reference URI.
    #[must_use]
    pub fn uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Set the optional reference Id.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the optional reference Type URI.
    #[must_use]
    pub fn ref_type(mut self, ref_type: impl Into<String>) -> Self {
        self.ref_type = Some(ref_type.into());
        self
    }

    /// Append a transform, preserving insertion order.
    #[must_use]
    pub fn transform(mut self, transform: Transform) -> Self {
        self.transforms.push(transform);
        self
    }
}

/// Builder for a complete XMLDSig `<Signature>` template.
#[derive(Debug, Clone)]
pub struct SignatureBuilder {
    c14n_method: C14nAlgorithm,
    sign_method: SignatureAlgorithm,
    ns_prefix: Option<String>,
    signature_id: Option<String>,
    references: Vec<ReferenceBuilder>,
    include_key_info: bool,
}

impl SignatureBuilder {
    /// Create a signature template using the required algorithms.
    #[must_use]
    pub fn new(c14n_method: C14nAlgorithm, sign_method: SignatureAlgorithm) -> Self {
        Self {
            c14n_method,
            sign_method,
            ns_prefix: None,
            signature_id: None,
            references: Vec::new(),
            include_key_info: false,
        }
    }

    /// Use a namespace prefix such as `ds`; the default is an unprefixed namespace.
    #[must_use]
    pub fn ns_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.ns_prefix = Some(prefix.into());
        self
    }

    /// Set the optional Signature Id.
    #[must_use]
    pub fn signature_id(mut self, id: impl Into<String>) -> Self {
        self.signature_id = Some(id.into());
        self
    }

    /// Append a reference, preserving insertion order.
    #[must_use]
    pub fn add_reference(mut self, reference: ReferenceBuilder) -> Self {
        self.references.push(reference);
        self
    }

    /// Control whether an empty KeyInfo placeholder is emitted.
    #[must_use]
    pub fn key_info(mut self, include: bool) -> Self {
        self.include_key_info = include;
        self
    }

    /// Build a namespace-correct XMLDSig template with empty digest and signature values.
    pub fn build_template(&self) -> Result<String, SignatureBuilderError> {
        self.validate()?;

        let prefix = self.ns_prefix.as_deref();
        let mut writer = Writer::new(Vec::new());
        let signature_name = qualified_name(prefix, "Signature");
        let mut signature = BytesStart::new(&signature_name);
        let namespace_attr = prefix.map_or_else(|| "xmlns".to_owned(), |p| format!("xmlns:{p}"));
        signature.push_attribute((namespace_attr.as_str(), XMLDSIG_NS));
        if let Some(id) = &self.signature_id {
            signature.push_attribute(("Id", id.as_str()));
        }
        writer.write_event(Event::Start(signature))?;

        write_start(&mut writer, prefix, "SignedInfo")?;
        write_algorithm(
            &mut writer,
            prefix,
            "CanonicalizationMethod",
            self.c14n_method.uri(),
        )?;
        write_algorithm(
            &mut writer,
            prefix,
            "SignatureMethod",
            self.sign_method.uri(),
        )?;
        for reference in &self.references {
            write_reference(&mut writer, prefix, reference)?;
        }
        write_end(&mut writer, prefix, "SignedInfo")?;
        write_empty(&mut writer, prefix, "SignatureValue")?;
        if self.include_key_info {
            write_empty(&mut writer, prefix, "KeyInfo")?;
        }
        writer.write_event(Event::End(BytesEnd::new(signature_name)))?;

        Ok(String::from_utf8(writer.into_inner())?)
    }

    fn validate(&self) -> Result<(), SignatureBuilderError> {
        if let Some(prefix) = &self.ns_prefix
            && !is_namespace_prefix(prefix)
        {
            return Err(SignatureBuilderError::InvalidNamespacePrefix(
                prefix.clone(),
            ));
        }
        if let Some(id) = &self.signature_id
            && !is_ncname(id)
        {
            return Err(SignatureBuilderError::InvalidId {
                element: "Signature",
                value: id.clone(),
            });
        }
        if self.references.is_empty() {
            return Err(SignatureBuilderError::MissingReference);
        }
        if !self.sign_method.signing_allowed() {
            return Err(SignatureBuilderError::SigningAlgorithmDisabled(
                self.sign_method.uri(),
            ));
        }
        for reference in &self.references {
            if let Some(id) = &reference.id
                && !is_ncname(id)
            {
                return Err(SignatureBuilderError::InvalidId {
                    element: "Reference",
                    value: id.clone(),
                });
            }
            if !reference.digest_method.signing_allowed() {
                return Err(SignatureBuilderError::SigningAlgorithmDisabled(
                    reference.digest_method.uri(),
                ));
            }
        }
        Ok(())
    }
}

fn write_reference<W: Write>(
    writer: &mut Writer<W>,
    prefix: Option<&str>,
    reference: &ReferenceBuilder,
) -> Result<(), std::io::Error> {
    let name = qualified_name(prefix, "Reference");
    let mut element = BytesStart::new(&name);
    if let Some(id) = &reference.id {
        element.push_attribute(("Id", id.as_str()));
    }
    if let Some(ref_type) = &reference.ref_type {
        element.push_attribute(("Type", ref_type.as_str()));
    }
    if let Some(uri) = &reference.uri {
        element.push_attribute(("URI", uri.as_str()));
    }
    writer.write_event(Event::Start(element))?;

    if !reference.transforms.is_empty() {
        write_start(writer, prefix, "Transforms")?;
        for transform in &reference.transforms {
            write_transform(writer, prefix, transform)?;
        }
        write_end(writer, prefix, "Transforms")?;
    }
    write_algorithm(
        writer,
        prefix,
        "DigestMethod",
        reference.digest_method.uri(),
    )?;
    write_empty(writer, prefix, "DigestValue")?;
    writer.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_transform<W: Write>(
    writer: &mut Writer<W>,
    prefix: Option<&str>,
    transform: &Transform,
) -> Result<(), std::io::Error> {
    match transform {
        Transform::Enveloped => {
            write_algorithm(writer, prefix, "Transform", ENVELOPED_SIGNATURE_URI)
        }
        Transform::XpathExcludeAllSignatures => {
            let name = qualified_name(prefix, "Transform");
            let mut element = BytesStart::new(&name);
            element.push_attribute(("Algorithm", XPATH_TRANSFORM_URI));
            writer.write_event(Event::Start(element))?;
            let xpath_name = qualified_name(prefix, "XPath");
            let mut xpath = BytesStart::new(&xpath_name);
            xpath.push_attribute(("xmlns:dsig", XMLDSIG_NS));
            writer.write_event(Event::Start(xpath))?;
            writer.write_event(Event::Text(BytesText::new(XPATH_EXCLUDE_ALL_SIGNATURES)))?;
            writer.write_event(Event::End(BytesEnd::new(xpath_name)))?;
            writer.write_event(Event::End(BytesEnd::new(name)))?;
            Ok(())
        }
        Transform::C14n(algorithm) if algorithm.inclusive_prefixes().is_empty() => {
            write_algorithm(writer, prefix, "Transform", algorithm.uri())
        }
        Transform::C14n(algorithm) => {
            let name = qualified_name(prefix, "Transform");
            let mut element = BytesStart::new(&name);
            element.push_attribute(("Algorithm", algorithm.uri()));
            writer.write_event(Event::Start(element))?;

            if algorithm.mode() == C14nMode::Exclusive1_0 {
                let mut prefixes: Vec<&str> = algorithm
                    .inclusive_prefixes()
                    .iter()
                    .map(String::as_str)
                    .collect();
                prefixes.sort_unstable();
                let prefix_list = prefixes
                    .into_iter()
                    .map(|p| if p.is_empty() { "#default" } else { p })
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut inclusive = BytesStart::new("ec:InclusiveNamespaces");
                inclusive.push_attribute(("xmlns:ec", EXCLUSIVE_C14N_NS));
                inclusive.push_attribute(("PrefixList", prefix_list.as_str()));
                writer.write_event(Event::Empty(inclusive))?;
            }
            writer.write_event(Event::End(BytesEnd::new(name)))?;
            Ok(())
        }
    }
}

fn write_algorithm<W: Write>(
    writer: &mut Writer<W>,
    prefix: Option<&str>,
    local_name: &str,
    algorithm: &str,
) -> Result<(), std::io::Error> {
    let name = qualified_name(prefix, local_name);
    let mut element = BytesStart::new(name);
    element.push_attribute(("Algorithm", algorithm));
    writer.write_event(Event::Empty(element))?;
    Ok(())
}

fn write_start<W: Write>(
    writer: &mut Writer<W>,
    prefix: Option<&str>,
    local_name: &str,
) -> Result<(), std::io::Error> {
    writer.write_event(Event::Start(BytesStart::new(qualified_name(
        prefix, local_name,
    ))))?;
    Ok(())
}

fn write_end<W: Write>(
    writer: &mut Writer<W>,
    prefix: Option<&str>,
    local_name: &str,
) -> Result<(), std::io::Error> {
    writer.write_event(Event::End(BytesEnd::new(qualified_name(
        prefix, local_name,
    ))))?;
    Ok(())
}

fn write_empty<W: Write>(
    writer: &mut Writer<W>,
    prefix: Option<&str>,
    local_name: &str,
) -> Result<(), std::io::Error> {
    writer.write_event(Event::Empty(BytesStart::new(qualified_name(
        prefix, local_name,
    ))))?;
    Ok(())
}

fn qualified_name(prefix: Option<&str>, local_name: &str) -> String {
    prefix.map_or_else(
        || local_name.to_owned(),
        |prefix| format!("{prefix}:{local_name}"),
    )
}

fn is_ncname(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(':')
        && roxmltree::Document::parse(&format!("<{value}/>")).is_ok()
}

fn is_namespace_prefix(value: &str) -> bool {
    if !is_ncname(value) {
        return false;
    }

    // Parsing delegates the complete Unicode XML Name grammar and reserved-prefix
    // rules to the same parser used by the rest of the crate.
    roxmltree::Document::parse(&format!(
        "<{value}:n xmlns:{value}=\"urn:xml-sec:prefix-validation\"/>"
    ))
    .is_ok()
}
