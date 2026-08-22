//! Builders for deterministic XMLDSig signature templates.

use std::io::Write;

use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};

use crate::c14n::{C14nAlgorithm, C14nMode};
use crate::policy::{PolicyViolation, SigningPolicy};
use crate::xml::{is_xml_1_0_character, is_xml_ncname};

use super::transforms::{
    XPathSignatureParseBudget, validate_xpath_namespace_budget_with_resources,
};
use super::{
    BASE64_TRANSFORM_URI, DigestAlgorithm, ENVELOPED_SIGNATURE_URI, SignatureAlgorithm, Transform,
    XPATH_FILTER2_TRANSFORM_URI, XPATH_TRANSFORM_URI, XPathExpression,
};

const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";
const EXCLUSIVE_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const XPATH_EXCLUDE_ALL_SIGNATURES: &str = "not(ancestor-or-self::dsig:Signature)";

/// Errors produced while validating or serializing an XMLDSig template.
#[derive(Debug, thiserror::Error)]
pub enum SignatureBuilderError {
    /// A namespace prefix was not a supported XML NCName.
    #[error("invalid XML namespace prefix: {0}")]
    InvalidNamespacePrefix(String),
    /// A namespace URI could not be represented in an XML 1.0 declaration.
    #[error("XML namespace URI contains a character forbidden by XML 1.0: {0:?}")]
    InvalidNamespaceUri(String),
    /// An XPath binding would rebind the prefix used by XMLDSig elements.
    #[error("XPath namespace binding conflicts with XMLDSig prefix: {0}")]
    NamespacePrefixConflict(String),
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
    /// The immutable signing policy rejected the template.
    #[error("signing policy violation: {0}")]
    Policy(#[from] PolicyViolation),
    /// An XPath parameter cannot be parsed or exceeds its resource bounds.
    #[error("invalid XPath expression: {0}")]
    InvalidXPath(String),
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
        self.build_template_with_policy(&SigningPolicy::default())
    }

    /// Build a template after enforcing the same immutable policy snapshot used
    /// by the signing operation that will consume it.
    pub fn build_template_with_policy(
        &self,
        policy: &SigningPolicy,
    ) -> Result<String, SignatureBuilderError> {
        policy.validate()?;
        self.validate(policy)?;

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

    fn validate(&self, policy: &SigningPolicy) -> Result<(), SignatureBuilderError> {
        if let Some(prefix) = &self.ns_prefix
            && !is_namespace_prefix(prefix)
        {
            return Err(SignatureBuilderError::InvalidNamespacePrefix(
                prefix.clone(),
            ));
        }
        if let Some(id) = &self.signature_id
            && !is_xml_ncname(id)
        {
            return Err(SignatureBuilderError::InvalidId {
                element: "Signature",
                value: id.clone(),
            });
        }
        if self.references.is_empty() {
            return Err(SignatureBuilderError::MissingReference);
        }
        if self.references.len() > policy.resources.max_references {
            return Err(PolicyViolation::ResourceLimit {
                resource: "signature references",
                maximum: policy.resources.max_references,
                actual: self.references.len(),
            }
            .into());
        }
        let mut xpath_signature_budget =
            XPathSignatureParseBudget::from_resources(&policy.resources);
        for reference in &self.references {
            if !policy
                .uris
                .references
                .allows(reference.uri.as_deref().unwrap_or(""))
            {
                return Err(PolicyViolation::Uri {
                    operation: "signing",
                    reason: "signing reference URI class is not permitted",
                }
                .into());
            }
            if reference.transforms.len() > policy.resources.max_transforms_per_reference {
                return Err(PolicyViolation::ResourceLimit {
                    resource: "reference transforms",
                    maximum: policy.resources.max_transforms_per_reference,
                    actual: reference.transforms.len(),
                }
                .into());
            }
            for transform in &reference.transforms {
                if policy
                    .transforms
                    .allowed_algorithms
                    .as_ref()
                    .is_some_and(|allowed| !allowed.contains(transform.algorithm_uri()))
                {
                    return Err(PolicyViolation::Algorithm {
                        operation: "signing transform",
                        algorithm: transform.algorithm_uri().to_owned(),
                    }
                    .into());
                }
                match transform {
                    Transform::XPath(xpath) => {
                        validate_xpath_source(xpath.expression(), &mut xpath_signature_budget)?;
                    }
                    Transform::XPathFilter2(filters) => {
                        if filters.is_empty() {
                            return Err(SignatureBuilderError::InvalidXPath(
                                "XPath Filter 2.0 requires at least one expression".into(),
                            ));
                        }
                        if filters.len() > policy.resources.max_xpath_filters {
                            return Err(PolicyViolation::ResourceLimit {
                                resource: "XPath Filter 2.0 expressions",
                                maximum: policy.resources.max_xpath_filters,
                                actual: filters.len(),
                            }
                            .into());
                        }
                        for filter in filters {
                            validate_xpath_source(
                                filter.xpath().expression(),
                                &mut xpath_signature_budget,
                            )?;
                        }
                    }
                    _ => {}
                }
            }
            validate_xpath_namespace_budget_with_resources(
                &reference.transforms,
                self.ns_prefix.as_deref().map(|prefix| (prefix, XMLDSIG_NS)),
                &policy.resources,
            )
            .map_err(map_transform_validation_error)?;
        }
        for (prefix, uri, shares_signature_namespace) in
            self.references.iter().flat_map(|reference| {
                reference
                    .transforms
                    .iter()
                    .flat_map(|transform| match transform {
                        Transform::XPath(xpath) => xpath
                            .namespaces()
                            .iter()
                            .map(|(prefix, uri)| (prefix, uri, true))
                            .collect::<Vec<_>>(),
                        Transform::XPathFilter2(filters) => filters
                            .iter()
                            .flat_map(|filter| {
                                filter
                                    .xpath()
                                    .namespaces()
                                    .iter()
                                    .map(|(prefix, uri)| (prefix, uri, false))
                            })
                            .collect(),
                        _ => Vec::new(),
                    })
            })
        {
            // Namespaces in XML reserves the declaration namespace and both
            // sides of the `xml` binding; prefixed declarations cannot be empty.
            if uri.is_empty() || uri == XMLNS_NS || !uri.chars().all(is_xml_1_0_character) {
                return Err(SignatureBuilderError::InvalidNamespaceUri(uri.clone()));
            }
            if prefix == "xmlns"
                || (prefix == "xml") != (uri == XML_NS)
                || (prefix != "xml" && !is_namespace_prefix(prefix))
            {
                return Err(SignatureBuilderError::InvalidNamespacePrefix(
                    prefix.clone(),
                ));
            }
            // Ordinary XPath parameters share the Signature namespace prefix,
            // while Filter2 parameters are unprefixed in their own namespace.
            if shares_signature_namespace
                && self.ns_prefix.as_ref() == Some(prefix)
                && uri != XMLDSIG_NS
            {
                return Err(SignatureBuilderError::NamespacePrefixConflict(
                    prefix.clone(),
                ));
            }
        }
        if !self.sign_method.signing_allowed() {
            return Err(SignatureBuilderError::SigningAlgorithmDisabled(
                self.sign_method.uri(),
            ));
        }
        if policy
            .signature_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&self.sign_method))
        {
            return Err(PolicyViolation::Algorithm {
                operation: "signing",
                algorithm: self.sign_method.uri().to_owned(),
            }
            .into());
        }
        if policy
            .transforms
            .allowed_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(self.c14n_method.uri()))
        {
            return Err(PolicyViolation::Algorithm {
                operation: "signing transform",
                algorithm: self.c14n_method.uri().to_owned(),
            }
            .into());
        }
        for reference in &self.references {
            if let Some(id) = &reference.id
                && !is_xml_ncname(id)
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
            if policy
                .digest_algorithms
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&reference.digest_method))
            {
                return Err(PolicyViolation::Algorithm {
                    operation: "signing",
                    algorithm: reference.digest_method.uri().to_owned(),
                }
                .into());
            }
        }
        Ok(())
    }
}

fn validate_xpath_source(
    source: &str,
    budget: &mut XPathSignatureParseBudget,
) -> Result<(), SignatureBuilderError> {
    if let Some(character) = source
        .chars()
        .find(|character| !is_xml_1_0_character(*character))
    {
        return Err(SignatureBuilderError::InvalidXPath(format!(
            "XPath expression contains a character forbidden by XML 1.0: {character:?}"
        )));
    }
    budget
        .validate_expression(source)
        .map_err(map_transform_validation_error)
}

fn map_transform_validation_error(error: super::TransformError) -> SignatureBuilderError {
    match error {
        super::TransformError::Policy(error) => SignatureBuilderError::Policy(error),
        error => SignatureBuilderError::InvalidXPath(error.to_string()),
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
        Transform::XPath(xpath) => {
            let transform_name = qualified_name(prefix, "Transform");
            let mut transform_element = BytesStart::new(&transform_name);
            transform_element.push_attribute(("Algorithm", XPATH_TRANSFORM_URI));
            writer.write_event(Event::Start(transform_element))?;
            write_xpath_expression(writer, prefix, "XPath", None, xpath)?;
            writer.write_event(Event::End(BytesEnd::new(transform_name)))?;
            Ok(())
        }
        Transform::XPathFilter2(filters) => {
            let transform_name = qualified_name(prefix, "Transform");
            let mut transform_element = BytesStart::new(&transform_name);
            transform_element.push_attribute(("Algorithm", XPATH_FILTER2_TRANSFORM_URI));
            writer.write_event(Event::Start(transform_element))?;
            for filter in filters {
                write_xpath_expression(
                    writer,
                    None,
                    "XPath",
                    Some(filter.operation().as_str()),
                    filter.xpath(),
                )?;
            }
            writer.write_event(Event::End(BytesEnd::new(transform_name)))?;
            Ok(())
        }
        Transform::Base64Decode => {
            write_algorithm(writer, prefix, "Transform", BASE64_TRANSFORM_URI)
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

fn write_xpath_expression<W: Write>(
    writer: &mut Writer<W>,
    prefix: Option<&str>,
    local_name: &str,
    filter: Option<&str>,
    xpath: &XPathExpression,
) -> Result<(), std::io::Error> {
    let name = qualified_name(prefix, local_name);
    let mut element = BytesStart::new(&name);
    let namespace_attributes = xpath
        .namespaces()
        .iter()
        .filter(|(namespace_prefix, _)| namespace_prefix.as_str() != "xml")
        .map(|(namespace_prefix, uri)| (format!("xmlns:{namespace_prefix}"), uri))
        .collect::<Vec<_>>();
    if prefix.is_none() && filter.is_some() {
        element.push_attribute(("xmlns", XPATH_FILTER2_TRANSFORM_URI));
    }
    if let Some(filter) = filter {
        element.push_attribute(("Filter", filter));
    }
    for (attribute, uri) in &namespace_attributes {
        element.push_attribute((attribute.as_str(), uri.as_str()));
    }
    writer.write_event(Event::Start(element))?;
    writer.write_event(Event::Text(BytesText::new(xpath.expression())))?;
    writer.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
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

fn is_namespace_prefix(value: &str) -> bool {
    // Namespaces in XML reserves these names regardless of the URI being bound.
    !matches!(value, "xml" | "xmlns") && is_xml_ncname(value)
}
