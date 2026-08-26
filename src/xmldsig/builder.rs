//! Builders for deterministic XMLDSig signature templates.

use std::{collections::HashSet, io::Write};

use base64::Engine;
use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};

use crate::c14n::{C14nAlgorithm, C14nMode, canonicalize_bounded_with_xml_base_budget};
use crate::policy::{PolicyViolation, SigningPolicy};
use crate::xml::{is_xml_1_0_character, is_xml_ncname};

use super::mutation::{
    fill_signature_value_with_budget, fill_signed_info_digest_values_with_budget,
    padded_base64_len_for_xml, projected_signature_value_output_len_at_index_with_budget,
    zero_base64_placeholder,
};
use super::transforms::{
    ENVELOPED_SIGNATURE_XPATH_EXPR, ENVELOPED_SIGNATURE_XPATH_PREFIX, TransformExecutionBudget,
    XPathSignatureParseBudget, map_c14n_resource_policy_violation,
    validate_signing_transform_policy, validate_xpath_namespace_budget_with_resources,
};
use super::uri::validate_signing_reference_uri;
use super::{
    BASE64_TRANSFORM_URI, DigestAlgorithm, ENVELOPED_SIGNATURE_URI, SignatureAlgorithm, Transform,
    XPATH_FILTER2_TRANSFORM_URI, XPATH_TRANSFORM_URI, XPathExpression,
};

const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";
const EXCLUSIVE_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

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
    /// The generated template could not be parsed under the selected policy.
    #[error("generated XML template is invalid: {0}")]
    GeneratedXml(#[from] roxmltree::Error),
    /// The generated SignedInfo could not be canonicalized.
    #[error("generated SignedInfo canonicalization failed: {0}")]
    Canonicalization(#[from] crate::c14n::C14nError),
    /// The generated template did not contain its required SignedInfo child.
    #[error("generated XML template is missing SignedInfo")]
    MissingGeneratedSignedInfo,
    /// The generated template could not be prepared for policy validation.
    #[error("generated XML template validation failed: {0}")]
    GeneratedMutation(#[source] super::mutation::XmlMutationError),
}

/// Builder for a single XMLDSig `<Reference>` template.
#[derive(Debug, Clone)]
pub struct ReferenceBuilder {
    uri: String,
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
            uri: String::new(),
            id: None,
            ref_type: None,
            transforms: Vec::new(),
            digest_method,
        }
    }

    /// Set the reference URI.
    ///
    /// References default to the empty same-document URI because the signing
    /// pipeline requires an explicit `URI` attribute.
    #[must_use]
    pub fn uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = uri.into();
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
    /// by the signing operation that will consume it. This key-independent
    /// method validates generated digest widths; `SignContext::sign_with_builder`
    /// additionally validates the exact key-dependent `SignatureValue` width.
    pub fn build_template_with_policy(
        &self,
        policy: &SigningPolicy,
    ) -> Result<String, SignatureBuilderError> {
        let budget = TransformExecutionBudget::from_resources(&policy.resources);
        let mut xpath_parse_budget = XPathSignatureParseBudget::from_resources(&policy.resources);
        self.build_template_with_policy_and_signature_output_len(
            policy,
            None,
            &budget,
            &mut xpath_parse_budget,
        )
    }

    pub(super) fn build_template_with_policy_for_signature_output(
        &self,
        policy: &SigningPolicy,
        signature_output_len: usize,
        budget: &TransformExecutionBudget,
        xpath_parse_budget: &mut XPathSignatureParseBudget,
    ) -> Result<String, SignatureBuilderError> {
        self.build_template_with_policy_and_signature_output_len(
            policy,
            Some(signature_output_len),
            budget,
            xpath_parse_budget,
        )
    }

    fn build_template_with_policy_and_signature_output_len(
        &self,
        policy: &SigningPolicy,
        signature_output_len: Option<usize>,
        budget: &TransformExecutionBudget,
        xpath_parse_budget: &mut XPathSignatureParseBudget,
    ) -> Result<String, SignatureBuilderError> {
        policy.validate()?;
        self.validate(policy, xpath_parse_budget)?;

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

        let template = String::from_utf8(writer.into_inner())?;
        // Field-level checks bound each input class; these checks cover the
        // completed artifact exactly as the signing operation will consume it.
        policy.resources.validate_xml_document_len(template.len())?;
        let digest_placeholders = self.references.iter().map(|reference| {
            base64::engine::general_purpose::STANDARD.encode(vec![
                0_u8;
                reference
                    .digest_method
                    .output_len()
            ])
        });
        let digest_validation_template = fill_signed_info_digest_values_with_budget(
            &template,
            digest_placeholders,
            Some(policy),
            Some(budget.xml_parse_work()),
        )
        .map_err(map_generated_mutation_error)?;
        let validation_template = if let Some(signature_output_len) = signature_output_len {
            let encoded_signature_len = padded_base64_len_for_xml(signature_output_len, policy)
                .map_err(map_generated_mutation_error)?;
            let projected_document_len = projected_signature_value_output_len_at_index_with_budget(
                &digest_validation_template,
                encoded_signature_len,
                0,
                Some(policy),
                Some(budget.xml_parse_work()),
            )
            .map_err(map_generated_mutation_error)?;
            policy
                .resources
                .validate_xml_document_len(projected_document_len)?;
            let signature_placeholder =
                zero_base64_placeholder(signature_output_len, encoded_signature_len);
            fill_signature_value_with_budget(
                &digest_validation_template,
                &signature_placeholder,
                Some(policy),
                Some(budget.xml_parse_work()),
            )
            .map_err(map_generated_mutation_error)?
        } else {
            digest_validation_template
        };
        policy
            .resources
            .validate_xml_document_len(validation_template.len())?;
        let settings =
            crate::document::DocumentParseSettings::from_policy(&policy.xml, &policy.resources);
        let document = super::mutation::parse_with_options_and_budget(
            &validation_template,
            Some(policy),
            Some(budget.xml_parse_work()),
        )
        .map_err(|error| match error.into_policy_violation(settings) {
            Ok(error) => SignatureBuilderError::Policy(error),
            Err(crate::document::XmlDocumentError::Parse(error)) => {
                SignatureBuilderError::GeneratedXml(error)
            }
            Err(error) => SignatureBuilderError::GeneratedMutation(
                super::mutation::XmlMutationError::Document(error),
            ),
        })?;
        let signed_info = document
            .root_element()
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
            .ok_or(SignatureBuilderError::MissingGeneratedSignedInfo)?;
        let signed_info_subtree: HashSet<_> =
            signed_info.descendants().map(|node| node.id()).collect();
        let mut canonical_signed_info = Vec::new();
        canonicalize_bounded_with_xml_base_budget(
            &document,
            Some(&|node| signed_info_subtree.contains(&node.id())),
            &self.c14n_method,
            budget.remaining_c14n_output(),
            budget.xml_base_resolution(),
            &mut canonical_signed_info,
        )
        .map_err(|error| {
            map_c14n_resource_policy_violation(
                &error,
                crate::policy::resource_name::CANONICALIZED_BYTES,
                budget.c14n_output_limit(),
            )
            .map_or_else(
                || SignatureBuilderError::Canonicalization(error),
                SignatureBuilderError::Policy,
            )
        })?;
        budget.charge_c14n_output_policy(canonical_signed_info.len())?;
        Ok(template)
    }

    pub(super) fn signature_method(&self) -> SignatureAlgorithm {
        self.sign_method
    }

    fn validate(
        &self,
        policy: &SigningPolicy,
        xpath_signature_budget: &mut XPathSignatureParseBudget,
    ) -> Result<(), SignatureBuilderError> {
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
                resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
                maximum: policy.resources.max_references,
                actual: self.references.len(),
            }
            .into());
        }
        for reference in &self.references {
            validate_signing_reference_uri(&reference.uri, policy)?;
            if reference.transforms.len() > policy.resources.max_transforms_per_reference {
                return Err(PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                    maximum: policy.resources.max_transforms_per_reference,
                    actual: reference.transforms.len(),
                }
                .into());
            }
            let initial_binary = !reference.uri.is_empty() && !reference.uri.starts_with('#');
            validate_signing_transform_policy(
                initial_binary,
                &reference.transforms,
                policy.transforms.allowed_algorithms.as_ref(),
            )?;
            for transform in &reference.transforms {
                match transform {
                    Transform::XpathExcludeAllSignatures => {
                        validate_xpath_source(
                            ENVELOPED_SIGNATURE_XPATH_EXPR,
                            xpath_signature_budget,
                        )?;
                    }
                    Transform::XPath(xpath) => {
                        validate_xpath_source(xpath.expression(), xpath_signature_budget)?;
                    }
                    Transform::XPathFilter2(filters) => {
                        if filters.is_empty() {
                            return Err(SignatureBuilderError::InvalidXPath(
                                "XPath Filter 2.0 requires at least one expression".into(),
                            ));
                        }
                        if filters.len() > policy.resources.max_xpath_filters {
                            return Err(PolicyViolation::ResourceLimit {
                                resource: crate::policy::resource_name::XPATH_FILTERS,
                                maximum: policy.resources.max_xpath_filters,
                                actual: filters.len(),
                            }
                            .into());
                        }
                        for filter in filters {
                            validate_xpath_source(
                                filter.xpath().expression(),
                                xpath_signature_budget,
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

fn map_generated_mutation_error(error: super::mutation::XmlMutationError) -> SignatureBuilderError {
    match error {
        super::mutation::XmlMutationError::Policy(violation) => {
            SignatureBuilderError::Policy(violation)
        }
        other => SignatureBuilderError::GeneratedMutation(other),
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
    element.push_attribute(("URI", reference.uri.as_str()));
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
            let namespace = format!("xmlns:{ENVELOPED_SIGNATURE_XPATH_PREFIX}");
            xpath.push_attribute((namespace.as_str(), XMLDSIG_NS));
            writer.write_event(Event::Start(xpath))?;
            writer.write_event(Event::Text(BytesText::new(ENVELOPED_SIGNATURE_XPATH_EXPR)))?;
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
