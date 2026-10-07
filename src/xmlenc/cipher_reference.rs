//! Source-anchored XMLEnc CipherReference processing.

use std::collections::HashMap;

use crate::xml::dom::Node;
use crate::xmldsig::transforms::{
    TransformExecutionBudget, TransformOptions, XPathSignatureParseBudget,
    execute_reference_transforms_with_budget, parse_reference_transforms_with_budget,
};
use crate::xmldsig::uri::ExternalResourceContext;

use super::types::{XMLENC_NS, XmlEncError};

pub(super) fn parse_reference<'doc, 'input>(
    node: Node<'doc, 'input>,
    resources: &crate::policy::ResourcePolicy,
    budget: &mut XPathSignatureParseBudget,
) -> Result<(&'doc str, Vec<crate::xmldsig::transforms::Transform>), XmlEncError> {
    if !node.has_tag_name((XMLENC_NS, "CipherReference")) {
        return Err(XmlEncError::InvalidStructure(
            "expected xenc:CipherReference".into(),
        ));
    }
    let uri = node
        .attribute("URI")
        .ok_or(XmlEncError::MissingRequired("CipherReference URI"))?;
    if uri.len() > resources.max_encryption_metadata_bytes {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
            maximum: resources.max_encryption_metadata_bytes,
            actual: uri.len(),
        }
        .into());
    }
    let mut container = None;
    for child in node.children() {
        if child.is_comment() || child.is_pi() {
            continue;
        }
        if child.is_text()
            && child.text().is_some_and(|text| {
                text.bytes()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            })
        {
            continue;
        }
        if !child.has_tag_name((XMLENC_NS, "Transforms")) || container.is_some() {
            return Err(XmlEncError::InvalidStructure(
                "CipherReference permits only one xenc:Transforms child".into(),
            ));
        }
        container = Some(child);
    }
    // XMLEnc 1.1 section 3.3.1 changes the container namespace but preserves
    // ds:Transform children and requires at least one when the container exists.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-CipherReference
    let transforms = match container {
        Some(container) => {
            let count = container.children().filter(Node::is_element).count();
            if count > resources.max_transforms_per_reference {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                    maximum: resources.max_transforms_per_reference,
                    actual: count,
                }
                .into());
            }
            if count == 0 {
                return Err(XmlEncError::InvalidStructure(
                    "xenc:Transforms must contain a ds:Transform".into(),
                ));
            }
            parse_reference_transforms_with_budget(container, XMLENC_NS, budget)?
        }
        None => Vec::new(),
    };
    Ok((uri, transforms))
}

/// One operation's source-anchored ciphertext reference processor.
///
/// Resources are supplied by the caller; this processor performs no I/O. All
/// resolutions through this context share external-byte and transform budgets.
pub struct CipherReferenceContext<'a> {
    policy: &'a crate::policy::DecryptionPolicy,
    external: ExternalResourceContext<'a>,
    transforms: TransformExecutionBudget,
    parse: std::cell::RefCell<XPathSignatureParseBudget>,
    id_attributes: &'a [crate::IdAttributeRegistration],
    backend: crate::XmlBackend,
    operation: Option<&'a dyn ReferenceOperationGate>,
}

pub(super) trait ReferenceOperationGate {
    fn run_resource(
        &self,
        identity: &crate::operation::OperationResourceIdentity,
        action: &mut dyn FnMut() -> Result<Vec<u8>, XmlEncError>,
    ) -> Result<Vec<u8>, XmlEncError>;
}

/// One lazily indexed source document, borrowed for this operation only.
pub(super) struct BoundCipherReferenceContext<'context, 'doc> {
    context: &'context CipherReferenceContext<'context>,
    document: &'doc crate::XmlDomDocument<'doc>,
    document_base: Option<&'doc str>,
    resolver: std::cell::OnceCell<crate::xmldsig::uri::UriReferenceResolver<'doc>>,
}

impl<'context: 'doc, 'doc> BoundCipherReferenceContext<'context, 'doc> {
    pub(super) fn resolver(&self) -> &crate::xmldsig::uri::UriReferenceResolver<'doc> {
        self.resolver.get_or_init(|| {
            self.context.external.bind(
                self.document,
                self.context.id_attributes,
                self.context.policy.transforms.same_document_id_semantics,
            )
        })
    }

    pub(super) fn resolve_parsed(
        &self,
        node: Node<'_, '_>,
        uri: &str,
        transforms: &[crate::xmldsig::transforms::Transform],
        xml_parse: &crate::document::XmlParseWorkBudget,
    ) -> Result<Vec<u8>, XmlEncError> {
        self.context.validate_reference_policy(uri, transforms)?;
        if !core::ptr::eq(node.document(), self.document) {
            return Err(XmlEncError::OperationPlan(
                "foreign CipherReference origin".into(),
            ));
        }
        self.context.resolve_with_resolver(
            node,
            uri,
            transforms,
            xml_parse,
            self.resolver(),
            self.document_base,
        )
    }
}

impl<'a> CipherReferenceContext<'a> {
    pub(super) fn preflight_cipher_data(
        &self,
        cipher: &super::CipherData,
    ) -> Result<(), XmlEncError> {
        if self.operation.is_some()
            && let super::CipherData::Reference { uri, transforms } = cipher
        {
            self.validate_reference_policy(uri, transforms)?;
        }
        Ok(())
    }

    pub(super) fn validate_method(
        &self,
        method: &super::EncryptionMethod,
        content: bool,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<(), XmlEncError> {
        // Standalone parsing preserves descriptors even for algorithms the
        // selected provider cannot execute. Runtime parsing preflights work.
        if self.operation.is_none() {
            return Ok(());
        }
        if content {
            method.validate_structure()?;
            let algorithm = super::DataEncryptionAlgorithm::from_uri(&method.algorithm)?;
            crate::policy::check_content_algorithm(
                self.policy.data_algorithms.as_ref(),
                algorithm,
                "decryption",
            )?;
            provider.require_capability(crate::provider::ProviderCapability::Decrypt(algorithm))?;
            Ok(())
        } else {
            super::decrypt::validate_key_encryption_method_policy(method, self.policy)
        }
    }

    pub(super) fn with_operation(mut self, operation: &'a dyn ReferenceOperationGate) -> Self {
        self.operation = Some(operation);
        self
    }
    pub(super) fn backend(&self) -> crate::XmlBackend {
        self.backend
    }
    pub(super) fn resolve_key_reference(
        &self,
        node: Node<'_, '_>,
        uri: &str,
        transforms: &[crate::xmldsig::transforms::Transform],
        document_base: Option<&str>,
        xml_parse: &crate::document::XmlParseWorkBudget,
    ) -> Result<(Vec<u8>, Option<String>), XmlEncError> {
        if !self.policy.uris.retrieval_methods.allows(uri) {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "encryption key retrieval URI",
                algorithm: uri.into(),
            }
            .into());
        }
        let external = !uri.is_empty() && !uri.starts_with('#');
        crate::xmldsig::transforms::validate_signing_transform_policy(
            external,
            transforms,
            self.policy.transforms.allowed_algorithms.as_ref(),
        )?;
        let resolved = if external {
            Some(
                crate::c14n::xml_base::resolve_uri_from_node_with_document_base_with_budget(
                    node,
                    uri,
                    document_base,
                    self.transforms.xml_base_resolution(),
                )
                .map_err(|error| {
                    XmlEncError::InvalidStructure(format!("key retrieval XML Base: {error}"))
                })?,
            )
        } else {
            document_base.map(str::to_owned)
        };
        let resolver = self.external.bind(
            node.document(),
            self.id_attributes,
            self.policy.transforms.same_document_id_semantics,
        );
        // XMLDSig 1.1 section 4.5.3 applies transforms in the RetrievalMethod's
        // original context, before interpreting the resulting key XML.
        // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-RetrievalMethod
        let bytes = self.execute_resolved_reference(
            node,
            if external {
                resolved.as_deref().expect("external URI resolved")
            } else {
                uri
            },
            transforms,
            xml_parse,
            &resolver,
        )?;
        Ok((bytes, resolved))
    }

    pub(super) fn bind_document<'doc>(
        &'doc self,
        document: &'doc crate::XmlDomDocument<'doc>,
    ) -> BoundCipherReferenceContext<'doc, 'doc> {
        BoundCipherReferenceContext {
            context: self,
            document,
            document_base: None,
            resolver: std::cell::OnceCell::new(),
        }
    }

    pub(super) fn bind_document_with_base<'doc>(
        &'doc self,
        document: &'doc crate::XmlDomDocument<'doc>,
        document_base: Option<&'doc str>,
    ) -> BoundCipherReferenceContext<'doc, 'doc> {
        let mut bound = self.bind_document(document);
        bound.document_base = document_base;
        bound
    }
    /// Bind caller-owned resources and the operation's immutable policy.
    pub fn new(
        policy: &'a crate::policy::DecryptionPolicy,
        resources: Option<&'a HashMap<String, Vec<u8>>>,
        backend: crate::XmlBackend,
        id_attributes: &'a [crate::IdAttributeRegistration],
    ) -> Result<Self, XmlEncError> {
        policy.validate()?;
        Ok(Self {
            policy,
            external: ExternalResourceContext::new(
                resources,
                policy.resources.max_external_resource_bytes,
                policy.resources.max_external_resource_total_bytes,
            ),
            transforms: TransformExecutionBudget::from_resources(&policy.resources)
                .with_xml_backend(backend),
            parse: std::cell::RefCell::new(XPathSignatureParseBudget::from_resources(
                &policy.resources,
            )),
            id_attributes,
            backend,
            operation: None,
        })
    }

    /// Resolve an original `xenc:CipherReference` without serializing its
    /// subtree or discarding inherited namespaces, XML Base, or XPath `here()`.
    pub fn resolve(&self, node: Node<'_, '_>) -> Result<Vec<u8>, XmlEncError> {
        // A public Node does not attest which parser policy produced it. Apply
        // the operation policy to its source before processing the original
        // node; XPath provenance must not be replaced by the validation parse.
        let settings = crate::document::DocumentParseSettings::from_policy(
            &self.policy.xml,
            &self.policy.resources,
        )
        .with_backend(self.backend);
        crate::document::parse_borrowed_with_settings_and_budget(
            node.document().input_text(),
            settings,
            Some(self.transforms.xml_parse_work()),
        )
        .map_err(|error| super::map_document_error(error, settings))?;
        self.resolve_validated(node, self.transforms.xml_parse_work())
    }

    pub(super) fn resolve_validated(
        &self,
        node: Node<'_, '_>,
        xml_parse: &crate::document::XmlParseWorkBudget,
    ) -> Result<Vec<u8>, XmlEncError> {
        let (uri, transforms) =
            parse_reference(node, &self.policy.resources, &mut self.parse.borrow_mut())?;
        self.resolve_parsed(node, uri, &transforms, xml_parse)
    }

    pub(super) fn resolve_parsed(
        &self,
        node: Node<'_, '_>,
        uri: &str,
        transforms: &[crate::xmldsig::transforms::Transform],
        xml_parse: &crate::document::XmlParseWorkBudget,
    ) -> Result<Vec<u8>, XmlEncError> {
        self.bind_document(node.document())
            .resolve_parsed(node, uri, transforms, xml_parse)
    }

    pub(super) fn validate_reference_policy(
        &self,
        uri: &str,
        transforms: &[crate::xmldsig::transforms::Transform],
    ) -> Result<(), XmlEncError> {
        crate::xmldsig::transforms::validate_relationship_chain(
            transforms,
            self.policy.transforms.opc_relationship_edition,
        )?;
        if !self.policy.uris.references.allows(uri) {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "cipher reference URI",
                algorithm: uri.to_owned(),
            }
            .into());
        }
        let initial_binary = !uri.is_empty() && !uri.starts_with('#');
        crate::xmldsig::transforms::validate_signing_transform_policy(
            initial_binary,
            transforms,
            self.policy.transforms.allowed_algorithms.as_ref(),
        )?;
        Ok(())
    }

    fn resolve_with_resolver(
        &self,
        node: Node<'_, '_>,
        uri: &str,
        transforms: &[crate::xmldsig::transforms::Transform],
        xml_parse: &crate::document::XmlParseWorkBudget,
        resolver: &crate::xmldsig::uri::UriReferenceResolver<'_>,
        document_base: Option<&str>,
    ) -> Result<Vec<u8>, XmlEncError> {
        if uri.is_empty() || uri.starts_with('#') {
            self.execute_resolved_reference(node, uri, transforms, xml_parse, resolver)
        } else {
            let resolved =
                crate::c14n::xml_base::resolve_uri_from_node_with_document_base_with_budget(
                    node,
                    uri,
                    document_base,
                    self.transforms.xml_base_resolution(),
                )
                .map_err(|error| {
                    XmlEncError::InvalidStructure(format!("cipher reference XML Base: {error}"))
                })?;
            self.execute_resolved_reference(node, &resolved, transforms, xml_parse, resolver)
        }
    }

    fn execute_resolved_reference(
        &self,
        node: Node<'_, '_>,
        uri: &str,
        transforms: &[crate::xmldsig::transforms::Transform],
        xml_parse: &crate::document::XmlParseWorkBudget,
        resolver: &crate::xmldsig::uri::UriReferenceResolver<'_>,
    ) -> Result<Vec<u8>, XmlEncError> {
        use crate::operation::OperationResourceIdentity;
        // Reserve selected external bytes before hashing or copying them. The
        // immutable caller map keeps this identity stable through execution.
        let external = if !uri.is_empty() && !uri.starts_with('#') {
            Some(
                resolver
                    .external_resource(uri)?
                    .ok_or_else(|| crate::xmldsig::TransformError::UnsupportedUri(uri.into()))?,
            )
        } else {
            None
        };
        let mut action = || {
            let input = match external {
                Some(bytes) => crate::xmldsig::TransformData::Binary(bytes.to_vec()),
                None => resolver
                    .dereference_with_budget(uri, self.transforms.node_set_materialization())?,
            };
            execute_reference_transforms_with_budget(
                node,
                // XMLDSig 1.1 section 6.6.4 identifies the Signature which
                // contains this transform, not a presumed XMLEnc-only root.
                // An encrypted Object can itself be inside a Signature.
                // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-EnvelopedSignature
                node.ancestors().find(|ancestor| {
                    ancestor.has_tag_name((super::types::XMLDSIG_NS, "Signature"))
                }),
                input,
                transforms,
                TransformOptions::default()
                    .xpath_here_semantics(self.policy.transforms.xpath_here_semantics)
                    .opc_relationship_edition(self.policy.transforms.opc_relationship_edition)
                    .allow_internal_dtd(self.policy.xml.allow_internal_dtd),
                &self.transforms,
                xml_parse,
            )
            .map_err(XmlEncError::from)
        };
        match self.operation {
            Some(operation) => {
                let identity = match external {
                    Some(bytes) => OperationResourceIdentity::external(uri, bytes),
                    None => OperationResourceIdentity::BorrowedDocumentNode {
                        document: node.document() as *const _ as usize,
                        node: node.id(),
                    },
                };
                operation.run_resource(&identity, &mut action)
            }
            None => action(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::dom::Document;
    use crate::xmldsig::UriTypeSet;

    const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
    const BASE64: &str = "http://www.w3.org/2000/09/xmldsig#base64";

    #[test]
    fn bound_references_share_one_index_and_reject_foreign_origins() {
        // Repeated ciphertext references must not rebuild a document-sized
        // index. Equal lexical XML in another document is not this origin.
        let xml = format!("<root>{}</root>", reference("urn:cipher", ""));
        let document = Document::parse(&xml).expect("source XML");
        let foreign = Document::parse(&xml).expect("independent XML");
        let resources = HashMap::from([("urn:cipher".into(), b"ciphertext".to_vec())]);
        let policy = crate::policy::DecryptionPolicy {
            uris: crate::policy::UriPolicy {
                references: UriTypeSet::ALL,
                ..Default::default()
            },
            ..Default::default()
        };
        let context = CipherReferenceContext::new(
            &policy,
            Some(&resources),
            crate::XmlBackend::default(),
            &[],
        )
        .expect("reference context");
        let bound = context.bind_document(&document);
        assert!(bound.resolver.get().is_none());
        let node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "CipherReference")))
            .expect("source reference");
        assert_eq!(
            bound
                .resolve_parsed(node, "urn:cipher", &[], context.transforms.xml_parse_work())
                .expect("first resolution"),
            b"ciphertext"
        );
        let index = bound.resolver.get().expect("initialized index") as *const _;
        assert_eq!(
            bound
                .resolve_parsed(node, "urn:cipher", &[], context.transforms.xml_parse_work())
                .expect("second resolution"),
            b"ciphertext"
        );
        assert_eq!(
            bound.resolver.get().expect("retained index") as *const _,
            index
        );
        let foreign_node = foreign
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "CipherReference")))
            .expect("foreign reference");
        assert!(matches!(
            bound.resolve_parsed(
                foreign_node,
                "urn:cipher",
                &[],
                context.transforms.xml_parse_work()
            ),
            Err(XmlEncError::OperationPlan(_))
        ));
    }

    fn reference(uri: &str, children: &str) -> String {
        format!(
            "<CipherReference xmlns='{XMLENC_NS}' xmlns:ds='{DS}' URI='{uri}'>{children}</CipherReference>"
        )
    }

    #[test]
    fn external_ciphertext_is_raw_not_implicitly_base64_decoded() {
        // CipherReference without transforms already yields ciphertext octets;
        // an inline CipherValue's base64 conversion must not be inherited.
        let xml = reference("urn:cipher", "");
        let document = Document::parse(&xml).expect("reference XML");
        let resources = HashMap::from([("urn:cipher".into(), b"YWJj".to_vec())]);
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.uris.references = UriTypeSet::ALL;
        let context = CipherReferenceContext::new(
            &policy,
            Some(&resources),
            crate::XmlBackend::default(),
            &[],
        )
        .expect("context");
        assert_eq!(
            context
                .resolve(document.root_element())
                .expect("ciphertext"),
            b"YWJj"
        );
    }

    #[test]
    fn encryption_transform_container_uses_signature_transform_children() {
        // Section 3.3.1 intentionally changes only the container namespace.
        let xml = reference(
            "urn:cipher",
            &format!("<Transforms><ds:Transform Algorithm='{BASE64}'/></Transforms>"),
        );
        let document = Document::parse(&xml).expect("reference XML");
        let resources = HashMap::from([("urn:cipher".into(), b"YWJj".to_vec())]);
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.uris.references = UriTypeSet::ALL;
        let context = CipherReferenceContext::new(
            &policy,
            Some(&resources),
            crate::XmlBackend::default(),
            &[],
        )
        .expect("context");
        assert_eq!(
            context
                .resolve(document.root_element())
                .expect("ciphertext"),
            b"abc"
        );
    }

    #[test]
    fn malformed_reference_does_not_spend_external_budget() {
        // Syntax rejection precedes resource resolution, leaving the sole
        // permitted read available for the subsequent valid reference.
        let resources = HashMap::from([("urn:cipher".into(), b"abc".to_vec())]);
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.uris.references = UriTypeSet::ALL;
        policy.resources.max_external_resource_total_bytes = 3;
        let context = CipherReferenceContext::new(
            &policy,
            Some(&resources),
            crate::XmlBackend::default(),
            &[],
        )
        .expect("context");
        for children in [
            "<ds:Transforms/>",
            "<Transforms/>",
            "<Transforms/><Transforms/>",
            "non-whitespace",
            "<foreign/>",
        ] {
            let xml = reference("urn:cipher", children);
            let document = Document::parse(&xml).expect("reference XML");
            assert!(
                context.resolve(document.root_element()).is_err(),
                "{children}"
            );
        }
        let xml = reference("urn:cipher", "");
        let document = Document::parse(&xml).expect("reference XML");
        assert_eq!(
            context
                .resolve(document.root_element())
                .expect("remaining read"),
            b"abc"
        );
        assert!(context.resolve(document.root_element()).is_err());
    }

    #[test]
    fn inherited_xml_base_resolves_caller_owned_resource() {
        // Moving the CipherReference into a synthetic fragment would lose the
        // ancestor base and select a different resource identity.
        let xml = format!(
            "<root xml:base='https://example.invalid/a/'><CipherReference xmlns='{XMLENC_NS}' URI='../cipher'/></root>"
        );
        let document = Document::parse(&xml).expect("reference XML");
        let node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "CipherReference")))
            .expect("reference");
        let resources = HashMap::from([("https://example.invalid/cipher".into(), vec![1, 2, 3])]);
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.uris.references = UriTypeSet::ALL;
        let context = CipherReferenceContext::new(
            &policy,
            Some(&resources),
            crate::XmlBackend::default(),
            &[],
        )
        .expect("context");
        assert_eq!(context.resolve(node).expect("ciphertext"), [1, 2, 3]);
    }

    #[test]
    fn same_document_base64_preserves_original_node_context() {
        // Same-document dereference must retain the actual text nodes, not
        // canonicalize and then decode XML markup as if it were base64.
        let xml = format!(
            "<root><data xml:id='cipher'>YWJj</data>{}</root>",
            reference(
                "#cipher",
                &format!("<Transforms><ds:Transform Algorithm='{BASE64}'/></Transforms>")
            )
        );
        let document = Document::parse(&xml).expect("reference XML");
        let node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "CipherReference")))
            .expect("reference");
        let policy = crate::policy::DecryptionPolicy::default();
        let context = CipherReferenceContext::new(&policy, None, crate::XmlBackend::default(), &[])
            .expect("context");
        assert_eq!(context.resolve(node).expect("ciphertext"), b"abc");
    }

    #[test]
    fn transforms_reject_character_data_before_resource_resolution() {
        // TransformsType is element-only. Treating arbitrary character data as
        // trivia would accept a malformed reference and still read its source.
        let xml = reference(
            "urn:cipher",
            &format!("<Transforms>invalid<ds:Transform Algorithm='{BASE64}'/></Transforms>"),
        );
        let document = Document::parse(&xml).expect("reference XML");
        let resources = HashMap::from([("urn:cipher".into(), b"YWJj".to_vec())]);
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.uris.references = UriTypeSet::ALL;
        let context = CipherReferenceContext::new(
            &policy,
            Some(&resources),
            crate::XmlBackend::default(),
            &[],
        )
        .expect("context");
        assert!(context.resolve(document.root_element()).is_err());
    }
}
