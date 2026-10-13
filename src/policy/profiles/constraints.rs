use super::*;
use crate::xml::dom::Node;

impl PolicySet {
    pub(super) fn validate(
        &self,
        context: &PolicyCompileContext<'_>,
    ) -> Result<(), PolicyViolation> {
        if let Some(policy) = &self.verification {
            policy.validate()?;
            signature_methods(
                policy.signature_algorithms.as_ref(),
                policy.hmac,
                context.provider,
                false,
                |algorithm| policy.check_signature_algorithm(algorithm),
            )?;
            digest_methods(policy.digest_algorithms.as_ref(), context.provider)?;
            uri_contract(policy.uris, context)?;
            if policy.signature_constraints != SignatureConstraints::General
                && !context.target_evidence
            {
                return Err(configuration(
                    "signature profile requires explicit expected targets through verify_request",
                ));
            }
        }
        if let Some(policy) = &self.signing {
            policy.validate()?;
            signature_methods(
                policy.signature_algorithms.as_ref(),
                policy.hmac,
                context.provider,
                true,
                |algorithm| policy.check_signature_algorithm(algorithm),
            )?;
            digest_methods(policy.digest_algorithms.as_ref(), context.provider)?;
            uri_contract(policy.uris, context)?;
        }
        #[cfg(feature = "xmlenc")]
        {
            if let Some(policy) = &self.encryption {
                policy.validate()?;
                cipher_methods(
                    policy.data_algorithms.as_ref(),
                    policy.key_wrap_algorithms.as_ref(),
                    context.provider,
                    true,
                )?;
                transport_methods(
                    policy.key_transport_algorithms.as_ref(),
                    policy.oaep_digests.as_ref(),
                    context.provider,
                    true,
                )?;
            }
            if let Some(policy) = &self.decryption {
                policy.validate()?;
                cipher_methods(
                    policy.data_algorithms.as_ref(),
                    policy.key_wrap_algorithms.as_ref(),
                    context.provider,
                    false,
                )?;
                transport_methods(
                    policy.key_transport_algorithms.as_ref(),
                    policy.oaep_digests.as_ref(),
                    context.provider,
                    false,
                )?;
                uri_contract(policy.uris, context)?;
            }
        }
        Ok(())
    }
}

fn signature_methods(
    methods: Option<&HashSet<SignatureAlgorithm>>,
    hmac: HmacPolicy,
    provider: &dyn CryptoProvider,
    signing: bool,
    check: impl Fn(SignatureAlgorithm) -> Result<(), PolicyViolation>,
) -> Result<(), PolicyViolation> {
    if let Some(methods) = methods {
        if methods.is_empty() {
            return Err(configuration(
                "enabled signature operation has no permitted signature method",
            ));
        }
        for &algorithm in methods {
            check(algorithm)?;
            if signing && !algorithm.signing_allowed() {
                return Err(configuration("verify-only algorithm enabled for signing"));
            }
            if algorithm
                .hmac_output_bits()
                .is_some_and(|bits| hmac.minimum_output_bits > bits)
            {
                return Err(configuration(
                    "HMAC output minimum exceeds permitted digest width",
                ));
            }
            let capability = if signing {
                ProviderCapability::Sign(algorithm)
            } else {
                ProviderCapability::Verify(algorithm)
            };
            if !provider.supports(capability) {
                return Err(configuration(
                    "selected provider does not support a permitted signature method",
                ));
            }
        }
    }
    Ok(())
}

fn digest_methods(
    methods: Option<&HashSet<DigestAlgorithm>>,
    provider: &dyn CryptoProvider,
) -> Result<(), PolicyViolation> {
    if let Some(methods) = methods {
        if methods.is_empty() {
            return Err(configuration(
                "enabled signature operation has no permitted digest method",
            ));
        }
        for &algorithm in methods {
            if !provider.supports(ProviderCapability::Digest(algorithm)) {
                return Err(configuration(
                    "selected provider does not support a permitted digest method",
                ));
            }
        }
    }
    Ok(())
}

fn uri_contract(
    uris: UriPolicy,
    context: &PolicyCompileContext<'_>,
) -> Result<(), PolicyViolation> {
    if !context.external_resources
        && [
            uris.references,
            uris.retrieval_methods,
            uris.key_info_references,
        ]
        .into_iter()
        .any(|set| set.allows("external"))
    {
        return Err(configuration(
            "external URI permission requires caller-provided resource contract",
        ));
    }
    Ok(())
}

#[cfg(feature = "xmlenc")]
fn cipher_methods(
    data: Option<&HashSet<DataEncryptionAlgorithm>>,
    wraps: Option<&HashSet<KeyWrapAlgorithm>>,
    provider: &dyn CryptoProvider,
    encrypt: bool,
) -> Result<(), PolicyViolation> {
    if let Some(data) = data {
        if data.is_empty() {
            return Err(configuration(
                "enabled encryption operation has no permitted cipher",
            ));
        }
        for &algorithm in data {
            let capability = if encrypt {
                ProviderCapability::Encrypt(algorithm)
            } else {
                ProviderCapability::Decrypt(algorithm)
            };
            if !provider.supports(capability) {
                return Err(configuration(
                    "selected provider does not support a permitted cipher",
                ));
            }
        }
    }
    if let Some(wraps) = wraps {
        for &algorithm in wraps {
            let capability = if encrypt {
                ProviderCapability::KeyWrap(algorithm)
            } else {
                ProviderCapability::KeyUnwrap(algorithm)
            };
            if !provider.supports(capability) {
                return Err(configuration(
                    "selected provider does not support a permitted key-wrap method",
                ));
            }
        }
    }
    Ok(())
}

impl SignatureConstraints {
    pub(crate) fn require_targets(self, present: bool) -> Result<(), PolicyViolation> {
        if self != Self::General && !present {
            return Err(configuration(
                "signature profile requires nonempty expected targets through verify_request",
            ));
        }
        Ok(())
    }

    /// Borrowed direct-child inspection, before resolver or provider callbacks.
    /// Protocol validators still own replay, audience, time and application semantics.
    pub(crate) fn check(
        self,
        signature: Node<'_, '_>,
        budget: &crate::xmldsig::transforms::TransformExecutionBudget,
    ) -> Result<(), PolicyViolation> {
        if self != Self::General {
            // All inspections below use direct-child loops, at most eight
            // passes over disjoint portions of the retained document. Reserve
            // that conservative bound in O(1), before any traversal.
            budget
                .charge_node_filter_work(signature.document().node_count() * 8)
                .map_err(|error| match error {
                    crate::xmldsig::TransformError::Policy(error) => error,
                    _ => configuration("signature profile inspection budget failed"),
                })?;
        }
        match self {
            Self::General => Ok(()),
            Self::Saml => saml(signature),
            Self::WsSecurity => ws_security(signature),
            Self::Xades => xades(signature),
        }
        .map_err(|error| match error {
            PolicyViolation::Configuration { reason } => PolicyViolation::SignatureProfile {
                profile: self,
                reason,
            },
            error => error,
        })
    }
}

#[cfg(feature = "xmlenc")]
fn transport_methods(
    methods: Option<&HashSet<KeyTransportAlgorithm>>,
    digests: Option<&HashSet<OaepDigestAlgorithm>>,
    provider: &dyn CryptoProvider,
    encrypt: bool,
) -> Result<(), PolicyViolation> {
    let Some(methods) = methods else {
        return Ok(());
    };
    for &algorithm in methods {
        #[cfg(feature = "legacy-algorithms")]
        if algorithm == KeyTransportAlgorithm::RsaPkcs1v15 {
            let capability = if encrypt {
                ProviderCapability::Pkcs1v15Transport
            } else {
                ProviderCapability::Pkcs1v15Recovery
            };
            if !provider.supports(capability) {
                return Err(configuration(
                    "selected provider does not support a permitted key-transport method",
                ));
            }
            continue;
        }
        // Both DigestMethod and MGF must satisfy the same compiled allowlist.
        // Only five wire MGF identifiers exist: XMLEnc 1.1 §5.5.2.
        // https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP
        let mut permitted_tuple = false;
        for digest in DigestAlgorithm::ALL
            .into_iter()
            .filter_map(|value| OaepDigestAlgorithm::from_uri(value.uri()))
        {
            if !digests.map_or(!digest.requires_explicit_permission(), |set| {
                set.contains(&digest)
            }) {
                continue;
            }
            for mgf in [
                OaepDigestAlgorithm::Sha1,
                OaepDigestAlgorithm::Sha224,
                OaepDigestAlgorithm::Sha256,
                OaepDigestAlgorithm::Sha384,
                OaepDigestAlgorithm::Sha512,
            ] {
                if digests.is_some_and(|set| !set.contains(&mgf)) {
                    continue;
                }
                permitted_tuple = true;
                let parameters = crate::xmlenc::RsaOaepParameters {
                    algorithm,
                    digest,
                    mgf_digest: mgf,
                    label: Vec::new(),
                };
                let capability = if encrypt {
                    ProviderCapability::KeyTransport(&parameters)
                } else {
                    ProviderCapability::KeyRecovery(&parameters)
                };
                if !provider.supports(capability) {
                    return Err(configuration(
                        "selected provider does not support a permitted RSA-OAEP tuple",
                    ));
                }
            }
        }
        if !permitted_tuple {
            return Err(configuration(
                "permitted RSA-OAEP method has no usable digest/MGF tuple",
            ));
        }
    }
    Ok(())
}

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
fn named(node: Node<'_, '_>, namespace: &str, local: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == local
}
fn child<'a>(node: Node<'a, 'a>, namespace: &str, local: &str) -> Option<Node<'a, 'a>> {
    node.children().find(|node| named(*node, namespace, local))
}

fn saml(signature: Node<'_, '_>) -> Result<(), PolicyViolation> {
    // SAML Core 2.0 §§5.4.1–5.4.4: one enveloped reference to the ID of
    // the enclosing assertion/message. Exclusive C14N is this profile's stricter
    // choice of the specification's SHOULD, not a general validity requirement.
    // https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    let parent = signature.parent().ok_or(configuration(
        "SAML Signature requires an enclosing element",
    ))?;
    if !parent.is_element()
        || !matches!(
            parent.tag_name().namespace(),
            Some("urn:oasis:names:tc:SAML:2.0:assertion" | "urn:oasis:names:tc:SAML:2.0:protocol")
        )
    {
        return Err(configuration(
            "SAML Signature must belong to a SAML assertion or message",
        ));
    }
    let id = parent
        .attribute("ID")
        .ok_or(configuration("signed SAML element requires ID"))?;
    let info = child(signature, DS, "SignedInfo").ok_or(configuration("missing SignedInfo"))?;
    let mut references = info.children().filter(|node| named(*node, DS, "Reference"));
    let reference = references
        .next()
        .ok_or(configuration("SAML requires one Reference"))?;
    if references.next().is_some()
        || reference
            .attribute("URI")
            .and_then(|uri| uri.strip_prefix('#'))
            != Some(id)
        || id.is_empty()
    {
        return Err(configuration(
            "SAML requires exactly one Reference to its enclosing element ID",
        ));
    }
    let exclusive = |uri| {
        matches!(
            uri,
            Some(
                "http://www.w3.org/2001/10/xml-exc-c14n#"
                    | "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
            )
        )
    };
    if !exclusive(
        child(info, DS, "CanonicalizationMethod").and_then(|node| node.attribute("Algorithm")),
    ) {
        return Err(configuration(
            "SAML profile requires exclusive SignedInfo canonicalization",
        ));
    }
    let transforms = child(reference, DS, "Transforms")
        .ok_or(configuration("SAML requires enveloped-signature transform"))?;
    let mut enveloped = 0;
    for transform in transforms.children().filter(|node| node.is_element()) {
        if !named(transform, DS, "Transform") {
            return Err(configuration("invalid SAML transform element"));
        }
        let uri = transform.attribute("Algorithm");
        if uri == Some("http://www.w3.org/2000/09/xmldsig#enveloped-signature") {
            enveloped += 1;
        } else if !exclusive(uri) {
            return Err(configuration(
                "SAML profile disallows partial-coverage transforms",
            ));
        }
    }
    if enveloped != 1 {
        return Err(configuration(
            "SAML requires one enveloped-signature transform",
        ));
    }
    Ok(())
}

fn ws_security(signature: Node<'_, '_>) -> Result<(), PolicyViolation> {
    // WS-Security 1.1.1 §8.2 places ds:Signature in wsse:Security.
    // SOAP Body authorization remains an explicit expected-target request.
    // https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.html
    let security = signature
        .parent()
        .ok_or(configuration("missing Security header"))?;
    if !named(
        security,
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "Security",
    ) {
        return Err(configuration(
            "WS-Security Signature must be a direct Security-header child",
        ));
    }
    let header = security
        .parent()
        .ok_or(configuration("missing SOAP Header"))?;
    let namespace = header
        .tag_name()
        .namespace()
        .ok_or(configuration("missing SOAP namespace"))?;
    if !matches!(
        namespace,
        "http://schemas.xmlsoap.org/soap/envelope/" | "http://www.w3.org/2003/05/soap-envelope"
    ) || !named(header, namespace, "Header")
        || !header
            .parent()
            .is_some_and(|node| named(node, namespace, "Envelope"))
    {
        return Err(configuration(
            "WS-Security requires a SOAP Envelope/Header/Security placement",
        ));
    }
    Ok(())
}

fn xades(signature: Node<'_, '_>) -> Result<(), PolicyViolation> {
    // ETSI EN 319 132-1 V1.3.1 §4.4.2: SignedProperties is protected by
    // a Reference with the assigned Type. This checks XML-security binding,
    // not the complete signature profile or its timestamp/certificate claims.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
    let signature_id = signature
        .attribute("Id")
        .filter(|id| !id.is_empty())
        .ok_or(configuration("XAdES Signature requires Id"))?;
    let mut properties = None;
    for object in signature
        .children()
        .filter(|node| named(*node, DS, "Object"))
    {
        for qualifying in object
            .children()
            .filter(|node| named(*node, XADES, "QualifyingProperties"))
        {
            if qualifying
                .attribute("Target")
                .and_then(|uri| uri.strip_prefix('#'))
                != Some(signature_id)
            {
                return Err(configuration(
                    "QualifyingProperties Target must identify its Signature",
                ));
            }
            for node in qualifying
                .children()
                .filter(|node| named(*node, XADES, "SignedProperties"))
            {
                if properties.replace(node).is_some() {
                    return Err(configuration("XAdES requires unique SignedProperties"));
                }
            }
        }
    }
    let properties = properties.ok_or(configuration("XAdES requires SignedProperties"))?;
    let id = properties
        .attribute("Id")
        .filter(|id| !id.is_empty())
        .ok_or(configuration("SignedProperties requires Id"))?;
    let info = child(signature, DS, "SignedInfo").ok_or(configuration("missing SignedInfo"))?;
    let mut count = 0;
    for reference in info.children().filter(|node| named(*node, DS, "Reference")) {
        if reference.attribute("Type") == Some("http://uri.etsi.org/01903#SignedProperties") {
            if reference
                .attribute("URI")
                .and_then(|uri| uri.strip_prefix('#'))
                != Some(id)
            {
                return Err(configuration(
                    "SignedProperties Reference must identify the protected properties",
                ));
            }
            count += 1;
            if let Some(transforms) = child(reference, DS, "Transforms") {
                for transform in transforms.children().filter(|node| node.is_element()) {
                    if !named(transform, DS, "Transform")
                        || !transform
                            .attribute("Algorithm")
                            .is_some_and(|uri| crate::c14n::C14nAlgorithm::from_uri(uri).is_some())
                    {
                        return Err(configuration(
                            "SignedProperties protection permits only canonicalization transforms",
                        ));
                    }
                }
            }
        }
    }
    if count != 1 {
        return Err(configuration(
            "XAdES requires exactly one typed SignedProperties Reference",
        ));
    }
    Ok(())
}
