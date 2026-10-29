#[cfg(feature = "xmlenc")]
use super::OAEP_MGF_DIGESTS;
use super::{PolicyCompileContext, PolicySet, SignatureConstraints, configuration};
use crate::policy::{
    CertificateSignatureAlgorithms, HmacPolicy, KeyTrustPolicy, PolicyViolation, TransformPolicy,
    UriPolicy,
};
#[cfg(feature = "xmlenc")]
use crate::policy::{
    DataEncryptionAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm,
};
use crate::provider::{CryptoProvider, ProviderCapability};
use crate::xml::dom::Node;
use crate::xmldsig::{DigestAlgorithm, SignatureAlgorithm};
use alloc::collections::BTreeSet;

impl PolicySet {
    pub(super) fn validate(
        &self,
        context: PolicyCompileContext,
        provider: &dyn CryptoProvider,
    ) -> Result<(), PolicyViolation> {
        if let Some(policy) = &self.verification {
            policy.validate()?;
            signature_methods(
                policy.signature_algorithms.as_ref(),
                policy.hmac,
                provider,
                false,
                |algorithm| policy.check_signature_algorithm(algorithm),
            )?;
            digest_methods(policy.digest_algorithms.as_ref(), provider)?;
            signature_transforms(&policy.transforms, policy.signature_constraints)?;
            certificate_methods(&policy.key_trust, provider)?;
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
                provider,
                true,
                |algorithm| policy.check_signature_algorithm(algorithm),
            )?;
            digest_methods(policy.digest_algorithms.as_ref(), provider)?;
            signature_transforms(&policy.transforms, policy.signature_constraints)?;
            uri_contract(policy.uris, context)?;
        }
        #[cfg(feature = "xmlenc")]
        {
            if let Some(policy) = &self.encryption {
                policy.validate()?;
                cipher_methods(
                    policy.data_algorithms.as_ref(),
                    policy.key_wrap_algorithms.as_ref(),
                    provider,
                    true,
                )?;
                transport_methods(
                    policy.key_transport_algorithms.as_ref(),
                    policy.oaep_digests.as_ref(),
                    provider,
                    true,
                )?;
            }
            if let Some(policy) = &self.decryption {
                policy.validate()?;
                cipher_methods(
                    policy.data_algorithms.as_ref(),
                    policy.key_wrap_algorithms.as_ref(),
                    provider,
                    false,
                )?;
                transport_methods(
                    policy.key_transport_algorithms.as_ref(),
                    policy.oaep_digests.as_ref(),
                    provider,
                    false,
                )?;
                uri_contract(policy.uris, context)?;
            }
        }
        Ok(())
    }
}

fn signature_methods(
    methods: Option<&BTreeSet<SignatureAlgorithm>>,
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
    methods: Option<&BTreeSet<DigestAlgorithm>>,
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

fn certificate_methods(
    trust: &KeyTrustPolicy,
    provider: &dyn CryptoProvider,
) -> Result<(), PolicyViolation> {
    if !trust.verify_x509_chains {
        return Ok(());
    }
    if let Some(CertificateSignatureAlgorithms::Allowlist(methods)) =
        &trust.certificate_signature_algorithms
    {
        for &algorithm in methods {
            if !provider.supports(ProviderCapability::VerifyCertificate(algorithm)) {
                return Err(configuration(
                    "selected provider does not support a permitted certificate/CRL method",
                ));
            }
        }
    }
    Ok(())
}

fn signature_transforms(
    transforms: &TransformPolicy,
    constraints: SignatureConstraints,
) -> Result<(), PolicyViolation> {
    // XMLDSig 1.1 §4.4.1 requires CanonicalizationMethod in SignedInfo.
    // This is configuration viability, not rejection of an untrusted document.
    // https://www.w3.org/TR/xmldsig-core1/#sec-CanonicalizationMethod
    if let Some(methods) = &transforms.allowed_algorithms {
        // SAML Core §§5.4.3–5.4.4 requires enveloped processing; exclusive
        // C14N is the existing profile's stricter choice of the SHOULD.
        // https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
        if constraints == SignatureConstraints::Saml
            && !methods.contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        {
            return Err(configuration(
                "SAML profile has no permitted enveloped-signature transform",
            ));
        }
        for uri in methods {
            let Some(algorithm) = crate::c14n::C14nAlgorithm::from_uri(uri) else {
                continue;
            };
            if constraints != SignatureConstraints::Saml
                || algorithm.mode() == crate::c14n::C14nMode::Exclusive1_0
            {
                return Ok(());
            }
        }
        return Err(configuration(
            "enabled signature operation has no permitted canonicalization method",
        ));
    }
    Ok(())
}

fn uri_contract(uris: UriPolicy, context: PolicyCompileContext) -> Result<(), PolicyViolation> {
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
    data: Option<&BTreeSet<DataEncryptionAlgorithm>>,
    wraps: Option<&BTreeSet<KeyWrapAlgorithm>>,
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
            Self::Xades => xades(signature, budget),
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
    methods: Option<&BTreeSet<KeyTransportAlgorithm>>,
    digests: Option<&BTreeSet<OaepDigestAlgorithm>>,
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
            for mgf in OAEP_MGF_DIGESTS {
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
    // Core §§2.3.3, 3.2 and 5.4.2: the ID names the assertion/message
    // root, not an arbitrary element sharing its namespace. The protocol schema
    // defines these request/response roots. SubjectQuery is an extension point
    // with an abstract base type (§3.3.2.1); derived schema validation stays
    // with the application, as does payload-schema validation for other roots.
    // https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
    let signable = match parent.tag_name().namespace() {
        Some("urn:oasis:names:tc:SAML:2.0:assertion") => parent.tag_name().name() == "Assertion",
        Some("urn:oasis:names:tc:SAML:2.0:protocol") => matches!(
            parent.tag_name().name(),
            "AssertionIDRequest"
                | "SubjectQuery"
                | "AuthnQuery"
                | "AttributeQuery"
                | "AuthzDecisionQuery"
                | "AuthnRequest"
                | "Response"
                | "ArtifactResolve"
                | "ArtifactResponse"
                | "ManageNameIDRequest"
                | "ManageNameIDResponse"
                | "LogoutRequest"
                | "LogoutResponse"
                | "NameIDMappingRequest"
                | "NameIDMappingResponse"
        ),
        _ => false,
    };
    if !parent.is_element() || !signable {
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
    for transform in transforms.children().filter(Node::is_element) {
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

fn xades(
    signature: Node<'_, '_>,
    budget: &crate::xmldsig::transforms::TransformExecutionBudget,
) -> Result<(), PolicyViolation> {
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
    // ETSI EN 319 132-1 V1.3.1 §4.3.2 forbids empty SignedProperties and
    // defines this sequence of optional containers, not arbitrary children.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    xades_containers(properties, budget)?;
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
                for transform in transforms.children().filter(Node::is_element) {
                    if !named(transform, DS, "Transform") {
                        return Err(configuration("invalid SignedProperties transform element"));
                    }
                    let Some(uri) = transform.attribute("Algorithm") else {
                        return Err(configuration(
                            "SignedProperties transform requires Algorithm",
                        ));
                    };
                    if crate::c14n::C14nAlgorithm::from_uri(uri).is_none() {
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

fn xades_containers(
    properties: Node<'_, '_>,
    budget: &crate::xmldsig::transforms::TransformExecutionBudget,
) -> Result<(), PolicyViolation> {
    // ETSI EN 319 132-1 V1.3.1 §4.3.2 requires nonempty, ordered containers.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
    let mut last = 0;
    for node in properties.children() {
        if node.is_element() {
            let position = if named(node, XADES, "SignedSignatureProperties") {
                1
            } else if named(node, XADES, "SignedDataObjectProperties") {
                2
            } else {
                return Err(configuration("invalid SignedProperties child"));
            };
            if position <= last {
                return Err(configuration(
                    "invalid SignedProperties container order or duplicate",
                ));
            }
            last = position;
        } else if let Some(text) = node.text().filter(|_| node.is_text()) {
            budget
                .charge_node_filter_work(text.len())
                .map_err(|error| match error {
                    crate::xmldsig::TransformError::Policy(error) => error,
                    _ => configuration("signature profile inspection budget failed"),
                })?;
            for byte in text.bytes() {
                if !matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                    return Err(configuration(
                        "SignedProperties cannot contain character data",
                    ));
                }
            }
        }
    }
    if last == 0 {
        return Err(configuration(
            "SignedProperties requires a qualifying-property container",
        ));
    }
    Ok(())
}
