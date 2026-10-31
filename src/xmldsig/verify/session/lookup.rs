//! Operation-bound lookups for signature-extension formats.

use super::{
    DigestAlgorithm, DsigError, MemoryError, NodeIdentity, ReferenceProcessingError,
    VerifiedSession, Work, XMLDSIG_NS,
};
use crate::xmldsig::uri::BareNameNode;
use alloc::boxed::Box;

/// Outcome of resolving a same-document bare-name URI (`#id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareNameTarget {
    /// The fragment names exactly this element under the operation's ID rules.
    Element(NodeIdentity),
    /// The URI has another form: a non-empty base, no fragment, or an `XPointer`.
    NotBareName,
    /// No element, or more than one, carries this ID.
    Unresolved,
}

/// An original `DigestMethod` interpreted under the compiled digest policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestMethodResolution {
    /// A digest this crate implements and the operation policy permits.
    Supported(DigestAlgorithm),
    /// The Algorithm URI names no digest implemented by this crate.
    Unsupported,
    /// The required Algorithm attribute is absent.
    Malformed,
}

/// One incremental digest of a verified operation's provider.
pub struct SessionDigest<'p> {
    algorithm: DigestAlgorithm,
    state: Box<dyn crate::provider::DigestState + 'p>,
}

impl<'p> SessionDigest<'p> {
    /// Start `algorithm` on `provider` once `policy` permits it.
    pub(crate) fn begin(
        provider: &'p dyn crate::provider::CryptoProvider,
        policy: &crate::policy::VerificationPolicy,
        algorithm: DigestAlgorithm,
    ) -> Result<Self, DsigError> {
        policy.check_digest_algorithm(algorithm)?;
        let state = super::super::super::digest::begin_digest(provider, algorithm)
            .map_err(DsigError::from)?;
        Ok(Self { algorithm, state })
    }

    /// Required digest output width, independent of provider output.
    #[must_use]
    pub fn output_len(&self) -> usize {
        self.algorithm.output_len()
    }

    /// Absorb `data`, charging its length to `work` first.
    ///
    /// # Errors
    /// Returns an error for exhausted work or failure of the selected provider's
    /// streaming update. Resource causes remain distinct from digest mismatch.
    pub fn update<Q: Work>(&mut self, data: &[u8], work: &Q) -> Result<(), DsigError> {
        work.charge_work(u64::try_from(data.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
        self.state.update(data).map_err(DsigError::from)
    }

    /// Write the digest into an exactly sized caller buffer. Admit finalization
    /// work and the provider's temporary output before invoking it; the caller
    /// can keep an inline output without another heap allocation.
    ///
    /// # Errors
    /// Returns an error for the wrong output width, refused work or temporary
    /// capacity, provider finalization failure, or an invalid provider output size.
    pub fn finish<Q: Work>(self, output: &mut [u8], work: &Q) -> Result<(), DsigError> {
        let width = self.algorithm.output_len();
        if output.len() != width {
            return Err(DsigError::InvalidRequest {
                reason: "digest output buffer has the wrong width",
            });
        }
        work.charge_work(width as u64)?;
        let _temporary = work.memory().reserve(width)?;
        let digest = super::super::super::digest::finish_digest(self.algorithm, self.state)
            .map_err(DsigError::from)?;
        output.copy_from_slice(&digest);
        Ok(())
    }
}

impl<W: Work> VerifiedSession<'_, '_, '_, W> {
    /// Resolve `#id` through this operation's ID registrations, fragment
    /// unescaping and same-document ID semantics, charging `work`. `XMLDSig` 1.1
    /// §4.4.3.3 defines the bare-name form; `XPointer` and non-fragment forms are
    /// reported, never interpreted.
    /// <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Same-Document>
    ///
    /// # Errors
    /// Returns an error for exhausted query work, invalid URI encoding, or
    /// failure of bounded same-document lookup. Missing targets are not errors.
    pub fn resolve_bare_name_in<Q: Work>(
        &self,
        uri: &str,
        work: &Q,
    ) -> Result<BareNameTarget, DsigError> {
        work.charge_work(1)?;
        let target = self
            .resolver
            .bare_name_node_in(
                uri,
                Some(self.budgets.transforms.node_set_materialization()),
                &crate::c14n::scratch::Accounted(work),
            )
            .map_err(|error| {
                DsigError::Reference(ReferenceProcessingError::UriDereference(error))
            })?;
        Ok(match target {
            BareNameNode::NotBareName => BareNameTarget::NotBareName,
            BareNameNode::Node(node) if node.is_element() => {
                BareNameTarget::Element(self.view.node_identity(node))
            }
            BareNameNode::Node(_) | BareNameNode::Unresolved => BareNameTarget::Unresolved,
        })
    }

    /// Interpret an original `DigestMethod` element. A recognized algorithm
    /// that the operation policy forbids is a policy error, not `Unsupported`.
    ///
    /// # Errors
    /// Returns an error for a foreign/stale identity, the wrong element type,
    /// exhausted query work, or a recognized digest denied by policy.
    pub fn resolve_digest_method_in<Q: Work>(
        &self,
        method: NodeIdentity,
        work: &Q,
    ) -> Result<DigestMethodResolution, DsigError> {
        work.charge_work(1)?;
        let node = self.view.resolve_node(method)?;
        if !node.has_tag_name((XMLDSIG_NS, "DigestMethod")) {
            return Err(DsigError::InvalidRequest {
                reason: "digest method identity is not a ds:DigestMethod",
            });
        }
        let mut algorithm = None;
        for attribute in node.attributes() {
            work.charge_work(
                u64::try_from(attribute.name().len() + 1).map_err(|_| MemoryError::WorkExceeded)?,
            )?;
            if attribute.namespace().is_none() && attribute.name() == "Algorithm" {
                algorithm = Some(attribute.value());
                break;
            }
        }
        let Some(uri) = algorithm else {
            return Ok(DigestMethodResolution::Malformed);
        };
        work.charge_work(u64::try_from(uri.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
        // XMLDSig 1.1 §4.4.3.5 types Algorithm as anyURI, whose whiteSpace is
        // collapse (XSD 1.0 §4.3.6). No algorithm URI has interior whitespace,
        // so trimming the four XML whitespace characters decides the same.
        // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#rf-whiteSpace
        let uri = uri.trim_matches([' ', '\t', '\r', '\n']);
        let Some(algorithm) = DigestAlgorithm::from_uri(uri) else {
            return Ok(DigestMethodResolution::Unsupported);
        };
        self.context.policy.check_digest_algorithm(algorithm)?;
        Ok(DigestMethodResolution::Supported(algorithm))
    }

    /// Start an incremental digest with the selected provider under the
    /// compiled digest policy.
    ///
    /// # Errors
    /// Returns an error for a digest denied by policy, an unavailable provider
    /// capability, or failure to create the provider's incremental state.
    pub fn begin_digest(&self, algorithm: DigestAlgorithm) -> Result<SessionDigest<'_>, DsigError> {
        SessionDigest::begin(self.context.provider, &self.context.policy, algorithm)
    }

    /// CMS and RFC 3161 signature checks through this operation's provider,
    /// digest and certificate-signature policy and RSA/DSA key policy. Each
    /// call opens a new certificate account, as [`Self::certificate_parser`]
    /// does, so one CMS processing session uses one provider.
    #[cfg(feature = "cms")]
    pub fn cms_provider(&self) -> crate::xmldsig::cms::CmsProvider<'_> {
        crate::xmldsig::cms::CmsProvider::new(self.context.provider, &self.context.policy)
    }

    /// This verified request's own execution. A continuation that funds its
    /// work from the request, rather than from a separately supplied query
    /// account, keeps the caller's local and aggregate ceilings.
    pub fn execution(&self) -> &W {
        self.work
    }

    /// A DER certificate parser bounded by this operation's X.509 resource
    /// policy (`max_x509_work`, `max_x509_workspace_bytes`, under the hard
    /// ceilings), on a fresh account of its own, as verification's
    /// certificate processing is. Path validation and certificate storage
    /// that use its account obey the same limits.
    pub fn certificate_parser(&self) -> structured_asn1::Parser {
        super::super::super::pkix::CertificateSession::new(&self.context.policy.resources)
            .into_parser()
    }

    /// Shared path-processor bounds from this operation's key-trust policy,
    /// the same bounds verification applied to its own paths.
    pub fn certificate_path_bounds(&self) -> structured_pkix::path::ValidationBounds {
        super::super::super::pkix::path_bounds(self.context.policy.key_trust.max_x509_chain_depth)
    }

    /// CRL and OCSP signature checks through this operation's provider and
    /// certificate-signature permissions. Any key it is given is checked as
    /// supplied: the caller establishes that key's authority.
    pub fn revocation_verifier(&self) -> super::super::super::pkix::ProviderVerifier<'_> {
        super::super::super::pkix::ProviderVerifier {
            provider: self.context.provider,
            allowed: self
                .context
                .policy
                .key_trust
                .certificate_signature_algorithms
                .as_ref(),
        }
    }

    /// Certificate-path signature checks for `chain` and `anchor` through this
    /// operation's provider and certificate trust policy. Issuer key material
    /// is read on a fresh account bounded by this operation's X.509 resource
    /// policy, as [`Self::certificate_parser`] is.
    pub fn certificate_path_verifier<'a, 'p>(
        &'p self,
        chain: &'p [&'a structured_pkix::Certificate<'a>],
        anchor: &'a structured_pkix::Certificate<'a>,
    ) -> super::super::super::pkix::CertificatePathVerifier<'a, 'p> {
        super::super::super::pkix::CertificatePathVerifier::new(
            self.context.provider,
            &self.context.policy.key_trust,
            chain,
            anchor,
            super::super::super::pkix::CertificateSession::new(&self.context.policy.resources),
        )
    }
}

#[cfg(test)]
mod digest_admission_tests {
    use super::*;
    use std::cell::Cell;

    struct Observed<'a>(&'a Cell<bool>);
    impl crate::provider::DigestState for Observed<'_> {
        fn update(&mut self, _: &[u8]) -> Result<(), crate::provider::ProviderError> {
            Ok(())
        }
        fn finalize(self: Box<Self>) -> Result<Vec<u8>, crate::provider::ProviderError> {
            self.0.set(true);
            Ok(vec![0; 32])
        }
    }

    #[test]
    fn digest_refusals_never_enter_provider_finalize() {
        // Wrong output shape and both admission axes fail before the backend,
        // and a temporary output reservation is released on every path.
        for (capacity, work, width) in [(31, 100, 32), (32, 31, 32), (32, 100, 31), (32, 100, 32)] {
            let memory = structured_asn1::memory::Memory::new(std::sync::Arc::new(
                structured_asn1::memory::MemoryAccount::new(capacity, work),
            ));
            let called = Cell::new(false);
            let state = SessionDigest {
                algorithm: DigestAlgorithm::Sha256,
                state: Box::new(Observed(&called)),
            };
            let mut output = [0; 32];
            let result = state.finish(&mut output[..width], &memory);
            let admitted = capacity == 32 && work == 100 && width == 32;
            assert_eq!(result.is_ok(), admitted, "{result:?}");
            assert_eq!(called.get(), admitted);
            assert_eq!(memory.used(), 0);
        }
    }
}
