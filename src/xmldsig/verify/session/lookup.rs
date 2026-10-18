//! Operation-bound lookups for signature-extension formats.

use super::*;

/// Outcome of resolving a same-document bare-name URI (`#id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareNameTarget {
    /// The fragment names exactly this element under the operation's ID rules.
    Element(NodeIdentity),
    /// The URI has another form: a non-empty base, no fragment, or an XPointer.
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

impl<W: Work> VerifiedSession<'_, '_, '_, W> {
    /// Resolve `#id` through this operation's ID registrations, fragment
    /// unescaping and same-document ID semantics, charging `work`. XMLDSig 1.1
    /// §4.4.3.3 defines the bare-name form; XPointer and non-fragment forms are
    /// reported, never interpreted.
    /// <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Same-Document>
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
            None => BareNameTarget::NotBareName,
            Some(Some(node)) if node.is_element() => {
                BareNameTarget::Element(self.view.node_identity(node))
            }
            Some(_) => BareNameTarget::Unresolved,
        })
    }

    /// Interpret an original `DigestMethod` element. A recognized algorithm
    /// that the operation policy forbids is a policy error, not `Unsupported`.
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

    /// Hash `data` with the selected provider under the compiled digest policy.
    /// Work covers the input; the output is stored in `work`'s account. A
    /// provider output of the wrong width is a provider error.
    pub fn digest_in<Q: Work>(
        &self,
        algorithm: DigestAlgorithm,
        data: &[u8],
        work: &Q,
    ) -> Result<OwnedVec<u8, Q>, DsigError> {
        self.context.policy.check_digest_algorithm(algorithm)?;
        work.charge_work(u64::try_from(data.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
        let mut output = work.vector();
        output.try_reserve_exact(algorithm.output_len())?;
        let mut state = super::super::super::digest::begin_digest(self.context.provider, algorithm)
            .map_err(DsigError::from)?;
        state.update(data).map_err(DsigError::from)?;
        let digest = super::super::super::digest::finish_digest(algorithm, state)
            .map_err(DsigError::from)?;
        output.try_extend_from_slice(&digest)?;
        Ok(output)
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

    /// Certificate-path signature checks for `chain` and `anchor` through this
    /// operation's provider and certificate trust policy.
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
        )
    }
}
