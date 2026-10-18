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
    /// Resolve `#id` through this operation's ID registrations and URI kernel,
    /// charging `work`. XMLDSig 1.1 §4.4.3.3 defines the bare-name form; other
    /// fragment forms are reported, never interpreted.
    /// <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Same-Document>
    pub fn resolve_bare_name_in<Q: Work>(
        &self,
        uri: &str,
        work: &Q,
    ) -> Result<BareNameTarget, DsigError> {
        work.charge_work(
            u64::try_from(uri.len())
                .ok()
                .and_then(|length| length.checked_add(1))
                .ok_or(MemoryError::WorkExceeded)?,
        )?;
        let Some(fragment) = uri.strip_prefix('#') else {
            return Ok(BareNameTarget::NotBareName);
        };
        if !crate::xml::is_xml_ncname(fragment) {
            return Ok(BareNameTarget::NotBareName);
        }
        let target = self
            .resolver
            .node_for_same_document_reference_in(
                uri,
                Some(self.budgets.transforms.node_set_materialization()),
                &crate::c14n::scratch::Accounted(work),
            )
            .map_err(|error| {
                DsigError::Reference(ReferenceProcessingError::UriDereference(error))
            })?;
        Ok(match target {
            Some(node) if node.is_element() => {
                BareNameTarget::Element(self.view.node_identity(node))
            }
            _ => BareNameTarget::Unresolved,
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
