//! Detached Reference payloads completed after the signature verified.
//!
//! Verification leaves an external Reference without caller bytes
//! `ReferenceUnavailable`. The caller then streams the payload it paired with
//! that Reference, or attests a digest it computed, through the same session:
//! the selected provider, the immutable policy and the remaining budgets of the
//! original operation decide the result. Nothing here performs I/O.

use super::super::{
    DigestAlgorithm, DsigError, DsigStatus, ExternalPayload, FailureReason, ReferenceSet,
    SignatureVerificationPipelineError, Transform, VerifiedSession,
};
use crate::NodeIdentity;
use base64::Engine as _;
use structured_asn1::memory::{MemoryError, OwnedText, OwnedVec, Work};

/// How detached completion treats a failed Reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachedCompletion {
    /// Every Reference gets its own result, as in verification.
    Complete,
    /// Stop at the first failure: no payload is requested for a Signature whose
    /// core validation already failed, and the first failed detached Reference
    /// leaves every remaining pending Reference `NotProcessed`.
    FailFast,
}

/// The bytes a pending detached Reference digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetachedChain {
    /// No transforms: the payload octets.
    Octets,
    /// A single Base64 transform: the decoded payload (RFC 2045 §6.8 alphabet).
    Base64,
}

/// A detached Reference of an authenticated Signature awaiting its payload.
#[derive(Debug)]
pub struct PendingDetached<W: Work> {
    signature: NodeIdentity,
    reference: NodeIdentity,
    reference_set: ReferenceSet,
    reference_index: usize,
    uri: OwnedText<W>,
    digest_algorithm: DigestAlgorithm,
    chain: DetachedChain,
}

impl<W: Work> PendingDetached<W> {
    /// The Signature that authenticated this Reference.
    #[must_use]
    pub const fn signature(&self) -> NodeIdentity {
        self.signature
    }
    /// The original Reference element.
    #[must_use]
    pub const fn reference(&self) -> NodeIdentity {
        self.reference
    }
    /// Whether the Reference belongs to `SignedInfo` or a Manifest.
    #[must_use]
    pub const fn reference_set(&self) -> ReferenceSet {
        self.reference_set
    }
    /// Zero-based index within its reference set.
    #[must_use]
    pub const fn reference_index(&self) -> usize {
        self.reference_index
    }
    /// The URI resolved against its XML Base (XML Base Second Edition §4.2),
    /// as the signer wrote it; pairing a payload with it is the caller's choice.
    #[must_use]
    pub fn uri(&self) -> &str {
        self.uri.as_str()
    }
    /// The declared `DigestMethod`.
    #[must_use]
    pub const fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }
    /// What the digest covers.
    #[must_use]
    pub const fn chain(&self) -> DetachedChain {
        self.chain
    }
}

/// One pending Reference, located in the session evidence.
struct Target {
    signature: usize,
    set: ReferenceSet,
    ordinal: usize,
    reference: NodeIdentity,
    reference_index: usize,
    algorithm: DigestAlgorithm,
    expected: Vec<u8>,
    chain: DetachedChain,
}

/// One digest state per distinct (algorithm, chain): equal identities share it.
struct StreamState<'p> {
    algorithm: DigestAlgorithm,
    chain: DetachedChain,
    state: Box<dyn crate::provider::DigestState + 'p>,
}

/// RFC 2045 alphabet bytes are decoded in blocks of whole quanta; the same
/// `STANDARD` engine as the resident Base64 transform enforces padding.
const BASE64_BLOCK: usize = 4096;

struct Base64Stream {
    block: [u8; BASE64_BLOCK],
    filled: usize,
    /// Alphabet bytes accepted so far: the offset the resident decoder reports
    /// within its filtered input.
    offset: usize,
    padded: bool,
    failure: Option<base64::DecodeError>,
}

impl Base64Stream {
    fn new() -> Self {
        Self {
            block: [0; BASE64_BLOCK],
            filled: 0,
            offset: 0,
            padded: false,
            failure: None,
        }
    }

    /// Decode `chunk` and hand each decoded block to `sink`. A decoding error
    /// is kept and stops this stream only; octet digests continue.
    fn feed(
        &mut self,
        chunk: &[u8],
        sink: &mut impl FnMut(&[u8]) -> Result<(), DsigError>,
    ) -> Result<(), DsigError> {
        if self.failure.is_some() {
            return Ok(());
        }
        for &byte in chunk {
            // RFC 2045 §6.8: bytes outside the alphabet are ignored, exactly as
            // the resident transform filters them before decoding.
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')) {
                continue;
            }
            if self.padded {
                // Padding ends the encoded data; anything after it is the
                // invalid byte the resident decoder reports.
                self.failure = Some(base64::DecodeError::InvalidByte(self.offset, byte));
                return Ok(());
            }
            self.block[self.filled] = byte;
            self.filled += 1;
            // Bounded by the policy's streamed byte limit, which fits usize.
            self.offset += 1;
            if self.filled == BASE64_BLOCK {
                self.flush(sink)?;
                if self.failure.is_some() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn flush(
        &mut self,
        sink: &mut impl FnMut(&[u8]) -> Result<(), DsigError>,
    ) -> Result<(), DsigError> {
        let mut decoded = [0_u8; BASE64_BLOCK / 4 * 3];
        let encoded = &self.block[..self.filled];
        // The block holds the last `filled` accepted bytes.
        let base = self.offset - encoded.len();
        self.padded = encoded.last() == Some(&b'=');
        self.filled = 0;
        match base64::engine::general_purpose::STANDARD.decode_slice(encoded, &mut decoded) {
            Ok(written) => sink(&decoded[..written]),
            Err(error) => {
                self.failure = Some(match error {
                    base64::DecodeSliceError::DecodeError(base64::DecodeError::InvalidByte(
                        index,
                        byte,
                    )) => base64::DecodeError::InvalidByte(base + index, byte),
                    base64::DecodeSliceError::DecodeError(
                        base64::DecodeError::InvalidLastSymbol {
                            offset,
                            symbol,
                            symbol_value,
                        },
                    ) => base64::DecodeError::InvalidLastSymbol {
                        offset: base + offset,
                        symbol,
                        symbol_value,
                    },
                    base64::DecodeSliceError::DecodeError(base64::DecodeError::InvalidLength(
                        length,
                    )) => base64::DecodeError::InvalidLength(base + length),
                    base64::DecodeSliceError::DecodeError(error) => error,
                    // The output block holds every quantum of a full input
                    // block, so its size cannot be the failure.
                    base64::DecodeSliceError::OutputSliceTooSmall => {
                        base64::DecodeError::InvalidLength(encoded.len())
                    }
                });
                Ok(())
            }
        }
    }

    /// Decode the final partial block; an incomplete quantum is the padding
    /// error the resident `STANDARD` decoder reports for the whole input.
    fn finish(
        mut self,
        sink: &mut impl FnMut(&[u8]) -> Result<(), DsigError>,
    ) -> Result<Option<base64::DecodeError>, DsigError> {
        if self.failure.is_none() && self.filled > 0 {
            self.flush(sink)?;
        }
        Ok(self.failure)
    }
}

/// A detached payload being streamed into one session. Feed every chunk once
/// with [`Self::update`], then [`Self::finish`]. A refusal is sticky: the
/// payload yields no result and its References stay unavailable.
pub struct DetachedPayload<'s, 'view, 'scope, 'inputs, W: Work> {
    session: &'s mut VerifiedSession<'view, 'scope, 'inputs, W>,
    targets: Vec<Target>,
    states: Vec<StreamState<'scope>>,
    // A separate SHA-256 pass only when no Reference already digests the raw
    // payload with SHA-256; that digest is the fingerprint itself.
    fingerprint: Option<sha2::Sha256>,
    base64: Option<Base64Stream>,
    streamed: usize,
    completion: DetachedCompletion,
    refused: bool,
}

impl<'view, 'scope, 'inputs, W: Work> VerifiedSession<'view, 'scope, 'inputs, W> {
    /// Detached References still waiting for caller bytes, in document order
    /// of their Signatures. Only an authenticated Signature has any; with
    /// [`DetachedCompletion::FailFast`] a Signature whose core validation
    /// already failed offers none.
    ///
    /// # Errors
    /// Returns refused work or storage, or a failure re-reading an original
    /// Reference under the operation's budgets.
    pub fn pending_detached(
        &self,
        completion: DetachedCompletion,
    ) -> Result<OwnedVec<PendingDetached<W>, W>, DsigError> {
        let mut pending = self.work.vector();
        for target in self.detached_targets(completion)? {
            let node = self.view.resolve_node(target.reference)?;
            let uri = node.attribute("URI").ok_or(DsigError::InvalidRequest {
                reason: "pending detached Reference has no URI",
            })?;
            let resolved = crate::c14n::xml_base::resolve_uri_from_node_in(
                node,
                uri,
                None,
                self.budgets.transforms.xml_base_resolution(),
                &crate::c14n::scratch::Accounted(self.work),
            )
            .map_err(super::super::super::uri::map_xml_base_execution_error)
            .map_err(|error| {
                DsigError::Reference(super::ReferenceProcessingError::UriDereference(error))
            })?;
            pending.try_push(PendingDetached {
                signature: self.evidence.signatures()[target.signature].identity,
                reference: target.reference,
                reference_set: target.set,
                reference_index: target.reference_index,
                uri: resolved,
                digest_algorithm: target.algorithm,
                chain: target.chain,
            })?;
        }
        Ok(pending)
    }

    /// Start streaming one payload into the pending References the caller
    /// paired with it. Equal digest methods share one state, so one pass
    /// serves every listed Reference.
    ///
    /// # Errors
    /// Returns an invalid request for an empty, duplicated or non-pending
    /// Reference, or the selected provider's refusal of a digest method.
    pub fn detached_payload<'s>(
        &'s mut self,
        references: &[NodeIdentity],
        completion: DetachedCompletion,
    ) -> Result<DetachedPayload<'s, 'view, 'scope, 'inputs, W>, DsigError> {
        if references.is_empty() {
            return Err(DsigError::InvalidRequest {
                reason: "a detached payload needs at least one Reference",
            });
        }
        let targets = self.select_targets(references, completion)?;
        let provider = self.context.provider;
        let mut states: Vec<StreamState<'scope>> = Vec::new();
        for target in &targets {
            self.work.charge_work(1)?;
            if states
                .iter()
                .any(|state| state.algorithm == target.algorithm && state.chain == target.chain)
            {
                continue;
            }
            states.push(StreamState {
                algorithm: target.algorithm,
                chain: target.chain,
                state: super::super::super::digest::begin_digest(provider, target.algorithm)
                    .map_err(|error| DsigError::Reference(error.into()))?,
            });
        }
        let base64 = targets
            .iter()
            .any(|target| target.chain == DetachedChain::Base64)
            .then(Base64Stream::new);
        let fingerprint =
            (!states.iter().any(is_raw_sha256)).then(<sha2::Sha256 as sha2::Digest>::new);
        Ok(DetachedPayload {
            session: self,
            targets,
            states,
            fingerprint,
            base64,
            streamed: 0,
            completion,
            refused: false,
        })
    }

    /// Complete a Reference without transforms with a digest the caller
    /// computed over the payload it paired, when the policy accepts that. The
    /// result records the digest as attested, never as bytes hashed here.
    ///
    /// # Errors
    /// Returns a policy violation when attestation is forbidden, an invalid
    /// request for a non-pending or transformed Reference, or a failure
    /// completing core validation.
    pub fn attest_detached(
        &mut self,
        reference: NodeIdentity,
        digest: &[u8],
        completion: DetachedCompletion,
    ) -> Result<DsigStatus, DsigError> {
        if self.context.policy.detached_digest_attestation
            != crate::policy::DetachedDigestAttestation::Accepted
        {
            return Err(crate::policy::PolicyViolation::AttestedDigestForbidden.into());
        }
        let target = self.select_targets(&[reference], completion)?.pop().ok_or(
            DsigError::InvalidRequest {
                reason: "Reference is not a pending detached Reference",
            },
        )?;
        if target.chain != DetachedChain::Octets {
            return Err(DsigError::InvalidRequest {
                reason: "an attested digest covers only a Reference without transforms",
            });
        }
        self.work
            .charge_work(u64::try_from(digest.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
        let status = digest_status(&target, Some(digest));
        self.complete(
            &[(target, status)],
            None,
            ExternalPayload::Attested,
            completion,
        )?;
        Ok(status)
    }

    /// Every pending Reference eligible under `completion`.
    fn detached_targets(&self, completion: DetachedCompletion) -> Result<Vec<Target>, DsigError> {
        let mut targets = Vec::new();
        if completion == DetachedCompletion::FailFast && self.detached_stopped {
            return Ok(targets);
        }
        for (signature, entry) in self.evidence.signatures().iter().enumerate() {
            self.work.charge_work(1)?;
            let Ok(result) = &entry.result else {
                continue;
            };
            let operation = &self.operations[signature].operation;
            if !operation
                .accepted_signature()
                .is_some_and(|crypto| operation.is_executed(crypto))
            {
                continue;
            }
            let mut found = Vec::new();
            let mut core_failed = false;
            for (set, references) in [
                (ReferenceSet::SignedInfo, &result.signed_info_references),
                (ReferenceSet::Manifest, &result.manifest_references),
            ] {
                for (ordinal, reference) in references.iter().enumerate() {
                    self.work.charge_work(1)?;
                    let pending = matches!(
                        reference.status,
                        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { .. })
                    );
                    let target = match (pending, reference.reference_identity) {
                        (true, Some(identity)) => self.target(signature, set, ordinal, identity)?,
                        _ => None,
                    };
                    if set == ReferenceSet::SignedInfo
                        && reference.status != DsigStatus::Valid
                        && target.is_none()
                    {
                        // A failure the caller cannot repair by streaming.
                        core_failed = true;
                    }
                    found.extend(target);
                }
            }
            if completion == DetachedCompletion::FailFast && core_failed {
                continue;
            }
            targets.append(&mut found);
        }
        Ok(targets)
    }

    /// Re-read one original pending Reference under the operation's budgets.
    /// A chain needing XML stays on the resident path and is not streamable.
    fn target(
        &self,
        signature: usize,
        set: ReferenceSet,
        ordinal: usize,
        identity: NodeIdentity,
    ) -> Result<Option<Target>, DsigError> {
        let node = self.view.resolve_node(identity)?;
        for descendant in node.descendants() {
            let text = descendant
                .text()
                .filter(|_| descendant.is_text())
                .map_or(0, str::len);
            self.work.charge_work(
                u64::try_from(text)
                    .ok()
                    .and_then(|length| length.checked_add(1))
                    .ok_or(MemoryError::WorkExceeded)?,
            )?;
        }
        // Classify from the element layout first: a chain that cannot stream is
        // never parsed again, so listing it spends no XPath parse allowance.
        let Some(chain) = self.streamable_chain(node)? else {
            return Ok(None);
        };
        let reference = super::super::super::parse::parse_reference_with_xpath_budget(
            node,
            &mut self.budgets.xpath_parse.borrow_mut(),
        )
        .map_err(DsigError::ParseManifestReference)?;
        if !matches!(
            (chain, reference.transforms.as_slice()),
            (DetachedChain::Octets, []) | (DetachedChain::Base64, [Transform::Base64Decode])
        ) {
            return Ok(None);
        }
        let reference_index = match &self.evidence.signatures()[signature].result {
            Ok(result) => match set {
                ReferenceSet::SignedInfo => result.signed_info_references[ordinal].reference_index,
                ReferenceSet::Manifest => result.manifest_references[ordinal].reference_index,
            },
            Err(_) => return Ok(None),
        };
        Ok(Some(Target {
            signature,
            set,
            ordinal,
            reference: identity,
            reference_index,
            algorithm: reference.digest_method,
            expected: reference.digest_value,
            chain,
        }))
    }

    /// The streamable chain a Reference's `Transforms` layout declares: none, or
    /// exactly one Base64 transform. Anything else needs XML or other work.
    fn streamable_chain(
        &self,
        node: crate::xml::dom::Node<'_, '_>,
    ) -> Result<Option<DetachedChain>, DsigError> {
        let Ok((transforms, _, _)) = super::super::super::parse::inspect_reference_layout(node)
        else {
            return Ok(None);
        };
        let Some(transforms) = transforms else {
            return Ok(Some(DetachedChain::Octets));
        };
        let mut chain = None;
        for child in transforms
            .children()
            .filter(crate::xml::dom::Node::is_element)
        {
            self.work.charge_work(1)?;
            if chain.is_some()
                || !child.has_tag_name((super::super::XMLDSIG_NS, "Transform"))
                || child.attribute("Algorithm")
                    != Some(super::super::super::transforms::BASE64_TRANSFORM_URI)
            {
                return Ok(None);
            }
            chain = Some(DetachedChain::Base64);
        }
        Ok(chain)
    }

    fn select_targets(
        &self,
        references: &[NodeIdentity],
        completion: DetachedCompletion,
    ) -> Result<Vec<Target>, DsigError> {
        let mut pending = self.detached_targets(completion)?;
        let mut selected = Vec::with_capacity(references.len());
        for (position, reference) in references.iter().enumerate() {
            // One comparison per earlier listed Reference and per pending one.
            let comparisons = pending
                .len()
                .checked_add(position)
                .and_then(|count| u64::try_from(count).ok())
                .ok_or(MemoryError::WorkExceeded)?;
            self.work.charge_work(comparisons)?;
            if references[..position].contains(reference) {
                return Err(DsigError::InvalidRequest {
                    reason: "a Reference is listed twice for one detached payload",
                });
            }
            let index = pending
                .iter()
                .position(|target| target.reference == *reference)
                .ok_or(DsigError::InvalidRequest {
                    reason: "Reference is not a pending detached Reference",
                })?;
            selected.push(pending.swap_remove(index));
        }
        Ok(selected)
    }

    /// Record completed results, then apply core validation, fail-fast and the
    /// request's acceptance to the session evidence.
    fn complete(
        &mut self,
        results: &[(Target, DsigStatus)],
        fingerprint: Option<[u8; 32]>,
        payload: ExternalPayload,
        completion: DetachedCompletion,
    ) -> Result<(), DsigError> {
        let mut affected = Vec::new();
        let mut failed = false;
        for (target, status) in results {
            let retained = &self.operations[target.signature];
            let digest_node = retained
                .operation
                .reference_digest_node(target.reference_index, target.set == ReferenceSet::Manifest)
                .ok_or(DsigError::InvalidRequest {
                    reason: "pending detached Reference has no original digest node",
                })?;
            let accepted = *status == DsigStatus::Valid;
            retained.operation.set_outcome(
                digest_node,
                accepted,
                if accepted {
                    crate::operation::OperationDecisionReason::ReferenceDigestVerified
                } else {
                    crate::operation::OperationDecisionReason::ReferenceDigestRejected
                },
            );
            // Hash-use inspection reports what this operation hashed; an
            // attested digest was computed by the caller, not here.
            if payload == ExternalPayload::Streamed {
                let node = self.view.resolve_node(target.reference)?;
                super::super::VerificationCapture::computed_digest(
                    &retained.capture,
                    Some(node.id()),
                )?;
            }
            let entry = &mut self.evidence.signatures[target.signature];
            let Ok(result) = &mut entry.result else {
                continue;
            };
            let reference = match target.set {
                ReferenceSet::SignedInfo => &mut result.signed_info_references[target.ordinal],
                ReferenceSet::Manifest => &mut result.manifest_references[target.ordinal],
            };
            reference.status = *status;
            reference.external_resource_fingerprint = fingerprint;
            reference.external_payload = Some(payload);
            failed |= !accepted;
            if !affected.contains(&target.signature) {
                affected.push(target.signature);
            }
            // Fail-fast stops at the first failure in the caller's order; the
            // rest of this payload's References stay pending for stop_detached.
            if failed && completion == DetachedCompletion::FailFast {
                break;
            }
        }
        if failed && completion == DetachedCompletion::FailFast {
            self.stop_detached();
        }
        for signature in affected {
            self.revalidate(signature);
        }
        super::super::accept_verification_evidence(
            self.view,
            self.requirement,
            self.expected_targets,
            &mut self.evidence,
        )
    }

    /// Fail-fast: every Reference still waiting for bytes is left unprocessed.
    fn stop_detached(&mut self) {
        self.detached_stopped = true;
        for entry in &mut self.evidence.signatures {
            let Ok(result) = &mut entry.result else {
                continue;
            };
            for reference in result
                .signed_info_references
                .iter_mut()
                .chain(result.manifest_references.iter_mut())
            {
                if matches!(
                    reference.status,
                    DsigStatus::Invalid(FailureReason::ReferenceUnavailable { .. })
                ) {
                    reference.status = DsigStatus::NotProcessed;
                }
            }
        }
    }

    /// Recompute one Signature's core status. When its last `SignedInfo`
    /// Reference passes, core validation succeeds (`XMLDSig` 1.1 §3.2) and the
    /// authenticated Manifests are processed exactly as in verification.
    fn revalidate(&mut self, signature: usize) {
        let Ok(result) = &self.evidence.signatures[signature].result else {
            return;
        };
        let was_valid = result.status == DsigStatus::Valid;
        // NotProcessed is never an overall status: the first actual failure is.
        let first_failure = result
            .signed_info_references
            .iter()
            .find(|reference| matches!(reference.status, DsigStatus::Invalid(_)))
            .map(|reference| reference.status);
        let core_valid = result
            .signed_info_references
            .iter()
            .all(|reference| reference.status == DsigStatus::Valid);
        let reference_count = result.signed_info_references.len();
        if !core_valid {
            if let Ok(result) = &mut self.evidence.signatures[signature].result {
                result.status = first_failure.unwrap_or(result.status);
            }
            return;
        }
        if was_valid {
            return;
        }
        let manifests = self.process_manifests(signature, reference_count);
        let entry = &mut self.evidence.signatures[signature];
        match manifests {
            Ok(manifest_references) => {
                if let Ok(result) = &mut entry.result {
                    result.status = DsigStatus::Valid;
                    result.manifest_references = manifest_references;
                }
            }
            Err(error) => entry.result = Err(error),
        }
    }

    fn process_manifests(
        &mut self,
        signature: usize,
        reference_count: usize,
    ) -> Result<Vec<super::ReferenceResult>, SignatureVerificationPipelineError> {
        let view = self.view;
        let signature_node = view
            .resolve_node(self.evidence.signatures[signature].identity)
            .map_err(DsigError::from)?;
        let remaining = self
            .context
            .policy
            .resources
            .max_references
            .checked_sub(reference_count)
            .ok_or(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignedInfo exceeds the per-signature Reference limit",
            })?;
        let retained = &mut self.operations[signature];
        let operation = &mut retained.operation;
        let crypto = operation.accepted_signature().ok_or(
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "verified Signature has no accepted crypto node",
            },
        )?;
        let mut core_validation = Vec::with_capacity(reference_count + 1);
        for index in 0..reference_count {
            core_validation.push(operation.reference_digest_node(index, false).ok_or(
                SignatureVerificationPipelineError::InvalidStructure {
                    reason: "SignedInfo Reference has no original digest node",
                },
            )?);
        }
        core_validation.push(crypto);
        super::super::finish_core_validation(
            operation,
            view,
            signature_node,
            &self.resolver,
            &super::super::ManifestVerification {
                context: self.context,
                capture: &retained.capture,
            },
            remaining,
            core_validation,
        )
    }
}

fn is_raw_sha256(state: &StreamState<'_>) -> bool {
    state.algorithm == DigestAlgorithm::Sha256 && state.chain == DetachedChain::Octets
}

fn digest_status(target: &Target, digest: Option<&[u8]>) -> DsigStatus {
    match digest {
        Some(digest) if super::super::super::digest::constant_time_eq(digest, &target.expected) => {
            DsigStatus::Valid
        }
        Some(_) => DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch {
            ref_index: target.reference_index,
        }),
        None => DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure {
            ref_index: target.reference_index,
        }),
    }
}

impl<W: Work> DetachedPayload<'_, '_, '_, '_, W> {
    /// Feed the next chunk of the payload, exactly once and in order.
    ///
    /// # Errors
    /// Returns the policy limit, work or provider refusal. A refused payload
    /// accepts no further chunk and finishes without a result.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), DsigError> {
        if self.refused {
            return Err(DsigError::InvalidRequest {
                reason: "detached payload was already refused",
            });
        }
        let result = self.absorb(chunk);
        self.refused = result.is_err();
        result
    }

    fn absorb(&mut self, chunk: &[u8]) -> Result<(), DsigError> {
        let resources = &self.session.context.policy.resources;
        let streamed = self.streamed.checked_add(chunk.len()).ok_or(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::DETACHED_PAYLOAD_BYTES,
                maximum: resources.max_detached_payload_bytes,
            },
        )?;
        if streamed > resources.max_detached_payload_bytes {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::DETACHED_PAYLOAD_BYTES,
                maximum: resources.max_detached_payload_bytes,
                actual: streamed,
            }
            .into());
        }
        let total = self
            .session
            .detached_streamed
            .get()
            .checked_add(chunk.len())
            .ok_or(crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_DETACHED_PAYLOAD_BYTES,
                maximum: resources.max_detached_payload_total_bytes,
            })?;
        if total > resources.max_detached_payload_total_bytes {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_DETACHED_PAYLOAD_BYTES,
                maximum: resources.max_detached_payload_total_bytes,
                actual: total,
            }
            .into());
        }
        // Each digest state and a separate fingerprint read every byte once.
        let passes = self
            .states
            .len()
            .checked_add(usize::from(self.fingerprint.is_some()))
            .ok_or(MemoryError::WorkExceeded)?;
        let work = u64::try_from(chunk.len())
            .ok()
            .and_then(|bytes| bytes.checked_mul(u64::try_from(passes).ok()?))
            .ok_or(MemoryError::WorkExceeded)?;
        self.session.work.charge_work(work)?;
        self.streamed = streamed;
        self.session.detached_streamed.set(total);
        if let Some(fingerprint) = &mut self.fingerprint {
            sha2::Digest::update(fingerprint, chunk);
        }
        let provider_error =
            |error: crate::provider::ProviderError| DsigError::Reference(error.into());
        for state in &mut self.states {
            if state.chain == DetachedChain::Octets {
                state.state.update(chunk).map_err(provider_error)?;
            }
        }
        if let Some(base64) = &mut self.base64 {
            let states = &mut self.states;
            base64.feed(chunk, &mut |decoded| {
                for state in states.iter_mut() {
                    if state.chain == DetachedChain::Base64 {
                        state.state.update(decoded).map_err(provider_error)?;
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Finish the payload and record each listed Reference's own result.
    ///
    /// # Errors
    /// Returns an error for a payload refused earlier (its References stay
    /// unavailable), a provider failure, or a failure completing core validation.
    pub fn finish(self) -> Result<(), DsigError> {
        let Self {
            session,
            targets,
            mut states,
            fingerprint,
            base64,
            completion,
            refused,
            ..
        } = self;
        if refused {
            return Err(DsigError::InvalidRequest {
                reason: "detached payload was already refused",
            });
        }
        let provider_error =
            |error: crate::provider::ProviderError| DsigError::Reference(error.into());
        let base64_failure = match base64 {
            Some(base64) => base64
                .finish(&mut |decoded| {
                    for state in &mut states {
                        if state.chain == DetachedChain::Base64 {
                            state.state.update(decoded).map_err(provider_error)?;
                        }
                    }
                    Ok(())
                })?
                .is_some(),
            None => false,
        };
        let mut digests = Vec::with_capacity(states.len());
        for state in states {
            digests.push((
                state.algorithm,
                state.chain,
                super::super::super::digest::finish_digest(state.algorithm, state.state)
                    .map_err(provider_error)?,
            ));
        }
        let fingerprint: [u8; 32] = match fingerprint {
            Some(fingerprint) => sha2::Digest::finalize(fingerprint).into(),
            // finish_digest checked the SHA-256 width of the shared raw digest.
            None => digests
                .iter()
                .find(|(algorithm, chain, _)| {
                    *algorithm == DigestAlgorithm::Sha256 && *chain == DetachedChain::Octets
                })
                .and_then(|(_, _, digest)| <[u8; 32]>::try_from(digest.as_slice()).ok())
                .ok_or(DsigError::InvalidRequest {
                    reason: "raw SHA-256 digest is missing for the payload fingerprint",
                })?,
        };
        let mut results = Vec::with_capacity(targets.len());
        for target in targets {
            let digest = if target.chain == DetachedChain::Base64 && base64_failure {
                None
            } else {
                digests
                    .iter()
                    .find(|(algorithm, chain, _)| {
                        *algorithm == target.algorithm && *chain == target.chain
                    })
                    .map(|(_, _, digest)| digest.as_slice())
            };
            let status = digest_status(&target, digest);
            results.push((target, status));
        }
        session.complete(
            &results,
            Some(fingerprint),
            ExternalPayload::Streamed,
            completion,
        )
    }
}
