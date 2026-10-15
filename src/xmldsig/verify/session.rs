//! Continuations over the original verified document and operation state.

use super::*;
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};

type RetainedOperation<'scope, 'inputs> = OperationExecutionContext<
    &'scope crate::policy::VerificationPolicy,
    &'scope VerificationOperationBudgets<'inputs>,
>;

/// A verified request's scoped continuation. No document, policy, resolver or
/// budget is reconstructed when selecting a signature or replaying a reference.
pub struct VerifiedSession<'view, 'scope, 'inputs, W: Work> {
    view: DocumentView<'view>,
    context: &'scope VerifyContext<'inputs>,
    budgets: &'scope VerificationOperationBudgets<'inputs>,
    evidence: VerifyEvidence<OwnedVec<SignatureEvidence, W>>,
    operations: OwnedVec<RetainedOperation<'scope, 'inputs>, W>,
    resolver: UriReferenceResolver<'view>,
    work: &'scope W,
    replays: RefCell<OwnedVec<ReplayRecord, W>>,
    replay_active: Cell<bool>,
}

/// Verify once, then continue within the same document generation, selected
/// provider, immutable policy, captured inputs and remaining operation budgets.
/// The callback cannot return document- or operation-borrowing handles.
pub fn with_verified_request<'inputs, W: Work, R>(
    document: &XmlDocument,
    context: &VerifyContext<'inputs>,
    request: &VerificationRequest<'inputs>,
    work: &W,
    continuation: impl for<'view, 'scope> FnOnce(
        VerifiedSession<'view, 'scope, 'inputs, W>,
    ) -> Result<R, DsigError>,
) -> Result<R, DsigError> {
    with_verified_document(
        document,
        context,
        request,
        ScopedRequestStorage(work),
        |view, context, budgets, evidence, operations, resolver| {
            continuation(VerifiedSession {
                view,
                context,
                budgets,
                evidence,
                operations,
                resolver,
                work,
                replays: RefCell::new(work.vector()),
                replay_active: Cell::new(false),
            })
        },
    )
}

/// The exact authenticated parent of a reference instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceParent {
    /// Direct child of this selected Signature's SignedInfo.
    SignedInfo(NodeIdentity),
    /// Direct child of an authenticated original Manifest.
    Manifest(NodeIdentity),
}

/// Original reference metadata. Authentication of the instruction is separate
/// from the historical target digest result and conservative content coverage.
#[derive(Debug)]
pub struct AuthenticatedReference<'a> {
    /// Original document/generation-bound Reference identity.
    pub identity: NodeIdentity,
    /// Exact original SignedInfo or Manifest parent.
    pub parent: ReferenceParent,
    /// Original URI attribute, preserving omitted versus empty.
    pub uri: Option<&'a str>,
    /// Original Type attribute; not inferred from target shape.
    pub reference_type: Option<&'a str>,
    /// Historical result, absent when target execution was not completed.
    pub result: Option<&'a ReferenceResult>,
    /// Observed resource provenance, not a guess from URI spelling or a missing target.
    pub location: ReferenceLocation,
}

/// The original admitted resource route. `Unchecked` does not mean detached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceLocation {
    /// Original same-document target observed by reference verification.
    SameDocument(NodeIdentity),
    /// Admitted external lookup, with fingerprint only when bytes were supplied.
    Detached(Option<[u8; 32]>),
    /// No completed resource provenance was recorded.
    Unchecked,
}

/// Instruction discovery completeness, not a claim that every target is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogueCompleteness {
    /// All authenticated original instructions were visited.
    Complete,
    /// Original authenticated instructions were not processed by verification.
    Unchecked(NodeIdentity),
    /// An authenticated Manifest has not completed discovery/processing.
    Incomplete(NodeIdentity),
}

/// Visitor refusal remains distinct from XML/policy/resource processing errors.
#[derive(Debug)]
pub enum CatalogueError<E> {
    /// Original processing failure.
    Processing(DsigError),
    /// Original caller cause, without string conversion or boxing.
    Visitor(E),
}

/// Where the original property supplies its URI. Attribute lookup uses an
/// expanded name; simple content joins only direct text/CDATA in source order.
#[derive(Clone, Copy, Debug)]
pub enum LexicalSource<'a> {
    /// Exact original attribute; absence is not an empty URI.
    Attribute {
        /// Namespace URI, or no namespace (default namespaces do not apply to attributes).
        namespace: Option<&'a str>,
        /// Local name within that namespace.
        local_name: &'a str,
    },
    /// Simple content; nested elements are malformed, comments/PIs contribute no text.
    SimpleContent,
}

/// Semantic resolution facts, independent of terminal processing failures.
#[derive(Debug)]
pub enum ReferenceResolution<'a> {
    /// The selected attribute is absent.
    Absent,
    /// Simple content contains an element child.
    Malformed,
    /// The original URI is outside the implemented same-document grammar.
    /// Policy and resource refusal are processing errors, not this disposition.
    Unsupported,
    /// The admitted URI selects caller-owned external data, not an original XML Reference.
    Detached,
    /// The ID is missing or ambiguous under the operation's ID registrations.
    Unresolved,
    /// Original target is not a ds:Reference.
    NotReference(NodeIdentity),
    /// Original target instruction is not authenticated by this selected Signature.
    Unauthenticated(NodeIdentity),
    /// Original authenticated instruction, including exact parent and historical status.
    Reference(AuthenticatedReference<'a>),
}

enum LexicalValue<'a, W: Work> {
    Borrowed(&'a str),
    Joined(OwnedVec<u8, W>),
}
impl<W: Work> LexicalValue<'_, W> {
    fn as_str(&self) -> &str {
        match self {
            Self::Borrowed(value) => value,
            // Every appended fragment came from this document's UTF-8 semantic text.
            Self::Joined(value) => std::str::from_utf8(value).expect("semantic XML text is UTF-8"),
        }
    }
}

/// A selected signature, bound to this request rather than an aggregate boolean.
pub struct SelectedSignature<'session, 'view, 'scope, 'inputs, W: Work> {
    session: &'session VerifiedSession<'view, 'scope, 'inputs, W>,
    index: usize,
    results: OwnedMap<NodeIdentity, (ReferenceSet, usize), W>,
}

impl<'view, 'scope, 'inputs, W: Work> VerifiedSession<'view, 'scope, 'inputs, W> {
    /// Original immutable view; identities never cross a second parse/projection.
    pub fn view(&self) -> DocumentView<'view> {
        self.view
    }
    /// Results of the original verification. Inspect errors and target status
    /// independently of selected instruction authentication.
    pub fn evidence(&self) -> &VerifyEvidence<OwnedVec<SignatureEvidence, W>> {
        &self.evidence
    }

    /// Transfer independently owned result facts with their retained account.
    /// This transfers no document or operation borrow and no replay capability.
    pub fn into_evidence(self) -> VerifyEvidence<OwnedVec<SignatureEvidence, W>> {
        self.evidence
    }

    /// Select only a Signature whose original cryptographic decision succeeded.
    /// A failed child Manifest digest does not erase that decision.
    pub fn select_signature(
        &self,
        identity: NodeIdentity,
    ) -> Result<SelectedSignature<'_, 'view, 'scope, 'inputs, W>, DsigError> {
        self.work.charge_work(1)?;
        self.view.resolve_node(identity)?;
        for (index, entry) in self.evidence.signatures().iter().enumerate() {
            self.work.charge_work(1)?;
            if entry.identity != identity {
                continue;
            }
            let operation = &self.operations[index];
            operation.validate_document_view(self.view)?;
            self.work.charge_work(
                u64::try_from(operation.decision_count()).map_err(|_| MemoryError::WorkExceeded)?,
            )?;
            if operation.accepted_signature().is_none() {
                return Err(DsigError::InvalidRequest {
                    reason: "selected Signature is not authenticated",
                });
            }
            let mut results = self.work.map();
            if let Ok(result) = &entry.result {
                for (set, entries) in [
                    (ReferenceSet::SignedInfo, &result.signed_info_references),
                    (ReferenceSet::Manifest, &result.manifest_references),
                ] {
                    for (ordinal, reference) in entries.iter().enumerate() {
                        self.work.charge_work(1)?;
                        if let Some(node) = reference.reference_identity
                            && results.try_insert(node, (set, ordinal))?.is_some()
                        {
                            return Err(DsigError::InvalidRequest {
                                reason: "ambiguous original Reference evidence",
                            });
                        }
                    }
                }
            }
            return Ok(SelectedSignature {
                session: self,
                index,
                results,
            });
        }
        Err(DsigError::InvalidRequest {
            reason: "Signature is not part of this request",
        })
    }
}

impl<'session, 'view, 'scope, 'inputs, W: Work>
    SelectedSignature<'session, 'view, 'scope, 'inputs, W>
{
    fn operation(&self) -> &RetainedOperation<'scope, 'inputs> {
        &self.session.operations[self.index]
    }
    fn signature(&self) -> Result<Node<'_, '_>, DsigError> {
        Ok(self
            .session
            .view
            .resolve_node(self.session.evidence.signatures()[self.index].identity)?)
    }
    fn authenticates_element(&self, node: Node<'_, '_>) -> Result<bool, DsigError> {
        let signature = self.signature()?;
        for ancestor in node.ancestors() {
            self.session.work.charge_work(1)?;
            if ancestor.has_tag_name((XMLDSIG_NS, "SignedInfo"))
                && ancestor.parent() == Some(signature)
            {
                return Ok(true);
            }
            if self
                .operation()
                .is_authenticated(self.session.view.node_identity(ancestor))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Resolve from the authenticated original property's lexical source, using
    /// this request's URI grammar, ID registrations, policy and XML Base budget.
    /// No network fetch, independent ID scan or fabricated Reference is involved.
    pub fn resolve_reference(
        &self,
        property: NodeIdentity,
        source: LexicalSource<'_>,
    ) -> Result<ReferenceResolution<'_>, DsigError> {
        self.session.work.charge_work(1)?;
        self.operation().validate_document_view(self.session.view)?;
        let node = self.session.view.resolve_node(property)?;
        if !node.is_element() {
            return Err(DsigError::InvalidRequest {
                reason: "reference property must be an element",
            });
        }
        if !self.authenticates_element(node)? {
            return Ok(ReferenceResolution::Unauthenticated(property));
        }
        let value = match source {
            LexicalSource::Attribute {
                namespace,
                local_name,
            } => {
                let mut value = None;
                for attribute in node.attributes() {
                    let bytes = attribute
                        .name()
                        .len()
                        .checked_add(attribute.namespace().map_or(0, str::len))
                        .and_then(|n| n.checked_add(1))
                        .ok_or(MemoryError::WorkExceeded)?;
                    self.session.work.charge_work(
                        u64::try_from(bytes).map_err(|_| MemoryError::WorkExceeded)?,
                    )?;
                    if attribute.name() == local_name && attribute.namespace() == namespace {
                        value = Some(attribute.value());
                        break;
                    }
                }
                let Some(value) = value else {
                    return Ok(ReferenceResolution::Absent);
                };
                LexicalValue::Borrowed(value)
            }
            LexicalSource::SimpleContent => {
                let mut value = LexicalValue::Borrowed("");
                for child in node.children() {
                    self.session.work.charge_work(1)?;
                    if child.is_element() {
                        return Ok(ReferenceResolution::Malformed);
                    }
                    let Some(text) = child.text().filter(|_| child.is_text()) else {
                        continue;
                    };
                    match &mut value {
                        LexicalValue::Borrowed(first) if first.is_empty() => *first = text,
                        LexicalValue::Borrowed(first) => {
                            let mut joined = self.session.work.vector();
                            joined.try_extend_from_slice(first.as_bytes())?;
                            joined.try_extend_from_slice(text.as_bytes())?;
                            value = LexicalValue::Joined(joined);
                        }
                        LexicalValue::Joined(joined) => {
                            joined.try_extend_from_slice(text.as_bytes())?
                        }
                    }
                }
                value
            }
        };
        let uri = value.as_str();
        self.session
            .work
            .charge_work(u64::try_from(uri.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
        if !self.session.context.policy.uris.references.allows(uri) {
            return Err(crate::policy::PolicyViolation::Uri {
                operation: "extension reference resolution",
                reason: "reference URI class is not permitted",
            }
            .into());
        }
        if !uri.is_empty() && !uri.starts_with('#') {
            crate::c14n::xml_base::resolve_uri_from_node_with_budget(
                node,
                uri,
                self.session.budgets.transforms.xml_base_resolution(),
            )
            .map_err(super::super::uri::map_xml_base_resolution_error)
            .map_err(|error| {
                DsigError::Reference(ReferenceProcessingError::UriDereference(error))
            })?;
            return Ok(ReferenceResolution::Detached);
        }
        let target = self
            .session
            .resolver
            .node_for_same_document_reference_with_budget(
                uri,
                Some(self.session.budgets.transforms.node_set_materialization()),
            );
        let target = match target {
            Ok(target) => target,
            Err(TransformError::UnsupportedUri(_)) => return Ok(ReferenceResolution::Unsupported),
            Err(error) => {
                return Err(DsigError::Reference(
                    ReferenceProcessingError::UriDereference(error),
                ));
            }
        };
        let Some(target) = target else {
            return Ok(ReferenceResolution::Unresolved);
        };
        let identity = self.session.view.node_identity(target);
        if !target.has_tag_name((XMLDSIG_NS, "Reference")) {
            return Ok(ReferenceResolution::NotReference(identity));
        }
        match self.descriptor(identity)? {
            Some(reference) => Ok(ReferenceResolution::Reference(reference)),
            None => Ok(ReferenceResolution::Unauthenticated(identity)),
        }
    }
    fn parent(&self, reference: Node<'_, '_>) -> Result<Option<ReferenceParent>, DsigError> {
        if !reference.has_tag_name((XMLDSIG_NS, "Reference")) {
            return Ok(None);
        }
        let Some(parent) = reference.parent() else {
            return Ok(None);
        };
        let signature = self.signature()?;
        let view = self.session.view;
        if parent.has_tag_name((XMLDSIG_NS, "SignedInfo")) && parent.parent() == Some(signature) {
            return Ok(Some(ReferenceParent::SignedInfo(
                view.node_identity(parent),
            )));
        }
        if !parent.has_tag_name((XMLDSIG_NS, "Manifest")) {
            return Ok(None);
        }
        for ancestor in parent.ancestors() {
            self.session.work.charge_work(1)?;
            if self
                .operation()
                .is_authenticated(view.node_identity(ancestor))
            {
                return Ok(Some(ReferenceParent::Manifest(view.node_identity(parent))));
            }
        }
        Ok(None)
    }
    fn descriptor(
        &self,
        reference: NodeIdentity,
    ) -> Result<Option<AuthenticatedReference<'_>>, DsigError> {
        self.session.work.charge_work(1)?;
        self.operation().validate_document_view(self.session.view)?;
        let node = self.session.view.resolve_node(reference)?;
        let Some(parent) = self.parent(node)? else {
            return Ok(None);
        };
        let result = match self.results.get(&reference, self.session.work)? {
            Some((set, index)) => self.session.evidence.signatures()[self.index]
                .result
                .as_ref()
                .ok()
                .map(|result| match set {
                    ReferenceSet::SignedInfo => &result.signed_info_references[*index],
                    ReferenceSet::Manifest => &result.manifest_references[*index],
                }),
            None => None,
        };
        Ok(Some(AuthenticatedReference {
            identity: reference,
            parent,
            uri: node.attribute("URI"),
            reference_type: node.attribute("Type"),
            result,
            location: if let Some(target) = result.and_then(|result| result.target_identity) {
                ReferenceLocation::SameDocument(target)
            } else {
                match self
                    .session
                    .budgets
                    .resolved_reference_resources
                    .borrow()
                    .get(&node.id())
                {
                    Some(OperationResourceIdentity::External { fingerprint, .. }) => {
                        ReferenceLocation::Detached(Some(*fingerprint))
                    }
                    Some(OperationResourceIdentity::MissingExternal { .. }) => {
                        ReferenceLocation::Detached(None)
                    }
                    _ => ReferenceLocation::Unchecked,
                }
            },
        }))
    }

    /// Paid, single-pass original catalogue. No repeated ordinal rescanning;
    /// callbacks borrow descriptors and may retain only copied stable identities.
    pub fn visit_authenticated_references<E>(
        &self,
        mut visitor: impl for<'a> FnMut(AuthenticatedReference<'a>) -> Result<(), E>,
    ) -> Result<CatalogueCompleteness, CatalogueError<E>> {
        let mut completeness = CatalogueCompleteness::Complete;
        let mut references = 0;
        let maximum = self.session.context.policy.resources.max_references;
        self.operation()
            .validate_document_view(self.session.view)
            .map_err(|error| CatalogueError::Processing(error.into()))?;
        for node in self.session.view.document().descendants() {
            self.session
                .work
                .charge_work(1)
                .map_err(|error| CatalogueError::Processing(error.into()))?;
            if node.has_tag_name((XMLDSIG_NS, "Manifest"))
                && self
                    .authenticates_element(node)
                    .map_err(CatalogueError::Processing)?
            {
                let mut count = 0;
                let mut malformed = false;
                for child in node.children() {
                    self.session
                        .work
                        .charge_work(1)
                        .map_err(|error| CatalogueError::Processing(error.into()))?;
                    if child.has_tag_name((XMLDSIG_NS, "Reference")) {
                        count += 1;
                    } else if child.is_element() {
                        malformed = true;
                    } else if child.is_text() {
                        let text = child.text().unwrap_or_default();
                        self.session
                            .work
                            .charge_work(text.len() as u64)
                            .map_err(|error| CatalogueError::Processing(error.into()))?;
                        if !is_xml_whitespace_only(text) {
                            malformed = true;
                        }
                    }
                }
                if (malformed || count == 0)
                    && !matches!(completeness, CatalogueCompleteness::Incomplete(_))
                {
                    completeness =
                        CatalogueCompleteness::Incomplete(self.session.view.node_identity(node));
                }
            }
            if !node.has_tag_name((XMLDSIG_NS, "Reference")) {
                continue;
            }
            let Some(reference) = self
                .descriptor(self.session.view.node_identity(node))
                .map_err(CatalogueError::Processing)?
            else {
                continue;
            };
            if references == maximum {
                return Err(CatalogueError::Processing(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
                        maximum,
                        actual: references + 1,
                    }
                    .into(),
                ));
            }
            references += 1;
            if super::super::parse::reference_layout(node).is_err() {
                if !matches!(completeness, CatalogueCompleteness::Incomplete(_)) {
                    completeness = CatalogueCompleteness::Incomplete(reference.identity);
                }
            } else if let ReferenceParent::Manifest(parent) = reference.parent
                && matches!(completeness, CatalogueCompleteness::Complete)
                && self.session.context.policy.manifest_processing
                    == crate::policy::ManifestProcessing::Ignore
            {
                completeness = CatalogueCompleteness::Unchecked(parent);
            }
            visitor(reference).map_err(CatalogueError::Visitor)?;
        }
        Ok(completeness)
    }
}

/// Final node-set coercion. Explicit final C14N transforms already produce
/// octets and therefore take precedence over either implicit mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayMode {
    /// XMLDSig 1.1 §4.3.3.2 implicit C14N 1.0.
    ReferenceOutput,
    /// Original timestamp CanonicalizationMethod node, including parameters.
    Timestamp(NodeIdentity),
}

/// Missing explicitly supplied external bytes are diagnostic, not a successful
/// empty output. Policy, malformed XML and processing failures remain errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The receiver obtained the entire output.
    Complete,
    /// The request did not supply this admitted external resource.
    Unavailable(ExternalResourceUnavailable),
}

/// The admitted external lookup was absent from the captured caller map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalResourceUnavailable {
    /// Original authenticated Reference whose lookup was absent.
    pub reference: NodeIdentity,
}

/// Typed sticky receiver failure, independent of XML processing failure.
#[derive(Debug)]
pub enum ReplayError<E> {
    /// XML, policy, provenance or resource failure.
    Processing(DsigError),
    /// Original receiver error.
    Receiver(E),
}
impl<E> From<TransformError> for ReplayError<E> {
    fn from(error: TransformError) -> Self {
        Self::Processing(DsigError::Reference(ReferenceProcessingError::Transform(
            error,
        )))
    }
}
impl<E> From<OperationPlanError> for ReplayError<E> {
    fn from(error: OperationPlanError) -> Self {
        Self::Processing(error.into())
    }
}

struct ReplayWriter<'a, W: Work, E, F> {
    work: &'a W,
    budget: &'a TransformExecutionBudget,
    receiver: &'a mut F,
    failure: Option<ReplayError<E>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayState {
    Pending,
    Complete,
    Unavailable,
    Rejected,
}
struct ReplayRecord {
    signature: NodeIdentity,
    reference: NodeIdentity,
    state: ReplayState,
}

struct AdmittedReplay<'a, W: Work> {
    records: &'a RefCell<OwnedVec<ReplayRecord, W>>,
    active: &'a Cell<bool>,
    index: usize,
}
impl<W: Work> AdmittedReplay<'_, W> {
    fn finish<E>(&self, result: &Result<ReplayOutcome, ReplayError<E>>) {
        self.records.borrow_mut()[self.index].state = match result {
            Ok(ReplayOutcome::Complete) => ReplayState::Complete,
            Ok(ReplayOutcome::Unavailable(_)) => ReplayState::Unavailable,
            Err(_) => ReplayState::Rejected,
        };
    }
}
impl<W: Work> Drop for AdmittedReplay<'_, W> {
    fn drop(&mut self) {
        let mut records = self.records.borrow_mut();
        if records[self.index].state == ReplayState::Pending {
            records[self.index].state = ReplayState::Rejected;
        }
        self.active.set(false);
    }
}
impl<W: Work, E, F: FnMut(&[u8]) -> Result<(), E>> std::io::Write for ReplayWriter<'_, W, E, F> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.failure.is_some() {
            return Err(std::io::ErrorKind::Other.into());
        }
        let result = (|| {
            let units = u64::try_from(bytes.len())
                .map_err(|_| ReplayError::Processing(MemoryError::WorkExceeded.into()))?;
            self.work
                .charge_work(units)
                .map_err(|error| ReplayError::Processing(error.into()))?;
            super::super::transforms::charge_replay_output(self.budget, bytes.len())?;
            (self.receiver)(bytes).map_err(ReplayError::Receiver)
        })();
        match result {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.failure = Some(error);
                Err(std::io::ErrorKind::Other.into())
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Work> SelectedSignature<'_, '_, '_, '_, W> {
    /// Re-execute an authenticated instruction, not its historical digest test.
    /// EN 319 132-1 V1.3.1 §5.5.3 steps 3/6 and Note 2 deliberately permit
    /// renewal without recomputing the original digest algorithm.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn replay_reference<E>(
        &self,
        reference: NodeIdentity,
        mode: ReplayMode,
        receiver: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<ReplayOutcome, ReplayError<E>> {
        self.session
            .work
            .charge_work(
                u64::try_from(self.operation().decision_count())
                    .map_err(|_| ReplayError::Processing(MemoryError::WorkExceeded.into()))?,
            )
            .map_err(|error| ReplayError::Processing(error.into()))?;
        self.operation()
            .run_reference_replay(self.session.view, reference, || {
                self.replay_admitted(reference, mode, receiver)
            })
    }

    fn replay_admitted<E>(
        &self,
        reference: NodeIdentity,
        mode: ReplayMode,
        receiver: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<ReplayOutcome, ReplayError<E>> {
        let processing = ReplayError::Processing;
        let descriptor = self
            .descriptor(reference)
            .map_err(processing)?
            .ok_or_else(|| {
                processing(DsigError::InvalidRequest {
                    reason: "Reference instruction is not authenticated by selected Signature",
                })
            })?;
        if self.session.replay_active.get() {
            return Err(processing(DsigError::InvalidRequest {
                reason: "reentrant replay would reset the active transform chain",
            }));
        }
        let index = {
            let mut records = self.session.replays.borrow_mut();
            let index = records.len();
            records
                .try_push(ReplayRecord {
                    signature: self.session.evidence.signatures()[self.index].identity,
                    reference,
                    state: ReplayState::Pending,
                })
                .map_err(|error| processing(error.into()))?;
            debug_assert_eq!(records[index].reference, reference);
            debug_assert_eq!(
                records[index].signature,
                self.session.evidence.signatures()[self.index].identity
            );
            index
        };
        self.session.replay_active.set(true);
        let admission = AdmittedReplay {
            records: &self.session.replays,
            active: &self.session.replay_active,
            index,
        };
        let result = self.replay_instruction(descriptor, mode, receiver);
        admission.finish(&result);
        result
    }

    fn replay_instruction<E>(
        &self,
        descriptor: AuthenticatedReference<'_>,
        mode: ReplayMode,
        receiver: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<ReplayOutcome, ReplayError<E>> {
        let processing = ReplayError::Processing;
        let node = self
            .session
            .view
            .resolve_node(descriptor.identity)
            .map_err(|error| processing(error.into()))?;
        let uri = descriptor.uri.ok_or_else(|| {
            processing(DsigError::Reference(ReferenceProcessingError::MissingUri))
        })?;
        if !self.session.context.policy.uris.references.allows(uri) {
            return Err(processing(
                crate::policy::PolicyViolation::Uri {
                    operation: "reference replay",
                    reason: "reference URI class is not permitted",
                }
                .into(),
            ));
        }
        let allowed = self
            .session
            .context
            .policy
            .transforms
            .allowed_algorithms
            .as_ref();
        for transforms in node
            .children()
            .filter(|child| child.has_tag_name((XMLDSIG_NS, "Transforms")))
        {
            for transform in transforms.children().filter(Node::is_element) {
                self.session
                    .work
                    .charge_work(1)
                    .map_err(|error| processing(error.into()))?;
                if let Some(algorithm) = transform.attribute("Algorithm") {
                    self.session
                        .work
                        .charge_work(algorithm.len() as u64)
                        .map_err(|error| processing(error.into()))?;
                    enforce_transform_allowed(allowed, algorithm).map_err(processing)?;
                }
            }
        }
        let transforms = super::super::parse::parse_replay_transforms(
            node,
            &mut self.session.budgets.xpath_parse.borrow_mut(),
        )
        .map_err(|error| processing(DsigError::ParseManifestReference(error)))?;
        if matches!(mode, ReplayMode::ReferenceOutput)
            && !transform_chain_produces_binary(
                classify_uri(uri) == UriClass::External,
                &transforms,
            )
        {
            enforce_transform_allowed(allowed, DEFAULT_IMPLICIT_C14N_URI).map_err(processing)?;
        }
        let timestamp = match mode {
            ReplayMode::ReferenceOutput => None,
            ReplayMode::Timestamp(method) => {
                let method = self
                    .session
                    .view
                    .resolve_node(method)
                    .map_err(|error| processing(error.into()))?;
                let uri = method.attribute("Algorithm").ok_or_else(|| {
                    processing(DsigError::InvalidStructure {
                        reason: "timestamp method has no Algorithm",
                    })
                })?;
                enforce_transform_allowed(
                    self.session
                        .context
                        .policy
                        .transforms
                        .allowed_algorithms
                        .as_ref(),
                    uri,
                )
                .map_err(processing)?;
                let algorithm =
                    super::super::parse::parse_replay_canonicalization_method(method)
                        .map_err(|error| processing(DsigError::ParseManifestReference(error)))?;
                Some(algorithm)
            }
        };
        let budget = &self.session.budgets.transforms;
        let Some(data) = self.session.resolver.replay_input_from_with_budget(
            uri,
            node,
            budget.node_set_materialization(),
            budget.xml_base_resolution(),
        )?
        else {
            return Ok(ReplayOutcome::Unavailable(ExternalResourceUnavailable {
                reference: descriptor.identity,
            }));
        };
        super::super::transforms::replay_reference_transforms(
            node,
            self.signature().map_err(processing)?,
            data,
            &transforms,
            self.session.context.transform_options(),
            budget,
            |data, explicit, budget| {
                let mut output = ReplayWriter {
                    work: self.session.work,
                    budget,
                    receiver,
                    failure: None,
                };
                let result = match data {
                    super::super::TransformData::Binary(bytes) => {
                        use std::io::Write;
                        output.write_all(&bytes).map_err(crate::c14n::C14nError::Io)
                    }
                    super::super::TransformData::BorrowedBinary(bytes) => {
                        use std::io::Write;
                        output.write_all(bytes).map_err(crate::c14n::C14nError::Io)
                    }
                    super::super::TransformData::NodeSet(nodes) => {
                        let implicit =
                            crate::c14n::C14nAlgorithm::from_uri(DEFAULT_IMPLICIT_C14N_URI)
                                .expect("constant C14N URI");
                        let algorithm = explicit
                            .or(timestamp.as_ref().map(|(algorithm, _)| algorithm))
                            .unwrap_or(&implicit);
                        let prefix_list = if explicit.is_none() {
                            timestamp.as_ref().and_then(|(_, prefixes)| *prefixes)
                        } else {
                            None
                        };
                        crate::c14n::canonicalize_visible_to_writer_accounted(
                            nodes.document(),
                            Some(&nodes),
                            algorithm,
                            super::super::transforms::replay_output_limit(budget),
                            budget.xml_base_resolution(),
                            &mut output,
                            self.session.work,
                            prefix_list,
                        )
                    }
                };
                if let Some(error) = output.failure {
                    return Err(error);
                }
                result.map_err(|error| {
                    processing(match error {
                        crate::c14n::C14nError::SharedExecution(error) => error.into(),
                        error => error.into(),
                    })
                })
            },
        )?;
        Ok(ReplayOutcome::Complete)
    }
}
