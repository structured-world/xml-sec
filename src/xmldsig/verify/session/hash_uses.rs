//! Paid projection of original selected signature and digest decisions.

use super::*;

/// The instruction's exact hash role, independent of payload acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashUseRole {
    /// External digest of canonical SignedInfo, or an intrinsic signature suite.
    SignatureMessage,
    /// RSA-PSS's separately selected MGF1 hash.
    MaskGeneration,
    /// Digest of an authenticated Reference's transformed object.
    Reference(ReferenceParent),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_method_has_explicit_message_hash_semantics() {
        // A newly advertised signature method must not silently disappear from
        // algorithm projection, including pure experimental suites.
        for algorithm in SignatureAlgorithm::ALL {
            assert!(
                !matches!(message_hash(algorithm), HashUseAlgorithm::Unsupported(_)),
                "{algorithm:?}"
            );
        }
    }
}

/// Declared hash semantics; output length never determines the algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashUseAlgorithm<'a> {
    /// A recognized fixed-output digest.
    Digest(DigestAlgorithm),
    /// RFC 8032 Ed448ph's SHAKE256 prehash with a 64-byte output.
    Shake256_512,
    /// No independently selected external digest (e.g. PureEdDSA or pure ML-DSA).
    Intrinsic(SignatureAlgorithm),
    /// Original unimplemented/malformed instruction, including an absent URI.
    Unsupported(Option<&'a str>),
}

/// Whether this original role actually completed its hash operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashUseState {
    /// The original operation successfully computed the digest or signature suite.
    Complete,
    /// Original algorithm semantics could not be projected.
    Unsupported,
    /// Declared instructions were not completed, regardless of the reason.
    Unprocessed,
}

/// One original role, never reconstructed from result lengths or key metadata.
#[derive(Debug)]
pub struct SignatureHashUse<'a> {
    /// Original selected Signature, including document and generation.
    pub signature: NodeIdentity,
    /// Original SignatureMethod or Reference instruction.
    pub instruction: NodeIdentity,
    /// Original method element, absent only for a malformed Reference layout.
    pub method: Option<NodeIdentity>,
    /// Semantic role and, for Reference, exact authenticated parent.
    pub role: HashUseRole,
    /// Declared typed algorithm or original unsupported spelling.
    pub algorithm: HashUseAlgorithm<'a>,
    /// Actual original execution disposition, not a payload/trust verdict.
    pub state: HashUseState,
}

/// Overall completeness; every individual role retains its own disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashUseCompleteness {
    /// Every original authenticated role was projected and completed.
    Complete,
    /// An original role cannot be interpreted by this release.
    Unsupported(NodeIdentity),
    /// At least one original authenticated instruction was not completed.
    Unprocessed(NodeIdentity),
}

fn message_hash(algorithm: SignatureAlgorithm) -> HashUseAlgorithm<'static> {
    if let Some(parameters) = algorithm.rsa_pss_parameters() {
        return HashUseAlgorithm::Digest(parameters.digest);
    }
    if let Some(digest) = algorithm.ecdsa_digest() {
        return HashUseAlgorithm::Digest(digest);
    }
    use DigestAlgorithm as D;
    use SignatureAlgorithm as S;
    let digest = match algorithm {
        S::RsaSha1 | S::DsaSha1 | S::HmacSha1 => D::Sha1,
        S::RsaSha224 | S::HmacSha224 => D::Sha224,
        S::RsaSha256 | S::DsaSha256 | S::HmacSha256 => D::Sha256,
        S::RsaSha384 | S::HmacSha384 => D::Sha384,
        S::RsaSha512 | S::HmacSha512 | S::Ed25519Ph => D::Sha512,
        #[cfg(feature = "legacy-algorithms")]
        S::RsaMd5 | S::HmacMd5 => D::Md5,
        #[cfg(feature = "legacy-algorithms")]
        S::RsaRipemd160 | S::HmacRipemd160 => D::Ripemd160,
        // RFC 8032 §§3,5.1,5.2: PureEdDSA has PH(M)=M; Ed448ph uses
        // SHAKE256(M,64), not SHA3-512 or a digest inferred from 64 bytes.
        // https://www.rfc-editor.org/rfc/rfc8032#section-5.2
        S::Ed448Ph => return HashUseAlgorithm::Shake256_512,
        S::Ed25519 | S::Ed25519Ctx | S::Ed448 | S::PostQuantum(_) => {
            return HashUseAlgorithm::Intrinsic(algorithm);
        }
        _ => return HashUseAlgorithm::Unsupported(Some(algorithm.uri())),
    };
    HashUseAlgorithm::Digest(digest)
}

// A method (rather than a captured closure) accepts each attribute's fresh
// scoped lifetime without retaining its spelling or allocating an owned copy.
struct ReferenceHashVisitor<'a, W, F> {
    signature: NodeIdentity,
    instruction: NodeIdentity,
    parent: ReferenceParent,
    completed: bool,
    work: &'a W,
    completeness: &'a mut HashUseCompleteness,
    visitor: &'a mut F,
}

impl<W: Work, F> ReferenceHashVisitor<'_, W, F> {
    fn emit<E>(
        &mut self,
        algorithm: HashUseAlgorithm<'_>,
        method: Option<NodeIdentity>,
    ) -> Result<(), CatalogueError<E>>
    where
        F: for<'a> FnMut(SignatureHashUse<'a>) -> Result<(), E>,
    {
        let state = if matches!(algorithm, HashUseAlgorithm::Unsupported(_)) {
            *self.completeness = HashUseCompleteness::Unsupported(self.instruction);
            HashUseState::Unsupported
        } else if self.completed {
            HashUseState::Complete
        } else {
            if matches!(self.completeness, HashUseCompleteness::Complete) {
                *self.completeness = HashUseCompleteness::Unprocessed(self.instruction);
            }
            HashUseState::Unprocessed
        };
        self.work
            .charge_work(1)
            .map_err(|error| CatalogueError::Processing(error.into()))?;
        (self.visitor)(SignatureHashUse {
            signature: self.signature,
            instruction: self.instruction,
            method,
            role: HashUseRole::Reference(self.parent),
            algorithm,
            state,
        })
        .map_err(CatalogueError::Visitor)
    }
}

impl<W: Work> SelectedSignature<'_, '_, '_, '_, W> {
    /// Original typed method captured during the first successful verification.
    pub fn signature_method(&self) -> Result<SelectedSignatureMethod, DsigError> {
        self.session.work.charge_work(1)?;
        self.operation().validate_document_view(self.session.view)?;
        let capture = &self.session.operations[self.index].capture;
        if let Some(error) = capture.failure.get() {
            return Err(error.into());
        }
        capture.method.get().ok_or(DsigError::InvalidRequest {
            reason: "selected Signature has no original method receipt",
        })
    }

    /// Visit declared original roles and their actual original completion state.
    /// This neither verifies again nor resolves keys or resources again.
    pub fn visit_hash_uses<E>(
        &self,
        mut visitor: impl for<'a> FnMut(SignatureHashUse<'a>) -> Result<(), E>,
    ) -> Result<HashUseCompleteness, CatalogueError<E>> {
        let method = self
            .signature_method()
            .map_err(CatalogueError::Processing)?;
        let signature = self.session.evidence.signatures()[self.index].identity;
        let mut completeness = HashUseCompleteness::Complete;
        let algorithm = message_hash(method.algorithm);
        let state = if matches!(algorithm, HashUseAlgorithm::Unsupported(_)) {
            completeness = HashUseCompleteness::Unsupported(method.identity);
            HashUseState::Unsupported
        } else {
            HashUseState::Complete
        };
        self.session
            .work
            .charge_work(1)
            .map_err(|error| CatalogueError::Processing(error.into()))?;
        visitor(SignatureHashUse {
            signature,
            instruction: method.identity,
            method: Some(method.identity),
            role: HashUseRole::SignatureMessage,
            algorithm,
            state,
        })
        .map_err(CatalogueError::Visitor)?;
        // RFC 9231 §2.3.9 and RFC 8017 §9.1: MGF1's digest is independent
        // of the message digest. Use the originally parsed effective parameters.
        // https://www.rfc-editor.org/rfc/rfc9231#section-2.3.9
        if let Some(parameters) = method.algorithm.rsa_pss_parameters() {
            self.session
                .work
                .charge_work(1)
                .map_err(|error| CatalogueError::Processing(error.into()))?;
            visitor(SignatureHashUse {
                signature,
                instruction: method.identity,
                method: Some(method.identity),
                role: HashUseRole::MaskGeneration,
                algorithm: HashUseAlgorithm::Digest(parameters.mgf_digest),
                state: HashUseState::Complete,
            })
            .map_err(CatalogueError::Visitor)?;
        }
        let catalogue = self.visit_reference_instructions(|node, parent, method| {
            let reference = self.session.view.node_identity(node);
            let digest_receipt = self.session.operations[self.index]
                .capture
                .digests
                .borrow()
                .get(&node.id().get_usize(), self.session.work)
                .map_err(|error| CatalogueError::Processing(error.into()))?
                .copied();
            let mut emitter = ReferenceHashVisitor {
                signature,
                instruction: reference,
                parent,
                completed: digest_receipt.is_some_and(|receipt| receipt.computed),
                work: self.session.work,
                completeness: &mut completeness,
                visitor: &mut visitor,
            };
            let Some(method) = method else {
                return emitter.emit(HashUseAlgorithm::Unsupported(None), None);
            };
            let method_identity = self.session.view.node_identity(method);
            if let Some(receipt) = digest_receipt {
                return emitter.emit(
                    HashUseAlgorithm::Digest(receipt.algorithm),
                    Some(method_identity),
                );
            }
            let mut found = false;
            let inspected = super::super::super::extension::visit_direct_attributes(
                self.session.view,
                method_identity,
                self.session.work,
                |attribute| {
                    if attribute.namespace.is_none() && attribute.local_name == "Algorithm" {
                        found = true;
                        // Bound every possible registry comparison before interpreting
                        // an instruction the original execution never parsed.
                        let comparisons = DigestAlgorithm::ALL
                            .iter()
                            .map(|algorithm| algorithm.uri().len() as u64 + 1)
                            .sum();
                        self.session
                            .work
                            .charge_work(comparisons)
                            .map_err(|error| CatalogueError::Processing(error.into()))?;
                        let algorithm = DigestAlgorithm::from_uri(attribute.value).map_or(
                            HashUseAlgorithm::Unsupported(Some(attribute.value)),
                            HashUseAlgorithm::Digest,
                        );
                        emitter.emit(algorithm, Some(method_identity))?;
                    }
                    Ok(())
                },
            );
            match inspected {
                Ok(()) => {}
                Err(super::super::super::extension::InspectionError::Visitor(error)) => {
                    return Err(error);
                }
                Err(super::super::super::extension::InspectionError::Processing(error)) => {
                    return Err(CatalogueError::Processing(match error {
                        super::super::super::extension::ScalarError::Resource(error) => {
                            error.into()
                        }
                        super::super::super::extension::ScalarError::Document(error) => {
                            error.into()
                        }
                        super::super::super::extension::ScalarError::NotElement => {
                            DsigError::InvalidRequest {
                                reason: "DigestMethod is not an element",
                            }
                        }
                    }));
                }
            }
            if !found {
                emitter.emit(HashUseAlgorithm::Unsupported(None), Some(method_identity))?;
            }
            Ok(())
        });
        match catalogue {
            Err(CatalogueError::Visitor(error)) => Err(error),
            Err(CatalogueError::Processing(error)) => Err(CatalogueError::Processing(error)),
            Ok(status) => {
                if matches!(completeness, HashUseCompleteness::Complete) {
                    match status {
                        CatalogueCompleteness::Complete => {}
                        CatalogueCompleteness::Incomplete(node)
                        | CatalogueCompleteness::Unchecked(node) => {
                            completeness = HashUseCompleteness::Unprocessed(node)
                        }
                    }
                }
                Ok(completeness)
            }
        }
    }
}
