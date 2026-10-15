//! Original execution facts retained only by scoped verification.

use super::*;
use structured_asn1::memory::{MemoryError, OwnedMap, Work};

/// Original parsed method, not a reconstruction from an algorithm URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedSignatureMethod {
    /// Original SignatureMethod node, including document generation.
    pub identity: NodeIdentity,
    /// Parsed signature algorithm, including effective RSA-PSS parameters.
    pub algorithm: SignatureAlgorithm,
}

pub(super) trait VerificationCapture {
    fn method(
        &self,
        _view: DocumentView<'_>,
        _signed_info: Node<'_, '_>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<(), MemoryError> {
        Ok(())
    }
    fn admit_digest(
        &self,
        _reference: Option<NodeId>,
        _algorithm: DigestAlgorithm,
    ) -> Result<(), MemoryError> {
        Ok(())
    }
    fn computed_digest(&self, _reference: Option<NodeId>) -> Result<(), MemoryError> {
        Ok(())
    }
}

impl VerificationCapture for () {}

#[derive(Clone, Copy)]
pub(super) struct CapturedDigest {
    pub(super) algorithm: DigestAlgorithm,
    pub(super) computed: bool,
}

pub(super) struct ScopedCapture<'work, W: Work> {
    pub(super) method: Cell<Option<SelectedSignatureMethod>>,
    // Arena ordinals are private to the retained original operation, never
    // compared across parses or exposed as public provenance.
    pub(super) digests: RefCell<OwnedMap<usize, CapturedDigest, W>>,
    pub(super) failure: Cell<Option<MemoryError>>,
    work: &'work W,
}

impl<'work, W: Work> ScopedCapture<'work, W> {
    pub(super) fn new(work: &'work W) -> Self {
        Self {
            method: Cell::new(None),
            digests: RefCell::new(work.map()),
            failure: Cell::new(None),
            work,
        }
    }

    fn retain_failure<T>(&self, result: Result<T, MemoryError>) -> Result<T, MemoryError> {
        if let Err(error) = result
            && self.failure.get().is_none()
        {
            self.failure.set(Some(error));
        }
        result
    }
}

impl<W: Work> VerificationCapture for ScopedCapture<'_, W> {
    fn method(
        &self,
        view: DocumentView<'_>,
        signed_info: Node<'_, '_>,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), MemoryError> {
        self.retain_failure((|| {
            for child in signed_info.children() {
                self.work.charge_work(64)?;
                if child.has_tag_name((XMLDSIG_NS, "SignatureMethod")) {
                    self.method.set(Some(SelectedSignatureMethod {
                        identity: view.node_identity(child),
                        algorithm,
                    }));
                    break;
                }
            }
            Ok(())
        })())
    }

    fn admit_digest(
        &self,
        reference: Option<NodeId>,
        algorithm: DigestAlgorithm,
    ) -> Result<(), MemoryError> {
        self.retain_failure((|| {
            if let Some(reference) = reference {
                self.digests.borrow_mut().try_insert(
                    reference.get_usize(),
                    CapturedDigest {
                        algorithm,
                        computed: false,
                    },
                )?;
            }
            Ok(())
        })())
    }

    fn computed_digest(&self, reference: Option<NodeId>) -> Result<(), MemoryError> {
        self.retain_failure((|| {
            if let Some(reference) = reference {
                let mut digests = self.digests.borrow_mut();
                let completed = digests
                    .get_mut(&reference.get_usize(), self.work)?
                    .expect("digest admitted before execution");
                completed.computed = true;
            }
            Ok(())
        })())
    }
}

pub(super) struct CapturedOperation<P, B, C> {
    pub(super) operation: OperationExecutionContext<P, B>,
    pub(super) capture: C,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};

    #[test]
    fn first_receipt_resource_failure_stays_terminal() {
        // Manifest recovery must not replace an earlier allocator/capacity
        // cause with a later work error while continuing other instructions.
        let work = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
        let capture = ScopedCapture::new(&work);
        assert!(
            capture
                .retain_failure(Err::<(), _>(MemoryError::LimitExceeded))
                .is_err()
        );
        assert!(
            capture
                .retain_failure(Err::<(), _>(MemoryError::WorkExceeded))
                .is_err()
        );
        assert_eq!(capture.failure.get(), Some(MemoryError::LimitExceeded));
    }
}
