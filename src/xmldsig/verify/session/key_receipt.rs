//! Unforgeable, callback-scoped successful-key association.

use super::{
    CatalogueError, DsigError, NodeIdentity, SelectedSignature, VerifiedSession, Work,
    flatten_catalogue,
};
pub use crate::provider::KeyAssociation;

/// Receipt of the original selected provider's successful leaf decision.
/// Private fields prevent construction from certificate metadata or fingerprints.
/// The public material and provider identity cannot outlive this callback.
pub struct SelectedKeyReceipt<'a> {
    seal: &'a [u8; 1],
    signature: NodeIdentity,
    provider: &'a dyn crate::provider::CryptoProvider,
    public: Option<&'a [u8]>,
    binding: Option<&'a crate::provider::ProviderBinding>,
}

impl SelectedKeyReceipt<'_> {
    /// Original Signature and document generation, not a detached certificate ID.
    #[must_use]
    pub fn signature(&self) -> NodeIdentity {
        self.signature
    }

    /// Exact selected engine name; this is not a trust or FIPS approval claim.
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Whether the provider supplied public material for this successful key.
    /// False does not mean that an opaque/hardware-backed key failed verification.
    #[must_use]
    pub fn has_public_evidence(&self) -> bool {
        self.public.is_some()
    }
}

impl<W: Work> VerifiedSession<'_, '_, '_, W> {
    /// Associate an original authenticated Signature's successful key using only
    /// the supplied current query execution. Selection, receipt gates, provider
    /// comparison and callback admission all charge `work`, never the completed
    /// verification's producer-local execution. Retained storage keeps its
    /// original account; no Reference catalogue, resolver or verifier is run.
    ///
    /// The original document/generation, policy, provider and terminal capture
    /// cause remain binding. `Same` is key association, not certificate trust.
    ///
    /// # Errors
    /// Returns a processing error for foreign or unauthenticated identities,
    /// capture failure, account/budget refusal, or provider association failure.
    /// Preserves the visitor's original error separately.
    pub fn with_key_association_in<Q: Work, R, E>(
        &self,
        signature: NodeIdentity,
        expected: structured_pkix::path::WorkingKey<'_>,
        work: &Q,
        visitor: impl FnOnce(KeyAssociation) -> Result<R, E>,
    ) -> Result<R, CatalogueError<E>> {
        let index = self
            .authenticated_signature_in(signature, work)
            .map_err(CatalogueError::Processing)?;
        flatten_catalogue(self.with_key_receipt_at_in(index, work, |receipt| {
            let outcome = self
                .associate_receipt_in(index, &receipt, expected, work)
                .map_err(CatalogueError::Processing)?;
            visitor(outcome).map_err(CatalogueError::Visitor)
        }))
    }

    fn with_key_receipt_at_in<Q: Work, R, E>(
        &self,
        index: usize,
        work: &Q,
        visitor: impl for<'a> FnOnce(SelectedKeyReceipt<'a>) -> Result<R, E>,
    ) -> Result<R, CatalogueError<E>> {
        self.signature_method_in(index, work)
            .map_err(CatalogueError::Processing)?;
        work.charge_work(1)
            .map_err(|error| CatalogueError::Processing(error.into()))?;
        let capture = &self.operations[index].capture;
        let key = capture.key.borrow();
        visitor(SelectedKeyReceipt {
            seal: &capture.seal,
            signature: self.evidence.signatures()[index].identity,
            provider: self.context.provider,
            public: key.public.as_deref(),
            binding: key.binding.as_ref(),
        })
        .map_err(CatalogueError::Visitor)
    }

    fn associate_receipt_in<Q: Work>(
        &self,
        index: usize,
        receipt: &SelectedKeyReceipt<'_>,
        expected: structured_pkix::path::WorkingKey<'_>,
        work: &Q,
    ) -> Result<KeyAssociation, DsigError> {
        work.charge_work(1)?;
        let capture = &self.operations[index].capture;
        if !core::ptr::eq(
            core::ptr::from_ref(receipt.seal),
            core::ptr::from_ref(&capture.seal),
        ) || receipt.signature != self.evidence.signatures()[index].identity
            || !core::ptr::eq(receipt.provider, self.context.provider)
        {
            return Err(DsigError::InvalidRequest {
                reason: "key receipt belongs to another selected operation",
            });
        }
        let domain_matches = match (receipt.binding, receipt.provider.binding()) {
            (None, None) => true,
            (Some(key), Some(provider)) => key.matches(provider),
            _ => false,
        };
        if receipt.public.is_some() && !domain_matches {
            return Err(crate::provider::ProviderError::External(
                crate::provider::ExternalProviderError::Binding,
            )
            .into());
        }
        let outcome = match receipt.public {
            Some(public) => {
                receipt
                    .provider
                    .associate_verification_key(public, expected, &|cost| work.charge_work(cost))?
            }
            None => KeyAssociation::Unproven,
        };
        work.charge_work(1)?;
        Ok(outcome)
    }
}

impl<W: Work, Q: Work> SelectedSignature<'_, '_, '_, '_, W, Q> {
    /// Borrow the original successful-key receipt using this selection's Work.
    /// A provider unable to report a unique leaf yields an unproven receipt.
    ///
    /// # Errors
    /// Returns a processing error for an invalid selection, retained capture
    /// refusal, or exhausted query work. Preserves the visitor's error separately.
    pub fn with_key_receipt<R, E>(
        &self,
        visitor: impl for<'a> FnOnce(SelectedKeyReceipt<'a>) -> Result<R, E>,
    ) -> Result<R, CatalogueError<E>> {
        self.session
            .with_key_receipt_at_in(self.index, self.work, visitor)
    }

    /// Associate the exact original key decision using this selection's Work.
    /// A receipt from another operation, generation, Signature or provider is
    /// rejected before the provider comparison or the caller's callback.
    /// For a new query execution, use [`VerifiedSession::with_key_association_in`]
    /// directly, without first performing session-billed Signature selection.
    ///
    /// # Errors
    /// Returns a processing error for an invalid selection or receipt, exhausted
    /// query work, or failed provider comparison. Preserves the visitor's error.
    pub fn associate_key<R, E>(
        &self,
        receipt: &SelectedKeyReceipt<'_>,
        expected: structured_pkix::path::WorkingKey<'_>,
        visitor: impl FnOnce(KeyAssociation) -> Result<R, E>,
    ) -> Result<R, CatalogueError<E>> {
        self.signature_method()
            .map_err(CatalogueError::Processing)?;
        let outcome = self
            .session
            .associate_receipt_in(self.index, receipt, expected, self.work)
            .map_err(CatalogueError::Processing)?;
        visitor(outcome).map_err(CatalogueError::Visitor)
    }
}
