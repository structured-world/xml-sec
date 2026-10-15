//! Unforgeable, callback-scoped successful-key association.

use super::*;
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
    pub fn signature(&self) -> NodeIdentity {
        self.signature
    }

    /// Exact selected engine name; this is not a trust or FIPS approval claim.
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Whether the provider supplied public material for this successful key.
    /// False does not mean that an opaque/hardware-backed key failed verification.
    pub fn has_public_evidence(&self) -> bool {
        self.public.is_some()
    }
}

impl<W: Work> SelectedSignature<'_, '_, '_, '_, W> {
    /// Borrow the original successful-key receipt without resolving or verifying
    /// again. A provider unable to report a unique leaf yields an unproven receipt.
    pub fn with_key_receipt<R, E>(
        &self,
        visitor: impl for<'a> FnOnce(SelectedKeyReceipt<'a>) -> Result<R, E>,
    ) -> Result<R, CatalogueError<E>> {
        self.signature_method()
            .map_err(CatalogueError::Processing)?;
        self.session
            .work
            .charge_work(1)
            .map_err(|error| CatalogueError::Processing(error.into()))?;
        let capture = &self.session.operations[self.index].capture;
        let key = capture.key.borrow();
        visitor(SelectedKeyReceipt {
            seal: &capture.seal,
            signature: self.session.evidence.signatures()[self.index].identity,
            provider: self.session.context.provider,
            public: key.public.as_deref(),
            binding: key.binding.as_ref(),
        })
        .map_err(CatalogueError::Visitor)
    }

    /// Associate the exact original key decision with caller-supplied PKIX state.
    /// A receipt from another operation, generation, Signature or provider is
    /// rejected before the provider comparison or the caller's callback.
    pub fn associate_key<R, E>(
        &self,
        receipt: &SelectedKeyReceipt<'_>,
        expected: structured_pkix::path::WorkingKey<'_>,
        visitor: impl FnOnce(KeyAssociation) -> Result<R, E>,
    ) -> Result<R, CatalogueError<E>> {
        self.signature_method()
            .map_err(CatalogueError::Processing)?;
        let capture = &self.session.operations[self.index].capture;
        if !std::ptr::eq(receipt.seal, &capture.seal)
            || receipt.signature != self.session.evidence.signatures()[self.index].identity
            || !std::ptr::eq(receipt.provider, self.session.context.provider)
        {
            return Err(CatalogueError::Processing(DsigError::InvalidRequest {
                reason: "key receipt belongs to another selected operation",
            }));
        }
        let domain_matches = match (receipt.binding, receipt.provider.binding()) {
            (None, None) => true,
            (Some(key), Some(provider)) => key.matches(provider),
            _ => false,
        };
        if receipt.public.is_some() && !domain_matches {
            return Err(CatalogueError::Processing(
                crate::provider::ProviderError::External(
                    crate::provider::ExternalProviderError::Binding,
                )
                .into(),
            ));
        }
        let outcome = match receipt.public {
            Some(public) => receipt
                .provider
                .associate_verification_key(public, expected, &|cost| {
                    self.session.work.charge_work(cost)
                })
                .map_err(CatalogueError::Processing)?,
            None => KeyAssociation::Unproven,
        };
        self.session
            .work
            .charge_work(1)
            .map_err(|error| CatalogueError::Processing(error.into()))?;
        visitor(outcome).map_err(CatalogueError::Visitor)
    }
}
