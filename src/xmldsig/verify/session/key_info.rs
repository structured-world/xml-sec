//! Key material a verified Signature's `KeyInfo` offered, as verification read it.

use super::super::capture::{RetainedCandidate, RetainedMaterial};
use super::{CatalogueError, DsigError, NodeIdentity, SelectedSignature, VerifiedSession, Work};
use crate::xmldsig::parse::KeyValueInfo;

/// Whether core verification read the Signature's `KeyInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyInfoReading {
    /// The Signature has no `KeyInfo`.
    Absent,
    /// The key came from the caller, a resolver that ignores document hints,
    /// or a recipient mechanism, so `KeyInfo` was not read.
    NotRead,
    /// `KeyInfo` was read under the operation's policy, budgets and provider;
    /// every key material it offered was visited.
    Read,
}

/// Where an offered key material is in the verified document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyInfoOrigin {
    /// Its own element: `X509Certificate`, `KeyValue`, `DEREncodedKeyValue`,
    /// or a `RetrievalMethod` verification did not read.
    Element(NodeIdentity),
    /// Found in a caller-supplied resource read through this
    /// `KeyInfoReference` or `RetrievalMethod`, including a hint an external
    /// `KeyInfo` left unread; the material has no element in this document.
    Retrieved(NodeIdentity),
}

/// Offered key material, borrowed as verification parsed it. Nothing here is
/// trusted or associated with the verifying key.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum KeyInfoMaterial<'a> {
    /// DER certificate from `X509Data` or a raw certificate retrieval.
    Certificate(&'a [u8]),
    /// Public parameters of a `KeyValue`, including ones no supported
    /// algorithm can use.
    KeyValue(&'a KeyValueInfo),
    /// DER `SubjectPublicKeyInfo` of a `dsig11:DEREncodedKeyValue`.
    SubjectPublicKeyInfo(&'a [u8]),
    /// A `RetrievalMethod` whose resource verification did not read: its type
    /// is not materialized, or the caller did not supply the resource.
    Unmaterialized {
        /// Resolved resource identity.
        uri: &'a str,
        /// Declared resource type.
        resource_type: Option<&'a str>,
    },
}

/// One offered key material and where it is.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct KeyInfoCandidate<'a> {
    /// Element or retrieving instruction in the verified document.
    pub origin: KeyInfoOrigin,
    /// The material itself.
    pub material: KeyInfoMaterial<'a>,
}

impl RetainedCandidate {
    fn view(&self) -> KeyInfoCandidate<'_> {
        KeyInfoCandidate {
            origin: self.origin,
            material: match &self.material {
                RetainedMaterial::Certificate(der) => KeyInfoMaterial::Certificate(der),
                RetainedMaterial::KeyValue(value) => KeyInfoMaterial::KeyValue(value),
                RetainedMaterial::SubjectPublicKeyInfo(der) => {
                    KeyInfoMaterial::SubjectPublicKeyInfo(der)
                }
                RetainedMaterial::Unmaterialized { uri, resource_type } => {
                    KeyInfoMaterial::Unmaterialized {
                        uri,
                        resource_type: resource_type.as_deref(),
                    }
                }
            },
        }
    }
}

impl<W: Work> VerifiedSession<'_, '_, '_, W> {
    /// Visit the key material an authenticated Signature's `KeyInfo` offered,
    /// as core verification read it: no second parse, no trust decision.
    /// Sources come in document order, followed by the hints external
    /// `KeyInfo` documents left unread. Selection and each visit charge `work`.
    ///
    /// Returns whether verification read `KeyInfo`; candidates exist only for
    /// [`KeyInfoReading::Read`].
    ///
    /// # Errors
    /// Returns a processing error for foreign or unauthenticated identities,
    /// retained capture failure or exhausted query work. Preserves the
    /// visitor's original error separately.
    pub fn visit_key_info_candidates_in<Q: Work, E>(
        &self,
        signature: NodeIdentity,
        work: &Q,
        visitor: impl for<'a> FnMut(KeyInfoCandidate<'a>) -> Result<(), E>,
    ) -> Result<KeyInfoReading, CatalogueError<E>> {
        let index = self
            .authenticated_signature_in(signature, work)
            .map_err(CatalogueError::Processing)?;
        self.visit_key_info_at_in(index, work, visitor)
    }

    fn visit_key_info_at_in<Q: Work, E>(
        &self,
        index: usize,
        work: &Q,
        mut visitor: impl for<'a> FnMut(KeyInfoCandidate<'a>) -> Result<(), E>,
    ) -> Result<KeyInfoReading, CatalogueError<E>> {
        let retained = self.operations[index].capture.key_info.borrow();
        let Some(retained) = retained.as_ref() else {
            return Err(CatalogueError::Processing(DsigError::InvalidRequest {
                reason: "selected Signature has no retained KeyInfo",
            }));
        };
        for candidate in &retained.candidates {
            work.charge_work(1)
                .map_err(|error| CatalogueError::Processing(error.into()))?;
            visitor(candidate.view()).map_err(CatalogueError::Visitor)?;
        }
        Ok(retained.reading)
    }
}

impl<W: Work, Q: Work> SelectedSignature<'_, '_, '_, '_, W, Q> {
    /// [`VerifiedSession::visit_key_info_candidates_in`] for this selection,
    /// charging its Work.
    ///
    /// # Errors
    /// Returns a processing error for retained capture failure or exhausted
    /// query work. Preserves the visitor's original error separately.
    pub fn visit_key_info_candidates<E>(
        &self,
        visitor: impl for<'a> FnMut(KeyInfoCandidate<'a>) -> Result<(), E>,
    ) -> Result<KeyInfoReading, CatalogueError<E>> {
        self.session
            .visit_key_info_at_in(self.index, self.work, visitor)
    }
}
