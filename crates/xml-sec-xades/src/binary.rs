//! Base64 values and certificate digests through the verified operation.

use crate::{Document, Error, Snapshot};
use structured_asn1::memory::Work;
use structured_asn1::{Parser, Reader};
use structured_cms::provider::Resolution;
use structured_xades::binary::{BinaryXml, Decoded};
use structured_xades::certificate::DigestProvider;
use structured_xades::hashes::HashClass;
use structured_xades::xml::Access;
use xml_sec::document::NodeIdentity;
use xml_sec::xmldsig::extension;
use xml_sec::xmldsig::{DigestAlgorithm, DigestMethodResolution, constant_time_eq};

impl<W: Work> BinaryXml for Document<'_, '_, '_, '_, W> {
    fn with_octets<R, C, Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        execution: &Q,
        visitor: impl for<'source> FnOnce(&'source [u8]) -> Result<R, C>,
    ) -> Result<Result<R, C>, Error> {
        self.check(snapshot)?;
        Ok(extension::with_base64(
            self.session.view(),
            node,
            execution,
            visitor,
        )?)
    }

    fn with_binary<R, C>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        operation: &Reader<'_>,
        visitor: impl for<'source> FnOnce(Decoded<'source>) -> Result<R, C>,
    ) -> Result<Result<R, C>, Error> {
        self.check(snapshot)?;
        let execution = operation.execution();
        Ok(extension::with_base64(
            self.session.view(),
            node,
            &execution,
            |bytes| {
                // A freshly decoded source has its own producing session on the
                // operation's account; sharing the account clones only its handle.
                let parser = Parser::der(operation.memory().clone());
                visitor(Decoded {
                    parser: &parser,
                    bytes,
                    base: 0,
                    depth: 0,
                })
            },
        )?)
    }
}

impl<'s, 'view, 'scope, 'inputs, W: Work> DigestProvider<Document<'s, 'view, 'scope, 'inputs, W>>
    for Document<'s, 'view, 'scope, 'inputs, W>
{
    type Identity = DigestAlgorithm;
    type Error = Error;

    fn resolve<Q: Work>(
        &self,
        access: &Access<'_, Self, Q>,
        method: NodeIdentity,
    ) -> Result<Resolution<DigestAlgorithm>, Error> {
        self.check(access.snapshot())?;
        Ok(
            match self
                .session
                .resolve_digest_method_in(method, access.execution())?
            {
                DigestMethodResolution::Supported(algorithm) => Resolution::Supported(algorithm),
                DigestMethodResolution::Unsupported => Resolution::Unsupported,
                DigestMethodResolution::Malformed => Resolution::Malformed,
            },
        )
    }

    fn classify(&self, identity: &DigestAlgorithm) -> HashClass {
        crate::signature::hash_class(*identity)
    }

    fn width(&self, identity: &DigestAlgorithm) -> Option<usize> {
        Some(identity.output_len())
    }

    fn matches<Q: Work>(
        &self,
        identity: &DigestAlgorithm,
        certificate: &[u8],
        expected: &[u8],
        execution: &Q,
    ) -> Result<bool, Error> {
        let digest = self.session.digest_in(*identity, certificate, execution)?;
        execution.charge_work(digest.len() as u64)?;
        Ok(constant_time_eq(&digest, expected))
    }
}
