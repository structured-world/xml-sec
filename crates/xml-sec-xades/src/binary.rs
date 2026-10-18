//! Base64 values and certificate digests through the verified operation.

use crate::signature::{MD5, any_uri};
use crate::{Document, Error, Snapshot};
use structured_asn1::memory::Work;
use structured_asn1::{Parser, Reader};
use structured_cms::provider::Resolution;
use structured_xades::binary::{BinaryXml, Decoded};
use structured_xades::certificate::DigestProvider;
use structured_xades::hashes::HashClass;
use structured_xades::xml::{Access, Name};
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

/// A resolved XML digest method of a signed certificate reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestIdentity {
    /// MD5, recognized whatever the XMLDSig digest policy and build support,
    /// so that EN 319 132-1 §6.2.1 classifies it. It is never computed.
    Md5,
    /// A digest xml-sec implements and the operation policy permits.
    Digest(DigestAlgorithm),
}

impl<'s, 'view, 'scope, 'inputs, W: Work> DigestProvider<Document<'s, 'view, 'scope, 'inputs, W>>
    for Document<'s, 'view, 'scope, 'inputs, W>
{
    type Identity = DigestIdentity;
    type Error = Error;

    fn resolve<Q: Work>(
        &self,
        access: &Access<'_, Self, Q>,
        method: NodeIdentity,
    ) -> Result<Resolution<DigestIdentity>, Error> {
        self.check(access.snapshot())?;
        let work = access.execution();
        // The format prohibition precedes deployment policy: an XMLDSig policy
        // or build without MD5 must not turn a prohibited method into a policy
        // error or an unsupported one.
        let md5 = self.with_attribute(
            method,
            Name {
                namespace: "",
                local: "Algorithm",
            },
            work,
            |value| value.is_some_and(|value| any_uri(value) == MD5),
        )?;
        if md5 {
            return Ok(Resolution::Supported(DigestIdentity::Md5));
        }
        Ok(match self.session.resolve_digest_method_in(method, work)? {
            DigestMethodResolution::Supported(algorithm) => {
                Resolution::Supported(DigestIdentity::Digest(algorithm))
            }
            DigestMethodResolution::Unsupported => Resolution::Unsupported,
            DigestMethodResolution::Malformed => Resolution::Malformed,
        })
    }

    fn classify(&self, identity: &DigestIdentity) -> HashClass {
        match identity {
            DigestIdentity::Md5 => HashClass::Md5,
            DigestIdentity::Digest(algorithm) => crate::signature::hash_class(*algorithm),
        }
    }

    fn width(&self, identity: &DigestIdentity) -> Option<usize> {
        Some(match identity {
            DigestIdentity::Md5 => 16,
            DigestIdentity::Digest(algorithm) => algorithm.output_len(),
        })
    }

    fn matches<Q: Work>(
        &self,
        identity: &DigestIdentity,
        certificate: &[u8],
        expected: &[u8],
        execution: &Q,
    ) -> Result<bool, Error> {
        let DigestIdentity::Digest(algorithm) = identity else {
            return Err(Error::ProhibitedDigest);
        };
        let digest = self.session.digest_in(*algorithm, certificate, execution)?;
        execution.charge_work(digest.len() as u64)?;
        Ok(constant_time_eq(&digest, expected))
    }
}
