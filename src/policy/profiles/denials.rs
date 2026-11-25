//! Permissions a deployment withdraws from a profile without restating it.

use super::{PolicyCompiler, PolicySet};
use crate::policy::{KeySourceKind, PolicyViolation, TransformPolicy, UriPolicy};
use crate::xmldsig::{DigestAlgorithm, SignatureAlgorithm, UriClass, UriTypeSet};
use alloc::{collections::BTreeSet, string::String};

/// Permissions withdrawn from whatever profile or layers a [`PolicyCompiler`]
/// holds: transforms, signature and digest methods, key sources and reference
/// URI classes, in every operation that has them.
///
/// A denial is one more restrictive layer. It removes the named permission and
/// nothing else, and it cannot grant one: denying a method the profile already
/// refuses changes nothing.
///
/// ```
/// use xml_sec::policy::{Denials, KeySourceKind, PolicyCompileContext, PolicyCompiler, PolicyProfile};
/// use xml_sec::provider::RustCryptoProvider;
///
/// let denials = Denials {
///     transforms: ["http://www.w3.org/2002/06/xmldsig-filter2".into()].into(),
///     key_sources: vec![KeySourceKind::KeyName],
///     ..Denials::default()
/// };
/// let policies = PolicyCompiler::new(PolicyProfile::XadesExtended, &RustCryptoProvider, None)?
///     .deny(&denials)?
///     .compile(&PolicyCompileContext { external_resources: false, target_evidence: true })?;
/// let verification = policies.verification().expect("enabled verification");
/// assert!(!verification.key_sources.contains(KeySourceKind::KeyName));
/// # Ok::<(), xml_sec::policy::PolicyViolation>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Denials {
    /// Transform and canonicalization URIs no operation may run.
    pub transforms: BTreeSet<String>,
    /// Signature methods no operation may use. Each withdraws every method of
    /// its URI: denying one RSA-PSS tuple withdraws every parameterization.
    pub signature_algorithms: BTreeSet<SignatureAlgorithm>,
    /// Digest methods no operation may use.
    pub digest_algorithms: BTreeSet<DigestAlgorithm>,
    /// Verification key sources withdrawn.
    pub key_sources: alloc::vec::Vec<KeySourceKind>,
    /// URI classes no `Reference` (or `CipherReference`) may name.
    pub reference_uri_classes: alloc::vec::Vec<UriClass>,
}

impl Denials {
    /// Whether this withdraws nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    fn transforms(&self, policy: &mut TransformPolicy) {
        if self.transforms.is_empty() {
            return;
        }
        let admitted = policy.allowed_algorithms.take().unwrap_or_else(|| {
            crate::xmldsig::transforms::implemented_transform_uris()
                .map(String::from)
                .collect()
        });
        policy.allowed_algorithms = Some(
            admitted
                .into_iter()
                .filter(|uri| !self.transforms.contains(uri))
                .collect(),
        );
    }

    fn uris(&self, policy: &mut UriPolicy) {
        let denied = |class| self.reference_uri_classes.contains(&class);
        let set = policy.references;
        policy.references = UriTypeSet::new(
            set.allows("") && !denied(UriClass::Empty),
            set.allows("#id") && !denied(UriClass::SameDocument),
            set.allows("external") && !denied(UriClass::External),
        );
    }
}

/// The methods `admitted` grants, or with `None` every method `accepts`
/// grants, without the denied ones.
fn without<T: Copy + Ord>(
    admitted: Option<&BTreeSet<T>>,
    all: &[T],
    accepts: impl Fn(T) -> bool,
    denied: &BTreeSet<T>,
) -> Option<BTreeSet<T>> {
    if denied.is_empty() {
        return admitted.cloned();
    }
    let granted: BTreeSet<T> = match admitted {
        Some(set) => set.clone(),
        None => all
            .iter()
            .copied()
            .filter(|value| accepts(*value))
            .collect(),
    };
    Some(granted.difference(denied).copied().collect())
}

impl PolicySet {
    /// These policies with `denials` withdrawn: the layer [`PolicyCompiler::deny`]
    /// restricts by.
    fn without(&self, denials: &Denials) -> Self {
        let mut layer = self.clone();
        // A signature method is withdrawn as its own record rather than by
        // removing it from the admitted list: the RSA-PSS family grant
        // admits tuples no list holds, and a list rebuilt from the fixed
        // methods would lose them.
        if let Some(policy) = layer.verification.as_mut() {
            policy
                .denied_signature_algorithms
                .extend(denials.signature_algorithms.iter().copied());
            policy.digest_algorithms = without(
                policy.digest_algorithms.as_ref(),
                &DigestAlgorithm::ALL,
                |method| policy.check_digest_algorithm(method).is_ok(),
                &denials.digest_algorithms,
            );
            for source in &denials.key_sources {
                policy.key_sources.remove(*source);
            }
            denials.transforms(&mut policy.transforms);
            denials.uris(&mut policy.uris);
        }
        if let Some(policy) = layer.signing.as_mut() {
            policy
                .denied_signature_algorithms
                .extend(denials.signature_algorithms.iter().copied());
            policy.digest_algorithms = without(
                policy.digest_algorithms.as_ref(),
                &DigestAlgorithm::ALL,
                |method| policy.check_digest_algorithm(method).is_ok(),
                &denials.digest_algorithms,
            );
            denials.transforms(&mut policy.transforms);
            denials.uris(&mut policy.uris);
        }
        #[cfg(feature = "xmlenc")]
        if let Some(policy) = layer.decryption.as_mut() {
            denials.transforms(&mut policy.transforms);
            denials.uris(&mut policy.uris);
        }
        layer
    }
}

impl PolicyCompiler<'_> {
    /// Withdraw `denials` from the profile and layers composed so far, as one
    /// more restrictive layer.
    ///
    /// # Errors
    /// Returns the composition's configuration violation, as
    /// [`Self::restrict`] does.
    pub fn deny(self, denials: &Denials) -> Result<Self, PolicyViolation> {
        if denials.is_empty() {
            return Ok(self);
        }
        let layer = self.policies.without(denials);
        self.restrict(&layer)
    }
}
