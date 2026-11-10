//! The policy under which the library's own transform work runs: the core's
//! libxmlsec1-compatible profile compiled for the default provider, so a
//! chain the caller executes is bounded by the same budgets and XML input
//! rules as a core operation.

use std::sync::OnceLock;

use super::errors::{self, Here};

use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile, VerificationPolicy};
use xml_sec::xmldsig::UriTypeSet;

/// The verification snapshot of the profile, built once; `None` when it
/// cannot be compiled.
///
/// The library is a compatibility boundary, as the xmlsec1 command is: it
/// admits external reference URIs, which libxmlsec1 reads, and resolves them
/// only from bytes the caller supplies through its registered input
/// callbacks, the caller-owned resource contract the compilation declares.
/// The profile itself keeps same-document references, so the permission is
/// granted here rather than by any profile a core caller selects.
pub(crate) fn verification() -> Option<&'static VerificationPolicy> {
    static POLICY: OnceLock<Option<VerificationPolicy>> = OnceLock::new();
    POLICY
        .get_or_init(|| {
            let provider = xml_sec::provider::default_provider();
            // No expected targets reach these runs.
            let context = PolicyCompileContext {
                external_resources: true,
                target_evidence: false,
            };
            let compiled = PolicyCompiler::new(PolicyProfile::XmlSecCompatible, provider, None)
                .ok()?
                .compile(&context)
                .ok()?;
            let mut policy = compiled.verification()?.clone();
            policy.uris.references = UriTypeSet::ALL;
            Some(policy)
        })
        .as_ref()
}

/// [`verification`] for the entry point at `here`, which reports the
/// failure when the profile is unavailable.
pub(crate) fn verification_at(here: Here) -> Option<&'static VerificationPolicy> {
    let policy = verification();
    if policy.is_none() {
        errors::policy_unavailable(here);
    }
    policy
}
