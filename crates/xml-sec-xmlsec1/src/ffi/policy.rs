//! The policy under which the library's own transform work runs: the core's
//! libxmlsec1-compatible profile compiled for the default provider, so a
//! chain the caller executes is bounded by the same budgets and XML input
//! rules as a core operation.

use std::sync::OnceLock;

use super::errors::{self, Here};

use xml_sec::policy::{
    CompiledPolicies, PolicyCompileContext, PolicyCompiler, PolicyProfile, VerificationPolicy,
};

/// The compiled profile, built once; `None` when it cannot be compiled.
fn compiled() -> Option<&'static CompiledPolicies> {
    static POLICIES: OnceLock<Option<CompiledPolicies>> = OnceLock::new();
    POLICIES
        .get_or_init(|| {
            let provider = xml_sec::provider::default_provider();
            // The library supplies neither external-resource maps nor expected
            // targets to these runs.
            let context = PolicyCompileContext {
                external_resources: false,
                target_evidence: false,
            };
            PolicyCompiler::new(PolicyProfile::XmlSecCompatible, provider, None)
                .ok()?
                .compile(&context)
                .ok()
        })
        .as_ref()
}

/// The verification snapshot of the profile, which bounds XML input,
/// canonical output and transform work.
pub(crate) fn verification() -> Option<&'static VerificationPolicy> {
    compiled()?.verification()
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
