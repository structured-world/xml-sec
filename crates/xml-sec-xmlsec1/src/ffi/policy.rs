//! The policy under which the library's own work runs: the one snapshot the
//! document tree owns ([`xml_sec_libxml2::policy::library`]), so a chain the
//! caller executes and the documents it works on are bounded by the same
//! budgets and XML input rules as a core operation.

use super::errors::{self, Here};

use xml_sec::policy::VerificationPolicy;

/// The library's verification snapshot; `None` when it cannot be compiled.
pub(crate) fn verification() -> Option<&'static VerificationPolicy> {
    xml_sec_libxml2::policy::library()
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
