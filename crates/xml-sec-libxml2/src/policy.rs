//! The policy of the library's own work: the core's libxmlsec1-compatible
//! profile compiled for the default provider. Documents the tree functions
//! parse and the libxmlsec1 interfaces built over them run under it, so they
//! are bounded by the same budgets and XML input rules as a core operation.

use std::sync::OnceLock;

use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile, VerificationPolicy};
use xml_sec::xmldsig::UriTypeSet;

/// The verification snapshot of the profile, built once; `None` when it
/// cannot be compiled.
///
/// The library is a compatibility boundary, as the xmlsec1 command is: it
/// admits external reference URIs, which libxmlsec1 reads, and resolves them
/// only from bytes the caller supplies, the caller-owned resource contract
/// the compilation declares. The profile itself keeps same-document
/// references, so the permission is granted here rather than by any profile
/// a core caller selects.
pub fn library() -> Option<&'static VerificationPolicy> {
    // no-std: once_cell::race::OnceBox
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
