//! The policy of the library's own work: the core's libxmlsec1-compatible
//! profile compiled for the default provider. Documents the tree functions
//! parse and the libxmlsec1 interfaces built over them run under it, so they
//! are bounded by the same budgets and XML input rules as a core operation,
//! and sign and verify under its algorithm, key and HMAC rules.
//!
//! The library publishes one immutable snapshot of each operation's policy
//! at a time. Each entry point takes the current snapshot once and uses it
//! for its whole run, so a run never sees two revisions; a libxmlsec1 setter
//! that changes a policy value builds complete replacements from the current
//! snapshots and publishes them ([`republish`]).

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use xml_sec::policy::{
    PolicyCompileContext, PolicyCompiler, PolicyProfile, SigningPolicy, VerificationPolicy,
};
use xml_sec::provider::ProviderCapability;
use xml_sec::xmldsig::UriTypeSet;

/// The published snapshots of both operations.
struct Published {
    verification: Arc<VerificationPolicy>,
    signing: Arc<SigningPolicy>,
}

// no-std: spin::RwLock
static PUBLISHED: RwLock<Option<Published>> = RwLock::new(None);

/// The turn of a republishing caller, held from reading the current
/// snapshots to publishing their replacements.
// no-std: spin::Mutex
static WRITER: Mutex<()> = Mutex::new(());

/// The profile compiled for the default provider; `None` when it cannot be
/// compiled.
///
/// The library is a compatibility boundary, as the xmlsec1 command is: it
/// admits external reference URIs, which libxmlsec1 reads, and resolves them
/// only from bytes the caller supplies, the caller-owned resource contract
/// the compilation declares. The profile itself keeps same-document
/// references, so the permission is granted here rather than by any profile
/// a core caller selects.
fn compile() -> Option<Published> {
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
    let mut verification = compiled.verification()?.clone();
    verification.uris.references = UriTypeSet::ALL;
    // Signing admits what this boundary verifies, as libxmlsec1 signs with
    // every method it verifies; the xmlsec1 command opts in the same way.
    let mut signing = compiled.signing()?.clone();
    signing.signature_algorithms = verification.signature_algorithms.as_ref().map(|methods| {
        methods
            .iter()
            .copied()
            .filter(|method| provider.supports(ProviderCapability::Sign(*method)))
            .collect()
    });
    signing
        .digest_algorithms
        .clone_from(&verification.digest_algorithms);
    signing.parameterized_rsa_pss = verification.parameterized_rsa_pss;
    signing.hmac = verification.hmac;
    Some(Published {
        verification: Arc::new(verification),
        signing: Arc::new(signing),
    })
}

/// The current snapshot `select` picks, compiled on first use; `None` when
/// the profile cannot be compiled.
fn current<T>(select: impl Fn(&Published) -> Arc<T>) -> Option<Arc<T>> {
    if let Some(published) = PUBLISHED.read().ok()?.as_ref() {
        return Some(select(published));
    }
    let mut slot = PUBLISHED.write().ok()?;
    if slot.is_none() {
        *slot = compile();
    }
    slot.as_ref().map(select)
}

/// The current verification snapshot; `None` when the profile cannot be
/// compiled.
#[must_use]
pub fn library() -> Option<Arc<VerificationPolicy>> {
    current(|published| Arc::clone(&published.verification))
}

/// The current signing snapshot; `None` when the profile cannot be
/// compiled.
#[must_use]
pub fn signing() -> Option<Arc<SigningPolicy>> {
    current(|published| Arc::clone(&published.signing))
}

/// Publishes the current snapshots with the edits applied, as complete
/// replacements; runs that already took the previous ones keep them. `None`
/// when the profile cannot be compiled.
///
/// Republishing callers take turns, so no edit is lost to a concurrent one.
/// The edits run on copies without holding the snapshot lock: an edit may
/// read the current snapshots, and one that panics leaves them published
/// unchanged. An edit must not republish itself, which would wait for its
/// own turn.
pub fn republish(
    edit_verification: impl FnOnce(&mut VerificationPolicy),
    edit_signing: impl FnOnce(&mut SigningPolicy),
) -> Option<()> {
    // The lock guards no data, only the turn: a turn whose edit panicked
    // published nothing, so its poison is cleared.
    let _turn = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let (Some(verification), Some(signing)) = (library(), signing()) else {
        return None;
    };
    let mut verification = VerificationPolicy::clone(&verification);
    let mut signing = SigningPolicy::clone(&signing);
    edit_verification(&mut verification);
    edit_signing(&mut signing);
    *PUBLISHED.write().ok()? = Some(Published {
        verification: Arc::new(verification),
        signing: Arc::new(signing),
    });
    Some(())
}

#[cfg(test)]
mod tests;
