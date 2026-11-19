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
    DecryptionPolicy, EncryptionPolicy, GeneratedCanonicalization, ManifestProcessing,
    PolicyCompileContext, PolicyCompiler, PolicyProfile, SigningPolicy, VerificationPolicy,
};
use xml_sec::provider::ProviderCapability;
use xml_sec::xmldsig::UriTypeSet;

/// The published snapshots of every operation.
struct Published {
    verification: Arc<VerificationPolicy>,
    signing: Arc<SigningPolicy>,
    encryption: Arc<EncryptionPolicy>,
    decryption: Arc<DecryptionPolicy>,
}

/// One revision of every operation's snapshot, taken together.
pub struct Snapshots {
    /// The verification snapshot.
    pub verification: Arc<VerificationPolicy>,
    /// The signing snapshot.
    pub signing: Arc<SigningPolicy>,
    /// The encryption snapshot.
    pub encryption: Arc<EncryptionPolicy>,
    /// The decryption snapshot.
    pub decryption: Arc<DecryptionPolicy>,
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
    // libxmlsec1 processes Manifests unless a context asks it not to; the
    // profile lets a request select either.
    verification.manifest_processing = ManifestProcessing::Process;
    // Signing admits what this boundary verifies, as libxmlsec1 signs with
    // every method it verifies; the xmlsec1 command opts in the same way.
    let mut signing = compiled.signing()?.clone();
    // A detached reference is digested when it is signed, from the same
    // caller-supplied bytes it is verified from.
    signing.uris.references = verification.uris.references;
    signing.manifest_processing = verification.manifest_processing;
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
    // libxmlsec1 signs a template as written: a node set is left to the
    // implicit Canonical XML 1.0 conversion (XMLDSig 1.1 section 4.4.3.2), and
    // a bare-name fragment is looked up as its verification looks it up.
    signing.transforms.generated_canonicalization = GeneratedCanonicalization::Implicit;
    signing.transforms.same_document_id_semantics =
        verification.transforms.same_document_id_semantics;
    let mut decryption = compiled.decryption()?.clone();
    // A CipherReference resolves as a signature's reference does: external
    // URIs from the bytes the caller's input callbacks supply, same-document
    // IDs as libxmlsec1 finds them.
    decryption.uris.references = verification.uris.references;
    decryption.transforms.same_document_id_semantics =
        verification.transforms.same_document_id_semantics;
    // Encryption admits what this boundary decrypts, as libxmlsec1 encrypts
    // with every cipher it decrypts with.
    let mut encryption = compiled.encryption()?.clone();
    encryption.data_algorithms = decryption.data_algorithms.as_ref().map(|ciphers| {
        ciphers
            .iter()
            .copied()
            .filter(|cipher| provider.supports(ProviderCapability::Encrypt(*cipher)))
            .collect()
    });
    encryption
        .key_wrap_algorithms
        .clone_from(&decryption.key_wrap_algorithms);
    encryption
        .key_transport_algorithms
        .clone_from(&decryption.key_transport_algorithms);
    encryption.oaep_digests.clone_from(&decryption.oaep_digests);
    Some(Published {
        verification: Arc::new(verification),
        signing: Arc::new(signing),
        encryption: Arc::new(encryption),
        decryption: Arc::new(decryption),
    })
}

/// Every operation's current snapshot, of one revision; `None` when the
/// profile cannot be compiled.
#[must_use]
pub fn snapshots() -> Option<Snapshots> {
    current(|published| Snapshots {
        verification: Arc::clone(&published.verification),
        signing: Arc::clone(&published.signing),
        encryption: Arc::clone(&published.encryption),
        decryption: Arc::clone(&published.decryption),
    })
}

/// The current snapshot `select` picks, compiled on first use; `None` when
/// the profile cannot be compiled.
fn current<R>(select: impl Fn(&Published) -> R) -> Option<R> {
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

/// The current verification and signing snapshots, of one revision: an
/// operation that may need both takes them together, so a republish between
/// two reads never hands it a mixed pair. `None` when the profile cannot be
/// compiled.
#[must_use]
pub fn snapshot() -> Option<(Arc<VerificationPolicy>, Arc<SigningPolicy>)> {
    current(|published| {
        (
            Arc::clone(&published.verification),
            Arc::clone(&published.signing),
        )
    })
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
    let current = snapshots()?;
    let mut verification = VerificationPolicy::clone(&current.verification);
    let mut signing = SigningPolicy::clone(&current.signing);
    edit_verification(&mut verification);
    edit_signing(&mut signing);
    *PUBLISHED.write().ok()? = Some(Published {
        verification: Arc::new(verification),
        signing: Arc::new(signing),
        encryption: current.encryption,
        decryption: current.decryption,
    });
    Some(())
}

/// [`republish`] for the encryption and decryption snapshots.
pub fn republish_encryption(
    edit_encryption: impl FnOnce(&mut EncryptionPolicy),
    edit_decryption: impl FnOnce(&mut DecryptionPolicy),
) -> Option<()> {
    let _turn = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let current = snapshots()?;
    let mut encryption = EncryptionPolicy::clone(&current.encryption);
    let mut decryption = DecryptionPolicy::clone(&current.decryption);
    edit_encryption(&mut encryption);
    edit_decryption(&mut decryption);
    *PUBLISHED.write().ok()? = Some(Published {
        verification: current.verification,
        signing: current.signing,
        encryption: Arc::new(encryption),
        decryption: Arc::new(decryption),
    });
    Some(())
}

#[cfg(test)]
mod tests;
