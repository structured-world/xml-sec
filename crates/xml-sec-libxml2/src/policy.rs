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
    PolicyCompileContext, PolicyCompiler, PolicyProfile, PolicySet, SigningPolicy,
    VerificationPolicy,
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
#[derive(Clone)]
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

/// A deployment's narrowing of the library: the snapshots it publishes for
/// the library's own snapshots, or why it refuses them.
pub type Restriction = dyn Fn(&Snapshots) -> Result<Snapshots, String> + Send + Sync;

/// What the published revision is made of: the library's own snapshots,
/// which its setters edit, and the deployment's narrowing applied on top of
/// them once there is one, so no setter reaches past the deployment.
struct Layers {
    own: Snapshots,
    restriction: Option<Arc<Restriction>>,
}

/// The turn of a republishing caller, held from reading the current
/// snapshots to publishing their replacements, and the layers they are made
/// of, taken from the first published revision on the first turn.
// no-std: spin::Mutex
static WRITER: Mutex<Option<Layers>> = Mutex::new(None);

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
    // The verify-only ones among them (SHA-1 and weaker) are signed with by
    // explicit permission, as libxmlsec1 signs with them.
    signing.verify_only_signature_algorithms = signing
        .signature_algorithms
        .iter()
        .flatten()
        .copied()
        .filter(|method| !method.signing_allowed())
        .collect();
    signing
        .digest_algorithms
        .clone_from(&verification.digest_algorithms);
    signing.parameterized_rsa_pss = verification.parameterized_rsa_pss;
    signing.hmac = verification.hmac;
    // An AgreementMethod yielding an HMAC key agrees as its verification does.
    signing
        .key_establishment
        .clone_from(&verification.key_establishment);
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
    // An encryption agrees on keys as the decryption does.
    encryption
        .key_establishment
        .clone_from(&decryption.key_establishment);
    // A resource named to xmlSecEncCtxUriEncrypt is read from the bytes the
    // caller's input callbacks supply, as a CipherReference is; the key's
    // references keep the decryption's classes.
    encryption.uris = decryption.uris;
    // The boundary's own grants are compiled as every policy is, so the
    // ceiling it publishes holds the core's consistency rules.
    let compiled = PolicyCompiler::from_policies(
        PolicyProfile::XmlSecCompatible,
        provider,
        PolicySet {
            verification: Some(verification),
            signing: Some(signing),
            encryption: Some(encryption),
            decryption: Some(decryption),
        },
    )
    .compile(&context)
    .ok()?;
    Some(Published {
        verification: Arc::new(compiled.verification()?.clone()),
        signing: Arc::new(compiled.signing()?.clone()),
        encryption: Arc::new(compiled.encryption()?.clone()),
        decryption: Arc::new(compiled.decryption()?.clone()),
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
///
/// After [`restrict`], the edits change the library's own snapshots and the
/// restriction is applied again on top of them, so a setter never reaches
/// past the deployment; a restriction that refuses the result publishes
/// nothing, and `None` is returned for it too.
pub fn republish(
    edit_verification: impl FnOnce(&mut VerificationPolicy),
    edit_signing: impl FnOnce(&mut SigningPolicy),
) -> Option<()> {
    // The lock guards the restriction and the turn: a turn whose edit
    // panicked published nothing and left the restriction as it was, so its
    // poison is cleared.
    let mut turn = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let layers = layers(&mut turn)?;
    let mut own = layers.own.clone();
    let mut verification = VerificationPolicy::clone(&own.verification);
    let mut signing = SigningPolicy::clone(&own.signing);
    edit_verification(&mut verification);
    edit_signing(&mut signing);
    own.verification = Arc::new(verification);
    own.signing = Arc::new(signing);
    publish(layers, own)?.ok()
}

/// [`republish`] for the encryption and decryption snapshots.
pub fn republish_encryption(
    edit_encryption: impl FnOnce(&mut EncryptionPolicy),
    edit_decryption: impl FnOnce(&mut DecryptionPolicy),
) -> Option<()> {
    let mut turn = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let layers = layers(&mut turn)?;
    let mut own = layers.own.clone();
    let mut encryption = EncryptionPolicy::clone(&own.encryption);
    let mut decryption = DecryptionPolicy::clone(&own.decryption);
    edit_encryption(&mut encryption);
    edit_decryption(&mut decryption);
    own.encryption = Arc::new(encryption);
    own.decryption = Arc::new(decryption);
    publish(layers, own)?.ok()
}

/// Narrows the library by `restriction` from now on: every operation's
/// snapshot in one revision, and again after every later setter, on top of
/// any earlier restriction. A refusal publishes nothing and keeps the
/// restriction in force as it was. `None` when the profile cannot be
/// compiled.
pub fn restrict(restriction: Arc<Restriction>) -> Option<Result<(), String>> {
    let mut turn = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let layers = layers(&mut turn)?;
    let composed: Arc<Restriction> = match &layers.restriction {
        Some(earlier) => {
            let earlier = Arc::clone(earlier);
            Arc::new(move |own: &Snapshots| restriction(&earlier(own)?))
        }
        None => restriction,
    };
    let narrowed = match composed(&effective(&layers.own)) {
        Ok(narrowed) => narrowed,
        Err(error) => return Some(Err(error)),
    };
    *PUBLISHED.write().ok()? = Some(Published::from(narrowed));
    layers.restriction = Some(composed);
    Some(Ok(()))
}

/// The layers of the turn `turn` holds, the library's own snapshots taken
/// from the published revision on the first turn; `None` when the profile
/// cannot be compiled.
fn layers(turn: &mut Option<Layers>) -> Option<&mut Layers> {
    if turn.is_none() {
        *turn = Some(Layers {
            own: snapshots()?,
            restriction: None,
        });
    }
    turn.as_mut()
}

/// Publishes the library's own snapshots `own` as the layers make them: the
/// restriction in force narrows them, or the core compiles them as it
/// compiled the ceiling, so every published revision holds the core's
/// consistency rules; a refusal publishes nothing and keeps the layers.
fn publish(layers: &mut Layers, own: Snapshots) -> Option<Result<(), String>> {
    let effective = effective(&own);
    let published = match &layers.restriction {
        Some(restriction) => restriction(&effective),
        None => compile_snapshots(&effective),
    };
    let published = match published {
        Ok(published) => published,
        Err(error) => return Some(Err(error)),
    };
    layers.own = own;
    *PUBLISHED.write().ok()? = Some(Published::from(published));
    Some(Ok(()))
}

/// The snapshots a revision publishes for the library's own `own`: a
/// signature method whose full HMAC output falls short of its operation's
/// minimum output length is left out of the operation's methods, as
/// libxmlsec1's minimum refuses it when it runs. The own snapshots keep it,
/// so a lower minimum set later admits it again.
fn effective(own: &Snapshots) -> Snapshots {
    let mut effective = own.clone();
    let meets = |minimum: usize| {
        move |method: &xml_sec::xmldsig::SignatureAlgorithm| {
            method.hmac_output_bits().is_none_or(|bits| bits >= minimum)
        }
    };
    let minimum = own.verification.hmac.minimum_output_bits;
    if let Some(methods) = &own.verification.signature_algorithms
        && !methods.iter().all(meets(minimum))
    {
        let mut verification = VerificationPolicy::clone(&own.verification);
        verification.signature_algorithms =
            Some(methods.iter().copied().filter(meets(minimum)).collect());
        effective.verification = Arc::new(verification);
    }
    let minimum = own.signing.hmac.minimum_output_bits;
    if let Some(methods) = &own.signing.signature_algorithms
        && !methods.iter().all(meets(minimum))
    {
        let mut signing = SigningPolicy::clone(&own.signing);
        signing.signature_algorithms =
            Some(methods.iter().copied().filter(meets(minimum)).collect());
        effective.signing = Arc::new(signing);
    }
    effective
}

/// `snapshots` compiled as the library's ceiling is: under its profile, for
/// the default provider, with the caller-owned resources it declares; why
/// the core refuses them otherwise.
fn compile_snapshots(snapshots: &Snapshots) -> Result<Snapshots, String> {
    let context = PolicyCompileContext {
        external_resources: true,
        target_evidence: false,
    };
    let compiled = PolicyCompiler::from_policies(
        PolicyProfile::XmlSecCompatible,
        xml_sec::provider::default_provider(),
        PolicySet {
            verification: Some(VerificationPolicy::clone(&snapshots.verification)),
            signing: Some(SigningPolicy::clone(&snapshots.signing)),
            encryption: Some(EncryptionPolicy::clone(&snapshots.encryption)),
            decryption: Some(DecryptionPolicy::clone(&snapshots.decryption)),
        },
    )
    .compile(&context)
    .map_err(|error| error.to_string())?;
    let missing = || "the compiled policy lacks an operation".to_owned();
    Ok(Snapshots {
        verification: Arc::new(compiled.verification().ok_or_else(missing)?.clone()),
        signing: Arc::new(compiled.signing().ok_or_else(missing)?.clone()),
        encryption: Arc::new(compiled.encryption().ok_or_else(missing)?.clone()),
        decryption: Arc::new(compiled.decryption().ok_or_else(missing)?.clone()),
    })
}

impl From<Snapshots> for Published {
    fn from(snapshots: Snapshots) -> Self {
        Self {
            verification: snapshots.verification,
            signing: snapshots.signing,
            encryption: snapshots.encryption,
            decryption: snapshots.decryption,
        }
    }
}

#[cfg(test)]
mod tests;
