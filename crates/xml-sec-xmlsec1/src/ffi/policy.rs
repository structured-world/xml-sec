//! The policy under which the library's own work runs: the snapshots the
//! document tree publishes ([`xml_sec_libxml2::policy`]), so a chain the
//! caller executes and the documents it works on are bounded by the same
//! budgets and XML input rules as a core operation, and sign and verify
//! under its algorithm, key and HMAC rules.

use std::cell::Cell;
use std::ffi::{c_char, c_void};
use std::sync::Arc;

use super::errors::{self, Here};

use xml_sec::policy::{
    DecryptionPolicy, EncryptionPolicy, ResourcePolicy, SigningPolicy, VerificationPolicy,
};
use xml_sec::xmldsig::UriTypeSet;

/// The current verification snapshot; `None` when it cannot be compiled.
pub(crate) fn verification() -> Option<Arc<VerificationPolicy>> {
    xml_sec_libxml2::policy::library()
}

/// [`verification`] for the entry point at `here`, which reports the
/// failure when the profile is unavailable.
pub(crate) fn verification_at(here: Here) -> Option<Arc<VerificationPolicy>> {
    let policy = verification();
    if policy.is_none() {
        errors::policy_unavailable(here);
    }
    policy
}

/// One revision of both snapshots, pinned for one operation: a `KeyInfo` read
/// or a run of a transform context reads every policy value from it, so a
/// republish during the operation never changes the rules under it.
#[derive(Clone)]
pub(crate) struct Pinned {
    pub(crate) verification: Arc<VerificationPolicy>,
    pub(crate) signing: Arc<SigningPolicy>,
    pub(crate) encryption: Arc<EncryptionPolicy>,
    pub(crate) decryption: Arc<DecryptionPolicy>,
}

impl Pinned {
    /// The current revision, reported at `here` when the profile is
    /// unavailable.
    pub(crate) fn current(here: Here) -> Option<Self> {
        let Some(snapshots) = xml_sec_libxml2::policy::snapshots() else {
            errors::policy_unavailable(here);
            return None;
        };
        Some(Self {
            verification: snapshots.verification,
            signing: snapshots.signing,
            encryption: snapshots.encryption,
            decryption: snapshots.decryption,
        })
    }

    /// The snapshot of this revision that governs work on `side`.
    pub(crate) fn of(&self, side: Side) -> OperationPolicy<'_> {
        match side {
            Side::Verify => OperationPolicy::Verify(&self.verification),
            Side::Sign => OperationPolicy::Sign(&self.signing),
            Side::Encrypt => OperationPolicy::Encrypt(&self.encryption),
            Side::Decrypt => OperationPolicy::Decrypt(&self.decryption),
        }
    }
}

/// The operation a run of a transform chain serves, as libxmlsec1 marks each
/// transform with its operation: signing when one of its transforms signs (a
/// signature method, or a reference's digest method set to sign), encryption
/// or decryption when its cipher, wrap or transport does, verification
/// otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    Verify,
    Sign,
    Encrypt,
    Decrypt,
}

/// The snapshot of one side of a pinned revision.
#[derive(Clone, Copy)]
pub(crate) enum OperationPolicy<'a> {
    Verify(&'a VerificationPolicy),
    Sign(&'a SigningPolicy),
    Encrypt(&'a EncryptionPolicy),
    Decrypt(&'a DecryptionPolicy),
}

impl<'a> OperationPolicy<'a> {
    /// The resource ceilings of the operation.
    pub(crate) fn resources(self) -> &'a ResourcePolicy {
        match self {
            Self::Verify(policy) => &policy.resources,
            Self::Sign(policy) => &policy.resources,
            Self::Encrypt(policy) => &policy.resources,
            Self::Decrypt(policy) => &policy.resources,
        }
    }

    /// The key derivation, agreement and encapsulation rules of the
    /// operation.
    pub(crate) fn key_establishment(self) -> &'a xml_sec::policy::KeyEstablishmentPolicy {
        match self {
            Self::Verify(policy) => &policy.key_establishment,
            Self::Sign(policy) => &policy.key_establishment,
            Self::Encrypt(policy) => &policy.key_establishment,
            Self::Decrypt(policy) => &policy.key_establishment,
        }
    }

    /// How the operation reads a key name element.
    pub(crate) fn key_names(self) -> xml_sec::policy::KeyNameSemantics {
        match self {
            Self::Verify(policy) => policy.xml.key_names,
            Self::Sign(policy) => policy.xml.key_names,
            Self::Encrypt(policy) => policy.xml.key_names,
            Self::Decrypt(policy) => policy.xml.key_names,
        }
    }

    /// The URI-class permissions of the operation.
    fn uris(self) -> xml_sec::policy::UriPolicy {
        match self {
            Self::Verify(policy) => policy.uris,
            Self::Sign(policy) => policy.uris,
            Self::Encrypt(policy) => policy.uris,
            Self::Decrypt(policy) => policy.uris,
        }
    }

    /// The URI classes the operation admits for a signature's references, a
    /// `CipherReference` or the resource an encryption reads by URI.
    pub(crate) fn references(self) -> UriTypeSet {
        self.uris().references
    }

    /// The URI classes the operation admits for a `RetrievalMethod` of the
    /// key it reads.
    pub(crate) fn retrieval_methods(self) -> UriTypeSet {
        self.uris().retrieval_methods
    }

    /// The URI classes the operation admits for a `KeyInfoReference` of the
    /// key it reads.
    pub(crate) fn key_info_references(self) -> UriTypeSet {
        self.uris().key_info_references
    }
}

/// `$body` with `$policy` bound to the snapshot `$operation` selects, typed
/// as that policy, for a call that takes `&impl XmlDocumentPolicy`.
macro_rules! with_document_policy {
    ($operation:expr, |$policy:ident| $body:expr) => {
        match $operation {
            $crate::ffi::policy::OperationPolicy::Verify($policy) => $body,
            $crate::ffi::policy::OperationPolicy::Sign($policy) => $body,
            $crate::ffi::policy::OperationPolicy::Encrypt($policy) => $body,
            $crate::ffi::policy::OperationPolicy::Decrypt($policy) => $body,
        }
    };
}
pub(crate) use with_document_policy;

/// What one operation has spent of the policy's per-operation budgets,
/// carried from one transform run it drives to the next, as the core
/// charges one budget across a whole operation.
#[derive(Clone, Copy, Default)]
pub(crate) struct Spent {
    pub(crate) base64_input: usize,
    pub(crate) base64_output: usize,
    /// Octets read from external resources through the input callbacks.
    pub(crate) external_resources: usize,
    /// Octets handed to the XML parser, of `max_xml_parse_work_bytes`.
    pub(crate) xml_parse: usize,
    /// `XPath` expressions evaluated, of `max_xpath_expressions`.
    pub(crate) xpath_expressions: usize,
    /// The key derivation work reserved of the key establishment limits.
    pub(crate) key_establishment: xml_sec::key_establishment::KeyEstablishmentUsage,
    /// The limit that refused work of the operation: its budget is spent,
    /// so the operation ends wherever its parts hand it back.
    pub(crate) refused_by: Option<super::transforms::ctx::Limit>,
    /// Whether the keys the operation recovered were recovered validly,
    /// consulted only once its content work is done.
    pub(crate) recovery: xml_sec::provider::RecoveryValidity,
    /// The side of the operation that uses the keys its `KeyInfo` reads
    /// find, fixed by its outermost read and handed to nested ones.
    pub(crate) serves: Option<Side>,
}

/// The key candidates one `KeyInfo` read has inspected of the policy's
/// `max_key_candidates`, across every key-store search it makes.
#[derive(Clone, Copy)]
pub(crate) struct KeyCandidates {
    pub(crate) inspected: usize,
    /// A search was refused for the allowance; the read fails rather than
    /// taking the refusal for a missing key.
    pub(crate) exhausted: bool,
    /// The `max_key_candidates` of the operation the read is a part of, which
    /// bounds the read with its own; unbounded for a read of its own.
    operation_max: usize,
}

impl Default for KeyCandidates {
    fn default() -> Self {
        Self {
            inspected: 0,
            exhausted: false,
            operation_max: usize::MAX,
        }
    }
}

impl KeyCandidates {
    /// These candidates, read as a part of an operation whose policy allows
    /// `max`.
    pub(crate) fn within(self, max: usize) -> Self {
        Self {
            operation_max: self.operation_max.min(max),
            ..self
        }
    }

    /// Charges one more candidate within `max`, the read's allowance, and the
    /// operation's; refused, marked exhausted and reported for `object` at
    /// `here` once either is spent.
    pub(crate) fn charge(&mut self, max: usize, here: Here, object: *const c_char) -> bool {
        let max = max.min(self.operation_max);
        if self.inspected >= max {
            self.exhausted = true;
            errors::limit_exceeded(here, object, "max_key_candidates", max);
            return false;
        }
        // Below `max`, so the count cannot overflow.
        self.inspected += 1;
        true
    }
}

/// What a context's reserved slot holds during an operation: its policy
/// revision and what its runs have spent so far.
struct Operation {
    pinned: Pinned,
    spent: Cell<Spent>,
    key_candidates: Cell<KeyCandidates>,
}

/// A pin in a context's reserved slot for one call: the outermost call of an
/// operation pins the current revision and its guard releases it on return,
/// unwinding included; nested calls find the pin and leave it.
pub(crate) struct SlotPin {
    slot: *mut *mut c_void,
    owned: bool,
}

impl SlotPin {
    /// Pins the current revision into `slot` unless it holds one.
    ///
    /// # Safety
    /// `slot` is a context's reserved slot, null or a pin, that outlives
    /// the guard.
    pub(crate) unsafe fn hold(slot: *mut *mut c_void, here: Here) -> Option<Self> {
        // SAFETY: by the caller's contract.
        unsafe {
            if !(*slot).is_null() {
                return Some(Self { slot, owned: false });
            }
            Some(Self::hold_pinned(
                slot,
                Pinned::current(here)?,
                Spent::default(),
                KeyCandidates::default(),
            ))
        }
    }

    /// Pins `pinned` into `slot` unless it holds a pin, so the read sees the
    /// revision of the operation that makes it and counts on from `spent`
    /// and `candidates`, what that operation spent before it.
    ///
    /// # Safety
    /// As for [`SlotPin::hold`].
    pub(crate) unsafe fn hold_pinned(
        slot: *mut *mut c_void,
        pinned: Pinned,
        spent: Spent,
        candidates: KeyCandidates,
    ) -> Self {
        // SAFETY: by the caller's contract.
        unsafe {
            if !(*slot).is_null() {
                return Self { slot, owned: false };
            }
            let operation = Operation {
                pinned,
                spent: Cell::new(spent),
                key_candidates: Cell::new(candidates),
            };
            *slot = Box::into_raw(Box::new(operation)).cast();
        }
        Self { slot, owned: true }
    }
}

impl Drop for SlotPin {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: the slot holds the pin `hold` boxed and nothing else
            // released it.
            unsafe { release(self.slot) };
        }
    }
}

/// Frees the pin in `slot`, if any, and empties it.
///
/// # Safety
/// `slot` is a context's reserved slot, null or a pin.
pub(crate) unsafe fn release(slot: *mut *mut c_void) {
    // SAFETY: by the caller's contract.
    unsafe {
        if !(*slot).is_null() {
            drop(Box::from_raw((*slot).cast::<Operation>()));
            *slot = std::ptr::null_mut();
        }
    }
}

/// The policy revision the pin in `slot` holds, if any.
///
/// # Safety
/// `slot` is null or a pin that outlives the borrow.
pub(crate) unsafe fn pinned<'a>(slot: *mut c_void) -> Option<&'a Pinned> {
    // SAFETY: by the caller's contract.
    unsafe { slot.cast::<Operation>().as_ref() }.map(|operation| &operation.pinned)
}

/// What the operation pinned in `slot` has spent so far, if one is pinned.
///
/// # Safety
/// As for [`pinned`].
pub(crate) unsafe fn spent<'a>(slot: *mut c_void) -> Option<&'a Cell<Spent>> {
    // SAFETY: by the caller's contract.
    unsafe { slot.cast::<Operation>().as_ref() }.map(|operation| &operation.spent)
}

/// The key candidates the operation pinned in `slot` has inspected, if one
/// is pinned.
///
/// # Safety
/// As for [`pinned`].
pub(crate) unsafe fn key_candidates<'a>(slot: *mut c_void) -> Option<&'a Cell<KeyCandidates>> {
    // SAFETY: by the caller's contract.
    unsafe { slot.cast::<Operation>().as_ref() }.map(|operation| &operation.key_candidates)
}

/// `xsPolicyRestrict`: narrows the library's published snapshots by profile
/// `profile` of the `xml-sec-config` document in the `dataSize` bytes at
/// `data`, every operation's in one republish. Each call narrows what the
/// previous ones left; nothing widens the `XmlSecCompatible` ceiling, and a
/// context's enabled transforms and key data narrow further on top. Returns 0,
/// or -1 after a report, publishing nothing.
///
/// # Safety
/// `data` holds `size` bytes; `profile` is a NUL-terminated string.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xsPolicyRestrict(
    data: *const u8,
    size: usize,
    profile: *const c_char,
) -> std::ffi::c_int {
    super::contain(-1, || {
        let here = super::errors::here!("xsPolicyRestrict");
        for (failed, expression) in [
            (data.is_null(), c"data != NULL"),
            (size == 0, c"dataSize > 0"),
            (profile.is_null(), c"profile != NULL"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: the caller's `size` bytes and string.
        let (bytes, name) = unsafe {
            (
                std::slice::from_raw_parts(data, size),
                std::ffi::CStr::from_ptr(profile),
            )
        };
        let refuse = |message: &str| {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_DATA,
                message,
            );
            -1
        };
        let Ok(name) = name.to_str() else {
            return refuse("the profile name is not UTF-8");
        };
        let config = match xml_sec_config::Configuration::from_reader(
            bytes,
            xml_sec_config::LoadLimits::default(),
        ) {
            Ok(config) => config,
            Err(error) => return refuse(&error.to_string()),
        };
        // The deployment's layer stays in force: every later setter's
        // snapshots are narrowed by it again before they are published.
        let name = name.to_owned();
        let restriction = Arc::new(move |own: &xml_sec_libxml2::policy::Snapshots| {
            restricted(&config, &name, own)
        });
        match xml_sec_libxml2::policy::restrict(restriction) {
            Some(Ok(())) => 0,
            Some(Err(error)) => refuse(&error),
            None => {
                errors::policy_unavailable(here);
                -1
            }
        }
    })
}

/// The snapshots of `current` narrowed by profile `name` of `config`.
///
/// The composition only intersects, so the result is the library's ceiling
/// or less; each operation's own validation (limits against the hard
/// ceilings, consistent trust and key settings) runs on it, as every
/// operation runs it before work. The profile compiler's checks are not
/// rerun: the ceiling deliberately signs with what it verifies, SHA-1
/// methods included, as libxmlsec1 does, which a compiled profile refuses.
fn restricted(
    config: &xml_sec_config::Configuration,
    name: &str,
    current: &xml_sec_libxml2::policy::Snapshots,
) -> Result<xml_sec_libxml2::policy::Snapshots, String> {
    use xml_sec::policy::{PolicyCompiler, PolicyProfile, PolicySet};
    let ceiling = PolicySet {
        verification: Some(VerificationPolicy::clone(&current.verification)),
        signing: Some(SigningPolicy::clone(&current.signing)),
        encryption: Some(EncryptionPolicy::clone(&current.encryption)),
        decryption: Some(DecryptionPolicy::clone(&current.decryption)),
    };
    let compiler = PolicyCompiler::from_policies(
        PolicyProfile::XmlSecCompatible,
        xml_sec::provider::default_provider(),
        ceiling,
    );
    let narrowed = config
        .restrict(name, compiler)
        .map_err(|error| error.to_string())?;
    let PolicySet {
        verification: Some(verification),
        signing: Some(signing),
        encryption: Some(encryption),
        decryption: Some(decryption),
    } = narrowed.policies().clone()
    else {
        return Err(format!(
            "profile {name} disables an operation the library runs"
        ));
    };
    let invalid = |error: xml_sec::policy::PolicyViolation| error.to_string();
    verification.validate().map_err(invalid)?;
    signing.validate().map_err(invalid)?;
    encryption.validate().map_err(invalid)?;
    decryption.validate().map_err(invalid)?;
    Ok(xml_sec_libxml2::policy::Snapshots {
        verification: Arc::new(verification),
        signing: Arc::new(signing),
        encryption: Arc::new(encryption),
        decryption: Arc::new(decryption),
    })
}

#[cfg(test)]
mod tests;

/// Publishes the current snapshots with the edits applied, as a libxmlsec1
/// setter of a policy value does; `None` when the profile cannot be
/// compiled.
pub(crate) fn republish(
    edit_verification: impl FnOnce(&mut VerificationPolicy),
    edit_signing: impl FnOnce(&mut SigningPolicy),
) -> Option<()> {
    xml_sec_libxml2::policy::republish(edit_verification, edit_signing)
}
