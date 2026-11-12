//! The policy under which the library's own work runs: the snapshots the
//! document tree publishes ([`xml_sec_libxml2::policy`]), so a chain the
//! caller executes and the documents it works on are bounded by the same
//! budgets and XML input rules as a core operation, and sign and verify
//! under its algorithm, key and HMAC rules.

use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Arc;

use super::errors::{self, Here};

use xml_sec::policy::{SigningPolicy, VerificationPolicy};

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
}

impl Pinned {
    /// The current revision, reported at `here` when the profile is
    /// unavailable.
    pub(crate) fn current(here: Here) -> Option<Self> {
        let Some((verification, signing)) = xml_sec_libxml2::policy::snapshot() else {
            errors::policy_unavailable(here);
            return None;
        };
        Some(Self {
            verification,
            signing,
        })
    }
}

/// What one operation has spent of the policy's per-operation budgets,
/// carried from one transform run it drives to the next, as the core
/// charges one budget across a whole operation.
#[derive(Clone, Copy, Default)]
pub(crate) struct Spent {
    pub(crate) base64_input: usize,
    pub(crate) base64_output: usize,
    /// Octets read from external resources through the input callbacks.
    pub(crate) external_resources: usize,
}

/// The key candidates one `KeyInfo` read has inspected of the policy's
/// `max_key_candidates`, across every key-store search it makes.
#[derive(Clone, Copy, Default)]
pub(crate) struct KeyCandidates {
    pub(crate) inspected: usize,
    /// A search was refused for the allowance; the read fails rather than
    /// taking the refusal for a missing key.
    pub(crate) exhausted: bool,
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
            let operation = Operation {
                pinned: Pinned::current(here)?,
                spent: Cell::default(),
                key_candidates: Cell::default(),
            };
            *slot = Box::into_raw(Box::new(operation)).cast();
        }
        Some(Self { slot, owned: true })
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

/// Publishes the current snapshots with the edits applied, as a libxmlsec1
/// setter of a policy value does; `None` when the profile cannot be
/// compiled.
pub(crate) fn republish(
    edit_verification: impl FnOnce(&mut VerificationPolicy),
    edit_signing: impl FnOnce(&mut SigningPolicy),
) -> Option<()> {
    xml_sec_libxml2::policy::republish(edit_verification, edit_signing)
}
