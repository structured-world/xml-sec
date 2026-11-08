//! The library's handle table: a handle is a validated slot index, generation
//! and type tag, never a pointer the library dereferences.
#![forbid(unsafe_code)]

use crate::objects::Object;
use crate::status::{
    XS_BUSY, XS_DESTROYED_HANDLE, XS_HANDLE_LIMIT, XS_INVALID_ARGUMENT, XS_STALE_HANDLE,
    XS_WRONG_HANDLE, XsStatus,
};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
mod tests;

/// The object type a handle names; its value is the handle's top byte, so a
/// zero handle is never valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    Provider = 1,
    PolicyStore,
    Policy,
    Keys,
    Document,
    Signer,
    Verifier,
    Encryptor,
    Decryptor,
    Evidence,
    Audit,
    Error,
}

/// Slot indexes occupy 24 bits beside the tag and the 32-bit generation.
const MAX_SLOTS: usize = 1 << 24;

/// One object and the calls currently using it.
pub(crate) struct Entry {
    active: AtomicUsize,
    pub(crate) object: Object,
}

struct Slot {
    generation: u32,
    /// The type of the object this generation holds or held; a handle's tag
    /// is checked against it, never trusted alone.
    kind: Kind,
    entry: Option<Arc<Entry>>,
}

struct Table {
    slots: Vec<Slot>,
    /// Destroyed slots whose generation can still advance.
    free: Vec<u32>,
}

static TABLE: Mutex<Table> = Mutex::new(Table {
    slots: Vec::new(),
    free: Vec::new(),
});

fn encode(kind: Kind, index: u32, generation: u32) -> u64 {
    (u64::from(kind as u8) << 56) | (u64::from(index) << 32) | u64::from(generation)
}

/// The tag, slot index and generation of `handle`, without checking the slot.
fn decode(handle: u64) -> (u8, usize, u32) {
    let tag = handle.to_be_bytes()[0];
    let index = usize::try_from((handle >> 32) & 0x00ff_ffff).expect("24 bits fit usize");
    let generation = u32::try_from(handle & u64::from(u32::MAX)).expect("masked to 32 bits");
    (tag, index, generation)
}

/// Publish `object` and return its handle.
pub(crate) fn insert(object: Object) -> Result<u64, XsStatus> {
    Ok(reserve()?.publish(object))
}

/// A slot held for an object a call publishes only once its work has
/// committed, so that publication cannot fail after the work. Dropped
/// unpublished, it releases the slot.
pub(crate) struct Reservation(Option<u32>);

/// Hold a slot for one later object.
pub(crate) fn reserve() -> Result<Reservation, XsStatus> {
    #[cfg(test)]
    if EXHAUSTED.load(Ordering::Relaxed) {
        return Err(XS_HANDLE_LIMIT);
    }
    let mut table = TABLE.lock();
    if let Some(index) = table.free.pop() {
        let slot = &mut table.slots[usize::try_from(index).expect("slot indexes fit usize")];
        // A destroyed slot keeps its generation until reuse, so a handle to
        // the destroyed object reports destroyed, not stale. Cannot overflow:
        // a slot is retired at `u32::MAX` instead of freed.
        slot.generation += 1;
        return Ok(Reservation(Some(index)));
    }
    if table.slots.len() >= MAX_SLOTS {
        return Err(XS_HANDLE_LIMIT);
    }
    let index = u32::try_from(table.slots.len()).expect("fewer than 2^24 slots");
    // No handle names generation 0 of this slot until it is published, so the
    // kind recorded meanwhile is never trusted.
    table.slots.push(Slot {
        generation: 0,
        kind: Kind::Error,
        entry: None,
    });
    Ok(Reservation(Some(index)))
}

impl Reservation {
    /// Publish `object` in the held slot and return its handle.
    pub(crate) fn publish(mut self, object: Object) -> u64 {
        let index = self.0.take().expect("a reservation publishes once");
        let kind = object.kind();
        let entry = Arc::new(Entry {
            active: AtomicUsize::new(0),
            object,
        });
        let mut table = TABLE.lock();
        let slot = &mut table.slots[usize::try_from(index).expect("slot indexes fit usize")];
        slot.kind = kind;
        slot.entry = Some(entry);
        encode(kind, index, slot.generation)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(index) = self.0.take() {
            let mut table = TABLE.lock();
            release(&mut table, index);
        }
    }
}

/// Return an empty slot for reuse, or retire it once its generation is
/// exhausted, so no later handle can match an old one.
fn release(table: &mut Table, index: u32) {
    if table.slots[usize::try_from(index).expect("slot indexes fit usize")].generation != u32::MAX {
        table.free.push(index);
    }
}

/// Makes every reservation fail as a full table would.
#[cfg(test)]
pub(crate) static EXHAUSTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// A call's use of one object; destroying the object meanwhile reports busy.
pub(crate) struct InUse(Arc<Entry>);

impl InUse {
    pub(crate) fn object(&self) -> &Object {
        &self.0.object
    }
}

impl Drop for InUse {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Release);
    }
}

fn locate(table: &Table, handle: u64, kind: Kind) -> Result<&Slot, XsStatus> {
    if handle == 0 {
        return Err(XS_INVALID_ARGUMENT);
    }
    let (tag, index, generation) = decode(handle);
    if tag != kind as u8 {
        return Err(XS_WRONG_HANDLE);
    }
    let slot = table.slots.get(index).ok_or(XS_STALE_HANDLE)?;
    if slot.generation != generation {
        return Err(XS_STALE_HANDLE);
    }
    // A forged tag over a live slot and generation names another type.
    if slot.kind != kind {
        return Err(XS_WRONG_HANDLE);
    }
    Ok(slot)
}

/// Use the object `handle` names for the length of one call.
pub(crate) fn use_handle(handle: u64, kind: Kind) -> Result<InUse, XsStatus> {
    let table = TABLE.lock();
    let entry = locate(&table, handle, kind)?
        .entry
        .as_ref()
        .ok_or(XS_DESTROYED_HANDLE)?;
    entry.active.fetch_add(1, Ordering::Acquire);
    Ok(InUse(Arc::clone(entry)))
}

/// Destroy the object `handle` names. Other objects that hold it keep it
/// alive; a running call using it makes the destruction fail as busy.
pub(crate) fn destroy(handle: u64, kind: Kind) -> Result<(), XsStatus> {
    let released = {
        let mut table = TABLE.lock();
        let index = {
            let slot = locate(&table, handle, kind)?;
            let entry = slot.entry.as_ref().ok_or(XS_DESTROYED_HANDLE)?;
            if entry.active.load(Ordering::Acquire) != 0 {
                return Err(XS_BUSY);
            }
            decode(handle).1
        };
        let released = table.slots[index].entry.take();
        release(
            &mut table,
            u32::try_from(index).expect("slot indexes fit u32"),
        );
        released
    };
    // The object is released outside the lock.
    drop(released);
    Ok(())
}
