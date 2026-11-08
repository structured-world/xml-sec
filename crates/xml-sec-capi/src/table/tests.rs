use super::{Kind, destroy, insert, use_handle};
use crate::objects::{Failure, Object};
use crate::status::{
    XS_BUSY, XS_DESTROYED_HANDLE, XS_INVALID_ARGUMENT, XS_OK, XS_STALE_HANDLE, XS_WRONG_HANDLE,
};

fn error_object() -> Object {
    Object::Error(Failure::new(XS_OK, "test"))
}

#[test]
fn a_handle_names_only_its_own_kind_and_never_zero() {
    // A handle is checked against the type the caller declared, so passing
    // an error handle where an audit is expected cannot reach the object.
    let handle = insert(error_object()).unwrap();
    assert_ne!(handle, 0);
    assert!(use_handle(handle, Kind::Error).is_ok());
    assert_eq!(use_handle(handle, Kind::Audit).err(), Some(XS_WRONG_HANDLE));
    assert_eq!(destroy(handle, Kind::Audit), Err(XS_WRONG_HANDLE));
    assert_eq!(use_handle(0, Kind::Error).err(), Some(XS_INVALID_ARGUMENT));
    destroy(handle, Kind::Error).unwrap();
}

#[test]
fn destruction_is_reported_until_the_slot_holds_a_newer_object() {
    // A use after destroy is told apart from a stale handle whose slot was
    // reused, and neither can reach the newer object.
    let first = insert(error_object()).unwrap();
    destroy(first, Kind::Error).unwrap();
    assert_eq!(
        use_handle(first, Kind::Error).err(),
        Some(XS_DESTROYED_HANDLE)
    );
    assert_eq!(destroy(first, Kind::Error), Err(XS_DESTROYED_HANDLE));
    let second = insert(error_object()).unwrap();
    assert_ne!(first, second);
    assert_eq!(use_handle(first, Kind::Error).err(), Some(XS_STALE_HANDLE));
    assert_eq!(destroy(first, Kind::Error), Err(XS_STALE_HANDLE));
    assert!(use_handle(second, Kind::Error).is_ok());
    destroy(second, Kind::Error).unwrap();
}

#[test]
fn a_handle_outside_the_table_is_stale() {
    // Forged slot indexes past the table's end are refused, not indexed.
    let forged = (u64::from(Kind::Error as u8) << 56) | (0x00ff_ffff << 32);
    assert_eq!(use_handle(forged, Kind::Error).err(), Some(XS_STALE_HANDLE));
}

#[test]
fn a_forged_type_tag_cannot_reach_or_destroy_another_object() {
    // The slot, not the caller's handle, records the object's type: an error
    // handle relabeled as a provider keeps its slot and generation but is a
    // wrong handle, before and after the error object is destroyed.
    let handle = insert(error_object()).unwrap();
    let relabeled = (handle & 0x00ff_ffff_ffff_ffff) | (u64::from(Kind::Provider as u8) << 56);
    assert_eq!(
        use_handle(relabeled, Kind::Provider).err(),
        Some(XS_WRONG_HANDLE)
    );
    assert_eq!(destroy(relabeled, Kind::Provider), Err(XS_WRONG_HANDLE));
    assert!(use_handle(handle, Kind::Error).is_ok());
    destroy(handle, Kind::Error).unwrap();
    assert_eq!(destroy(relabeled, Kind::Provider), Err(XS_WRONG_HANDLE));
}

#[test]
fn an_unpublished_reservation_returns_its_slot() {
    // A call refused after holding a slot for its output does not leak the
    // slot, and the next object reuses it under a newer generation.
    let held = super::reserve().unwrap();
    drop(held);
    let first = insert(error_object()).unwrap();
    destroy(first, Kind::Error).unwrap();
    let held = super::reserve().unwrap();
    let second = held.publish(error_object());
    assert_eq!(second >> 32, first >> 32);
    assert_ne!(second, first);
    assert_eq!(use_handle(first, Kind::Error).err(), Some(XS_STALE_HANDLE));
    destroy(second, Kind::Error).unwrap();
}

#[test]
fn an_object_in_use_cannot_be_destroyed() {
    // A running call keeps its object; destroying it meanwhile reports busy
    // and leaves the handle valid.
    let handle = insert(error_object()).unwrap();
    let in_use = use_handle(handle, Kind::Error).unwrap();
    assert_eq!(destroy(handle, Kind::Error), Err(XS_BUSY));
    assert!(matches!(in_use.object(), Object::Error(_)));
    drop(in_use);
    destroy(handle, Kind::Error).unwrap();
}
