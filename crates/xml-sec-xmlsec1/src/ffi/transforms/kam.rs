//! The built-in provider's key agreement klasses, the transform an
//! `AgreementMethod` element is: `ECDH-ES` over EC keys, `DH-ES` over X9.42
//! DH keys, `x25519` and `x448` over XDH keys.
//!
//! Reading its `AgreementMethod` the transform takes the parameters of the
//! `KeyDerivationMethod` the core parses there and finds the originator's
//! and the recipient's keys through the keys manager of the `KeyInfo` read
//! that runs it: the private key of the side the operation is on and the
//! other party's public key. The keys stay in the context's `ka-params`
//! key data, which the `AgreementMethod` klass carries on to the key it
//! yields so a later write reuses them. It takes no input: on the final call
//! it agrees on the shared secret and derives the width its reader expects
//! through the core under the run's policy, charging the operation's key
//! establishment allowance.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

use xml_sec::policy::{KeyAgreementAlgorithm, PolicyViolation};
use xml_sec::provider::{
    KeyAgreementKey, KeyAgreementParameters, RustCryptoDhKey, RustCryptoEcdhKey, RustCryptoX448Key,
    RustCryptoX25519Key,
};
use xml_sec::xmldsig::{DigestAlgorithm, KeyValueInfo};
use xml_sec::xmlenc::{KeyDerivationMethod, KeyEstablishmentBudget, XmlEncError};

use super::super::asymkeys::{self, Material, material_of};
use super::super::buffer::xmlSecBufferAppend;
use super::super::errors::{self, Here, here};
use super::super::keyinfo::{
    MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx, xmlSecKeyInfoCtxCopyUserPref,
    xmlSecKeyInfoCtxFinalize, xmlSecKeyInfoCtxInitialize, xmlSecKeyInfoNodeWrite,
};
use super::super::keys::{
    TYPE_PRIVATE, TYPE_PUBLIC, XmlSecKey, xmlSecKeyDestroy, xmlSecKeyDuplicate, xmlSecKeyGetValue,
    xmlSecKeyMatch,
};
use super::super::keysdata::{XmlSecKeyData, XmlSecKeyDataKlass, check_id, data_valid};
use super::super::policy::{Side, SlotPin};
use super::super::strings::{
    xmlSecAttrAlgorithm, xmlSecEnc11Ns, xmlSecEncNs, xmlSecHrefDhEs, xmlSecHrefEcdh,
    xmlSecHrefX448, xmlSecHrefX25519, xmlSecNameDhEs, xmlSecNameEcdh, xmlSecNameX448,
    xmlSecNameX25519, xmlSecNodeKANonce, xmlSecNodeKeyDerivationMethod,
    xmlSecNodeOriginatorKeyInfo, xmlSecNodeRecipientKeyInfo,
};
use super::super::tree::{XmlNode, nodes};
use super::super::xdhkeys::{self, Curve, XdhKey};
use super::super::xmltree::{next_element, xmlSecCheckNodeName};
use super::super::{contain, write_stream};
use super::builtin::klass;
use super::ctx::{
    Limit, charge_key_info, enabled_klass, operation_side, run_budget, run_policy, run_spent,
    xmlSecTransformCtxExtraKeyDataEnsure, xmlSecTransformCtxExtraKeyDataGet,
};
use super::kdf::{method_under, parse_method, scope};
use super::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, OPERATION_SIGN, STATUS_FINISHED, STATUS_NONE,
    STATUS_WORKING, USAGE_AGREEMENT_METHOD, USAGE_KEY_DERIVATION_METHOD, WithContext, XmlSecKeyReq,
    XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass, klass_text, valid,
    xmlSecTransformDefaultPopBin, xmlSecTransformDefaultPushBin, xmlSecTransformSetKeyReq,
};

#[cfg(test)]
mod tests;

/// `xmlSecKeyUsageKeyAgreement`.
const KEY_USAGE_KEY_AGREEMENT: c_uint = 0x0000_0040;
/// `xmlSecKeyDataUsageUnknown`.
const DATA_USAGE_UNKNOWN: c_uint = 0;

/// The state of a key agreement.
struct Kam {
    /// The parameters of the `KeyDerivationMethod`, with the side whose
    /// policy they were read under, and its element.
    method: Option<(KeyDerivationMethod, Side)>,
    /// The `KeyDerivationMethod` element, read again when the side the
    /// agreement runs on differs from the one it was read under.
    method_node: *mut XmlNode,
    /// The width a `ConcatKDF` derivation yields when its reader expects
    /// none: the digest's output size, as libxmlsec1 falls back to it.
    default_width: usize,
}

/// An agreement klass of `name` and `href`.
const fn kam_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        read_node: Some(read_node),
        write_node: Some(write_node),
        set_key_req: Some(set_key_req),
        set_key: Some(set_key),
        push_bin: Some(xmlSecTransformDefaultPushBin),
        pop_bin: Some(xmlSecTransformDefaultPopBin),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<Kam>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_AGREEMENT_METHOD,
        )
    }
}

static ECDH: XmlSecTransformKlass = kam_klass(&xmlSecNameEcdh, &xmlSecHrefEcdh);
static DH_ES: XmlSecTransformKlass = kam_klass(&xmlSecNameDhEs, &xmlSecHrefDhEs);
static X25519: XmlSecTransformKlass = kam_klass(&xmlSecNameX25519, &xmlSecHrefX25519);
static X448: XmlSecTransformKlass = kam_klass(&xmlSecNameX448, &xmlSecHrefX448);

/// The built-in table's `ECDH-ES` klass.
pub(crate) extern "C" fn ecdh() -> *const XmlSecTransformKlass {
    &raw const ECDH
}

/// The built-in table's `DH-ES` klass.
pub(crate) extern "C" fn dh_es() -> *const XmlSecTransformKlass {
    &raw const DH_ES
}

/// The built-in table's `x25519` klass.
pub(crate) extern "C" fn x25519() -> *const XmlSecTransformKlass {
    &raw const X25519
}

/// The built-in table's `x448` klass.
pub(crate) extern "C" fn x448() -> *const XmlSecTransformKlass {
    &raw const X448
}

/// The agreement of klass `id` and the key-data klass both parties' keys
/// are of; `None` for any other klass.
fn agreement(
    id: *const XmlSecTransformKlass,
) -> Option<(KeyAgreementAlgorithm, *const XmlSecKeyDataKlass)> {
    if std::ptr::eq(id, &raw const ECDH) {
        Some((KeyAgreementAlgorithm::EcdhEs, asymkeys::ec()))
    } else if std::ptr::eq(id, &raw const DH_ES) {
        Some((KeyAgreementAlgorithm::DhEs, asymkeys::dh()))
    } else if std::ptr::eq(id, &raw const X25519) {
        Some((KeyAgreementAlgorithm::X25519, xdhkeys::xdh()))
    } else if std::ptr::eq(id, &raw const X448) {
        Some((KeyAgreementAlgorithm::X448, xdhkeys::xdh()))
    } else {
        None
    }
}

/// The key of one party of an agreement, as its key data holds it.
#[derive(Clone, Copy)]
enum Party<'a> {
    /// An EC key, for ECDH-ES, or a DH key, for DH-ES.
    Value(&'a Material),
    /// An X25519 or X448 key.
    Xdh(&'a XdhKey),
}

impl<'a> Party<'a> {
    /// The PKCS#8 of the party's private key, when its key data holds one.
    fn private(self) -> Option<&'a [u8]> {
        match self {
            Self::Value(material) => material.private.as_deref().map(Vec::as_slice),
            Self::Xdh(key) => key.private.as_deref().map(Vec::as_slice),
        }
    }

    /// The p, q and g of a DH party's group, without leading zero octets.
    fn dh_group(self) -> Option<[&'a [u8]; 3]> {
        let Self::Value(Material {
            value:
                KeyValueInfo::Dh {
                    p: Some(p),
                    q: Some(q),
                    generator: Some(generator),
                    ..
                },
            ..
        }) = self
        else {
            return None;
        };
        Some(
            [p, q, generator]
                .map(|bytes| &bytes[bytes.iter().take_while(|byte| **byte == 0).count()..]),
        )
    }
}

/// The agreement object of a valid transform of these klasses, with its
/// algorithm and key-data klass, after libxmlsec1's assertion at `here`.
///
/// # Safety
/// `transform` is null or a transform; a transform of these klasses was
/// initialized.
unsafe fn object<'a>(
    transform: *mut XmlSecTransform,
    here: Here,
) -> Option<(
    &'a mut XmlSecTransform,
    (KeyAgreementAlgorithm, *const XmlSecKeyDataKlass),
    &'a mut Kam,
)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the agreement layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let found = agreement(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Kam>>()).then_some(found)
        });
        let Some(found) = found else {
            errors::assertion(
                here,
                c"xmlSecTransformCheckSize(transform, xmlSecOpenSSLKeyAgreementSize)",
            );
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Kam>>();
        Some((&mut with.transform, found, &mut with.context))
    }
}

/// The transform's name for a report.
fn name_of(transform: &XmlSecTransform) -> *const c_char {
    // SAFETY: a valid transform's klass outlives it.
    unsafe { (*transform.id).name.cast() }
}

unsafe extern "C" fn initialize(transform: *mut XmlSecTransform) -> c_int {
    contain(-1, || {
        // SAFETY: the dispatcher passes a transform of these klasses, whose
        // zeroed tail is written here.
        unsafe {
            if valid(transform)
                .and_then(|(object, _)| agreement(object.id))
                .is_none()
            {
                errors::internal(
                    here!("xmlSecOpenSSLKeyAgreementInitialize"),
                    std::ptr::null(),
                    c"Unknown key agreement transform",
                );
                return -1;
            }
            (&raw mut (*transform.cast::<WithContext<Kam>>()).context).write(Kam {
                method: None,
                method_node: std::ptr::null_mut(),
                default_width: 0,
            });
        }
        0
    })
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    contain((), || {
        // SAFETY: an initialized transform of these klasses; its state is
        // dropped once.
        unsafe {
            if valid(transform)
                .and_then(|(object, _)| agreement(object.id))
                .is_some()
            {
                std::ptr::drop_in_place(&raw mut (*transform.cast::<WithContext<Kam>>()).context);
            }
        }
    });
}

/// Whether `node` is the element `name` in `ns`.
///
/// # Safety
/// `node` is null or a live node.
unsafe fn is(node: *mut XmlNode, name: &[u8], ns: &[u8]) -> bool {
    // SAFETY: by the caller's contract; the names are NUL-terminated.
    !node.is_null() && unsafe { xmlSecCheckNodeName(node, name.as_ptr(), ns.as_ptr()) } != 0
}

/// The first element child of the `AgreementMethod` `node` after its
/// optional leading `KA-Nonce`, which the agreement does not use.
///
/// # Safety
/// `node` is a live element.
unsafe fn after_nonce(node: *mut XmlNode) -> *mut XmlNode {
    // SAFETY: by the caller's contract; each sibling is live.
    unsafe {
        let cur = next_element(nodes::first_child(node));
        if is(cur, &xmlSecNodeKANonce, &xmlSecEncNs) {
            next_element(nodes::next(cur))
        } else {
            cur
        }
    }
}

/// The width a `ConcatKDF` `method` yields by default: its digest's output
/// size; zero for any other derivation or an unknown digest.
fn default_width(method: &KeyDerivationMethod) -> usize {
    if method.algorithm() != "http://www.w3.org/2009/xmlenc11#ConcatKDF" {
        return 0;
    }
    DigestAlgorithm::from_uri(method.digest()).map_or(0, DigestAlgorithm::output_len)
}

/// The `KeyInfo` context of the read that runs the chain of `ctx`, after
/// libxmlsec1's assertion at `here`.
///
/// # Safety
/// `ctx` is an initialized context whose parent is null or a live `KeyInfo`
/// context.
unsafe fn parent<'a>(ctx: *mut XmlSecTransformCtx, here: Here) -> Option<&'a mut XmlSecKeyInfoCtx> {
    // SAFETY: by the caller's contract.
    let parent = unsafe {
        (*ctx)
            .parent_key_info_ctx
            .cast::<XmlSecKeyInfoCtx>()
            .as_mut()
    };
    if parent.is_none() {
        errors::assertion(here, c"transformCtx->parentKeyInfoCtx != NULL");
    }
    parent
}

/// `readNode` (libxmlsec1's `xmlSecTransformKAMRead`): the parameters of the
/// `KeyDerivationMethod` and the two parties' keys of the `AgreementMethod`
/// element `node`.
unsafe extern "C" fn read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecTransformKAMRead");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, kam)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() {
            errors::assertion(here, c"node != NULL");
            return -1;
        }
        // SAFETY: a non-null, initialized context and the caller's live
        // element; the object is the transform's own.
        if unsafe { read(object, kam, node, ctx, here) } {
            0
        } else {
            errors::internal(
                here!("xmlSecOpenSSLKeyAgreementNodeRead"),
                name_of(object),
                c"xmlSecTransformKAMRead",
            );
            -1
        }
    })
}

/// [`read_node`] past its preconditions; `false` after a report.
///
/// # Safety
/// As for [`read_node`], with every pointer valid.
unsafe fn read(
    object: &mut XmlSecTransform,
    kam: &mut Kam,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
    here: Here,
) -> bool {
    // SAFETY: the caller's context, element and its live children.
    unsafe {
        let Some(parent) = parent(ctx, here) else {
            return false;
        };
        // The originator, who encrypts or signs, agrees with its own private
        // key and the recipient's public key; the recipient the other way.
        let (originator_type, recipient_type) =
            if parent.operation == OPERATION_ENCRYPT || parent.operation == OPERATION_SIGN {
                (TYPE_PRIVATE, TYPE_PUBLIC)
            } else {
                (TYPE_PUBLIC, TYPE_PRIVATE)
            };
        let data = xmlSecTransformCtxExtraKeyDataEnsure(ctx, &raw const KAM_DATA);
        let Some(keys) = kam_data(data) else {
            errors::internal(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxExtraKeyDataEnsure(kamKeyData)",
            );
            return false;
        };
        let cur = after_nonce(node);
        if !is(cur, &xmlSecNodeKeyDerivationMethod, &xmlSecEnc11Ns) {
            errors::invalid_node(here, cur, "KeyDerivationMethod", std::ptr::null());
            return false;
        }
        if !read_method(object, kam, cur, ctx, here) {
            return false;
        }
        let cur = next_element(nodes::next(cur));
        if !is(cur, &xmlSecNodeOriginatorKeyInfo, &xmlSecEncNs) {
            errors::invalid_node(here, cur, "OriginatorKeyInfo", std::ptr::null());
            return false;
        }
        // A key a write carried over is not looked up again.
        if keys.originator.is_null() {
            keys.originator = role_key(originator_type, cur, object, ctx, parent, here);
            if keys.originator.is_null() {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformReadKeyInfoNode(OriginatorKeyInfo)",
                );
                return false;
            }
        }
        let cur = next_element(nodes::next(cur));
        if !is(cur, &xmlSecNodeRecipientKeyInfo, &xmlSecEncNs) {
            errors::invalid_node(here, cur, "RecipientKeyInfo", std::ptr::null());
            return false;
        }
        if keys.recipient.is_null() {
            keys.recipient = role_key(recipient_type, cur, object, ctx, parent, here);
            if keys.recipient.is_null() {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformReadKeyInfoNode(RecipientKeyInfo)",
                );
                return false;
            }
        }
        let cur = next_element(nodes::next(cur));
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return false;
        }
        true
    }
}

/// Reads the `KeyDerivationMethod` element `node` into `kam`: a derivation
/// the registry knows and the context enables, parsed by the core under the
/// policy of the agreement's side; `false` after a report.
///
/// # Safety
/// `ctx` is an initialized context; `node` a live element.
unsafe fn read_method(
    object: &XmlSecTransform,
    kam: &mut Kam,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
    here: Here,
) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        let href = CStr::from_bytes_with_nul(&xmlSecAttrAlgorithm)
            .ok()
            .and_then(|attribute| attribute.to_str().ok())
            .and_then(|attribute| nodes::property(node, attribute))
            .and_then(|href| std::ffi::CString::new(href).ok());
        let Some(href) = href else {
            errors::invalid_node_attribute(here, node, c"Algorithm", std::ptr::null(), "empty");
            return false;
        };
        let node_read = here!("xmlSecTransformNodeRead");
        if enabled_klass(
            href.as_ptr().cast(),
            USAGE_KEY_DERIVATION_METHOD,
            ctx,
            node_read,
        )
        .is_null()
        {
            errors::internal(here, std::ptr::null(), c"xmlSecTransformNodeRead");
            return false;
        }
        let Some((pinned, side)) = scope(object, ctx, here) else {
            return false;
        };
        match parse_method(node, pinned.of(side)) {
            Ok(method) => {
                kam.default_width = default_width(&method);
                kam.method = Some((method, side));
                kam.method_node = node;
                true
            }
            Err(error) => {
                errors::report(
                    node_read,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_TRANSFORM,
                    &error,
                );
                errors::internal(here, std::ptr::null(), c"xmlSecTransformNodeRead");
                false
            }
        }
    }
}

/// libxmlsec1's `xmlSecTransformReadKeyInfoNode`: the key of `key_type` the
/// keys manager of the `KeyInfo` read `parent` finds from the role element
/// `node` (`OriginatorKeyInfo` or `RecipientKeyInfo`) for the agreement
/// `transform`; null after a report.
///
/// The role is read one level of `EncryptedKey` below `parent`, as the
/// agreement's nested context is: libxmlsec1 reads it in a fresh context
/// whose levels start again, which lets a role that holds another
/// `AgreementMethod` recurse without bound on hostile input.
///
/// # Safety
/// `ctx` is the chain's initialized context; `node` a live element;
/// `parent` the `KeyInfo` context the chain runs for.
unsafe fn role_key(
    key_type: c_uint,
    node: *mut XmlNode,
    transform: &mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
    parent: &mut XmlSecKeyInfoCtx,
    here: Here,
) -> *mut XmlSecKey {
    let here_read = here!("xmlSecTransformReadKeyInfoNode");
    let mngr = parent.keys_mngr;
    // SAFETY: a non-null manager of the parent context.
    let get_key = unsafe { mngr.as_ref() }.and_then(|mngr| mngr.get_key);
    let Some(get_key) = get_key else {
        errors::assertion(here_read, c"keysMngr->getKey != NULL");
        return std::ptr::null_mut();
    };
    // SAFETY: the chain's initialized context.
    let Some(pinned) = (unsafe { run_policy(ctx, here) }) else {
        return std::ptr::null_mut();
    };
    let side = operation_side(transform.operation).unwrap_or(Side::Decrypt);
    let mut local = std::mem::MaybeUninit::<XmlSecKeyInfoCtx>::uninit();
    let local = local.as_mut_ptr();
    // SAFETY: a local context initialized here and finalized on every path;
    // the parent context and the chain's context are live.
    unsafe {
        if xmlSecKeyInfoCtxInitialize(local, mngr) < 0 {
            errors::internal(here_read, std::ptr::null(), c"xmlSecKeyInfoCtxInitialize");
            return std::ptr::null_mut();
        }
        let key = 'read: {
            if xmlSecKeyInfoCtxCopyUserPref(local, parent) < 0 {
                errors::internal(here_read, std::ptr::null(), c"xmlSecKeyInfoCtxCopyUserPref");
                break 'read std::ptr::null_mut();
            }
            (*local).mode = MODE_READ;
            (*local).operation = transform.operation;
            (*local).cur_retrieval_method_level = parent.cur_retrieval_method_level;
            (*local).cur_key_info_reference_level = parent.cur_key_info_reference_level;
            let Some(level) = parent.cur_encrypted_key_level.checked_add(1) else {
                errors::internal(here_read, std::ptr::null(), c"curEncryptedKeyLevel");
                break 'read std::ptr::null_mut();
            };
            (*local).cur_encrypted_key_level = level;
            if xmlSecTransformSetKeyReq(transform, &raw mut (*local).key_req) < 0 {
                errors::internal(here_read, std::ptr::null(), c"xmlSecTransformSetKeyReq");
                break 'read std::ptr::null_mut();
            }
            (*local).key_req.key_type = key_type;
            // The role is found under the revision the operation runs under,
            // counting on from what the operation spent.
            let pin = SlotPin::hold_pinned(
                &raw mut (*local).reserved0,
                pinned.clone(),
                run_spent(ctx),
                run_budget(ctx)
                    .key_candidates
                    .within(pinned.of(side).resources().max_key_candidates),
            );
            let key = get_key(node, local);
            let charged =
                charge_key_info(ctx, (*local).reserved0, pinned.of(side).resources(), here);
            drop(pin);
            if !charged {
                if !key.is_null() {
                    xmlSecKeyDestroy(key);
                }
                break 'read std::ptr::null_mut();
            }
            if key.is_null() {
                errors::other(
                    here_read,
                    errors::R_KEY_NOT_FOUND,
                    std::ptr::null(),
                    Some("key not found"),
                );
                break 'read key;
            }
            if xmlSecKeyMatch(key, std::ptr::null(), &raw mut (*local).key_req) != 1 {
                errors::other(
                    here_read,
                    errors::R_KEY_NOT_FOUND,
                    std::ptr::null(),
                    Some("key doesn't match requirements"),
                );
                xmlSecKeyDestroy(key);
                break 'read std::ptr::null_mut();
            }
            key
        };
        xmlSecKeyInfoCtxFinalize(local);
        key
    }
}

/// `writeNode` (libxmlsec1's `xmlSecTransformKAMWrite`): the public keys of
/// both parties into the role elements of the `AgreementMethod` `node`.
unsafe extern "C" fn write_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecTransformKAMWrite");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, _)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() {
            errors::assertion(here, c"node != NULL");
            return -1;
        }
        // SAFETY: a non-null, initialized context and the caller's element.
        if unsafe { write(node, ctx, here) } {
            0
        } else {
            errors::internal(
                here!("xmlSecOpenSSLKeyAgreementNodeWrite"),
                name_of(object),
                c"xmlSecTransformKAMWrite",
            );
            -1
        }
    })
}

/// [`write_node`] past its preconditions; `false` after a report.
///
/// # Safety
/// `ctx` is an initialized context; `node` a live element.
unsafe fn write(node: *mut XmlNode, ctx: *mut XmlSecTransformCtx, here: Here) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        let Some(parent) = parent(ctx, here) else {
            return false;
        };
        let Some(keys) = kam_data(xmlSecTransformCtxExtraKeyDataGet(ctx, &raw const KAM_DATA))
        else {
            errors::assertion(here, c"kamKeyData != NULL");
            return false;
        };
        let cur = after_nonce(node);
        if !is(cur, &xmlSecNodeKeyDerivationMethod, &xmlSecEnc11Ns) {
            errors::invalid_node(here, cur, "KeyDerivationMethod", std::ptr::null());
            return false;
        }
        let mut cur = next_element(nodes::next(cur));
        for (key, name, role) in [
            (
                keys.originator,
                &xmlSecNodeOriginatorKeyInfo[..],
                c"xmlSecTransformWriteKeyInfoNode(OriginatorKeyInfo)",
            ),
            (
                keys.recipient,
                &xmlSecNodeRecipientKeyInfo[..],
                c"xmlSecTransformWriteKeyInfoNode(RecipientKeyInfo)",
            ),
        ] {
            if !is(cur, name, &xmlSecEncNs) {
                let expected = klass_text(name.as_ptr());
                errors::invalid_node(here, cur, &expected, std::ptr::null());
                return false;
            }
            if key.is_null() {
                errors::internal(here, std::ptr::null(), c"no key to write in the role node");
                return false;
            }
            if !write_role(key, cur, parent) {
                errors::internal(here, std::ptr::null(), role);
                return false;
            }
            cur = next_element(nodes::next(cur));
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return false;
        }
        true
    }
}

/// libxmlsec1's `xmlSecTransformWriteKeyInfoNode`: the public part of `key`
/// into the role element `node`, with the preferences of `parent`.
///
/// # Safety
/// `key` is a valid key, `node` a live element, `parent` an initialized
/// context.
unsafe fn write_role(
    key: *mut XmlSecKey,
    node: *mut XmlNode,
    parent: &mut XmlSecKeyInfoCtx,
) -> bool {
    let here = here!("xmlSecTransformWriteKeyInfoNode");
    let mut local = std::mem::MaybeUninit::<XmlSecKeyInfoCtx>::uninit();
    let local = local.as_mut_ptr();
    // SAFETY: a local context initialized here and finalized on every path.
    unsafe {
        if xmlSecKeyInfoCtxInitialize(local, std::ptr::null_mut()) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxInitialize");
            return false;
        }
        let written = if xmlSecKeyInfoCtxCopyUserPref(local, parent) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxCopyUserPref");
            false
        } else {
            (*local).mode = MODE_WRITE;
            // Only public keys are written.
            (*local).key_req.key_type = TYPE_PUBLIC;
            let written = xmlSecKeyInfoNodeWrite(node, key, local) >= 0;
            if !written {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoNodeWrite");
            }
            written
        };
        xmlSecKeyInfoCtxFinalize(local);
        written
    }
}

/// `setKeyReq`: a private key of the agreement's key-data klass for key
/// agreement.
unsafe extern "C" fn set_key_req(transform: *mut XmlSecTransform, req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKeyAgreementSetKeyReq");
        // SAFETY: the dispatcher passes a transform.
        let Some((_, (_, key_id), _)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        // SAFETY: null or the caller's key requirements.
        let Some(req) = (unsafe { req.as_mut() }) else {
            errors::assertion(here, c"keyReq != NULL");
            return -1;
        };
        req.key_id = key_id;
        req.key_type = TYPE_PRIVATE;
        req.key_usage = KEY_USAGE_KEY_AGREEMENT;
        0
    })
}

/// `setKey`: nothing; the agreement takes both parties' keys from the
/// context's `ka-params` key data.
unsafe extern "C" fn set_key(transform: *mut XmlSecTransform, key: *mut c_void) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKeyAgreementSetKey");
        // SAFETY: the dispatcher passes a transform.
        if unsafe { object(transform, here) }.is_none() {
            return -1;
        }
        if key.is_null() {
            errors::assertion(here, c"key != NULL");
            return -1;
        }
        0
    })
}

/// `execute`: takes no input; on the final call agrees and derives the
/// expected width.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKeyAgreementExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, (algorithm, key_id), kam)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if object.operation != OPERATION_ENCRYPT && object.operation != OPERATION_DECRYPT {
            errors::assertion(
                here,
                c"((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt))",
            );
            return -1;
        }
        if ctx.is_null() {
            errors::assertion(here, c"transformCtx != NULL");
            return -1;
        }
        if object.status == STATUS_NONE {
            object.status = STATUS_WORKING;
        }
        if object.status == STATUS_FINISHED {
            // SAFETY: the transform's own input buffer.
            if unsafe { super::super::buffer::xmlSecBufferGetSize(&raw mut object.in_buf) } != 0 {
                errors::assertion(here, c"xmlSecBufferGetSize(in) == 0");
                return -1;
            }
            return 0;
        }
        if object.status != STATUS_WORKING {
            errors::invalid_status(here, name_of(object), object.status);
            return -1;
        }
        if last == 0 {
            return 0;
        }
        let name = name_of(object);
        // SAFETY: a non-null, initialized context.
        let Some(output) = (unsafe { derive(object, algorithm, key_id, kam, ctx, here) }) else {
            return -1;
        };
        // The output buffer of an agreement holds the derived key, marked as
        // a secret as libxmlsec1 swaps a secure buffer in.
        // SAFETY: the transform's own output buffer.
        unsafe {
            super::super::buffer::xmlSecBufferMakeSecure(&raw mut object.out_buf);
            if xmlSecBufferAppend(&raw mut object.out_buf, output.as_ptr(), output.len()) < 0 {
                errors::internal(here, name, c"xmlSecBufferAppend");
                return -1;
            }
        }
        object.status = STATUS_FINISHED;
        0
    })
}

/// The key the agreement of `object` derives on its final call: both
/// parties' keys from the context's `ka-params`, the derivation read under
/// the run's policy, the width its reader expects or the derivation's
/// default; `None` after a report at `here`.
///
/// # Safety
/// `ctx` is the chain's initialized context.
unsafe fn derive(
    object: &XmlSecTransform,
    algorithm: KeyAgreementAlgorithm,
    key_id: *const XmlSecKeyDataKlass,
    kam: &mut Kam,
    ctx: *mut XmlSecTransformCtx,
    here: Here,
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let name = name_of(object);
    // SAFETY: by the caller's contract.
    let Some(keys) =
        (unsafe { kam_data(xmlSecTransformCtxExtraKeyDataGet(ctx, &raw const KAM_DATA)) })
    else {
        errors::internal(here, name, c"xmlSecTransformCtxExtraKeyDataGet");
        return None;
    };
    let width = match object.expected_output_size {
        0 => kam.default_width,
        width => width,
    };
    // SAFETY: by the caller's contract.
    let (pinned, side) = unsafe { scope(object, ctx, here) }?;
    let method = method_under(
        &mut kam.method,
        kam.method_node,
        pinned.of(side),
        side,
        here,
    )?;
    // The party whose private key agrees is the side the operation is on.
    let (mine, peer) = if object.operation == OPERATION_ENCRYPT {
        (keys.originator, keys.recipient)
    } else {
        (keys.recipient, keys.originator)
    };
    // SAFETY: the keys the read found, owned by the key data.
    let (mine, peer) = unsafe { parties(mine, peer, key_id, name, here) }?;
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(ctx) };
    // A refusal ends the operation: no later part agrees under it.
    if let Some(limit) = run.refused_by {
        errors::limit_exceeded(here, name, limit.name, limit.max);
        return None;
    }
    match agree(
        algorithm,
        method,
        width,
        mine,
        peer,
        pinned.of(side).key_establishment(),
        &mut run.key_establishment,
    ) {
        Ok(output) => Some(output),
        Err(XmlEncError::Policy(PolicyViolation::ResourceLimit {
            resource, maximum, ..
        })) => {
            // The operation's allowance is spent: the operation ends wherever
            // its parts hand it back.
            run.refused_by = run.refused_by.or(Some(Limit {
                name: resource,
                max: maximum,
            }));
            errors::limit_exceeded(here, name, resource, maximum);
            None
        }
        Err(error) => {
            errors::report(
                here,
                name,
                std::ptr::null(),
                errors::R_CRYPTO_FAILED,
                &error.to_string(),
            );
            None
        }
    }
}

/// The key material of the agreeing party `mine` and of its `peer`, both of
/// key-data klass `key_id`; `None` after libxmlsec1's report at `here`.
///
/// # Safety
/// `mine` and `peer` are null or keys.
unsafe fn parties<'a>(
    mine: *mut XmlSecKey,
    peer: *mut XmlSecKey,
    key_id: *const XmlSecKeyDataKlass,
    name: *const c_char,
    here: Here,
) -> Option<(Party<'a>, Party<'a>)> {
    // SAFETY: by the caller's contract.
    unsafe {
        if mine.is_null() || peer.is_null() {
            errors::assertion(here, c"kamData->keyOriginator != NULL");
            return None;
        }
        let mut found = [None, None];
        for (slot, (key, which)) in found
            .iter_mut()
            .zip([(mine, "key data"), (peer, "peer key data")])
        {
            let value = xmlSecKeyGetValue(key);
            if value.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyGetValue");
                return None;
            }
            if !check_id(value, key_id) {
                let klass = klass_text((*(*value).id).name);
                errors::report(
                    here,
                    name,
                    std::ptr::null(),
                    errors::R_INVALID_TRANSFORM,
                    &format!(
                        "{which} \"{klass}\" is not compatible with this key agreement transform"
                    ),
                );
                return None;
            }
            *slot = if std::ptr::eq(key_id, xdhkeys::xdh()) {
                xdhkeys::key_of(value).map(Party::Xdh)
            } else {
                material_of(value).map(Party::Value)
            };
        }
        if let [Some(mine), Some(peer)] = found {
            return Some((mine, peer));
        }
        errors::internal(here, name, c"xmlSecKeyGetValue");
        None
    }
}

/// The private key of `party`, as the provider's key for `algorithm`; a
/// key of another curve is refused by the import's algorithm check. A DH
/// key's group is validated under `budget`, which its import charges.
fn agreement_key(
    algorithm: KeyAgreementAlgorithm,
    party: Party<'_>,
    budget: &mut KeyEstablishmentBudget<'_>,
) -> Result<Box<dyn KeyAgreementKey>, XmlEncError> {
    let private = party.private().ok_or(XmlEncError::KeyNotFound)?;
    match algorithm {
        KeyAgreementAlgorithm::EcdhEs => Ok(Box::new(RustCryptoEcdhKey::from_pkcs8_der(private)?)),
        KeyAgreementAlgorithm::DhEs => Ok(Box::new(RustCryptoDhKey::from_pkcs8_der(
            xml_sec::provider::default_provider(),
            budget,
            private,
        )?)),
        KeyAgreementAlgorithm::X25519 => {
            Ok(Box::new(RustCryptoX25519Key::from_pkcs8_der(private)?))
        }
        KeyAgreementAlgorithm::X448 => Ok(Box::new(RustCryptoX448Key::from_pkcs8_der(private)?)),
        // XML Encryption 1.0's DH agreement has no klass of this library.
        KeyAgreementAlgorithm::LegacyDh => Err(XmlEncError::UnsupportedAlgorithm(
            algorithm.uri().to_owned(),
        )),
    }
}

/// The public key of `party`, the peer of `mine`, in the encoding
/// `algorithm` agrees with; an X448 key for an X25519 agreement, or the
/// other way, or a DH key of another group, is no peer.
fn peer_public<'a>(
    algorithm: KeyAgreementAlgorithm,
    mine: Party<'_>,
    party: Party<'a>,
) -> Result<&'a [u8], XmlEncError> {
    match (algorithm, party) {
        (
            KeyAgreementAlgorithm::EcdhEs,
            Party::Value(Material {
                value: KeyValueInfo::Ec { public_key, .. },
                ..
            }),
        ) => Ok(public_key),
        // RFC 2631 section 2.1.1: both parties' keys are of the same group,
        // as OpenSSL's derivation requires of its peer.
        (
            KeyAgreementAlgorithm::DhEs,
            Party::Value(Material {
                value: KeyValueInfo::Dh { public, .. },
                ..
            }),
        ) if mine.dh_group().is_some() && party.dh_group() == mine.dh_group() => Ok(public),
        (KeyAgreementAlgorithm::X25519, Party::Xdh(key)) => match key.public() {
            Some((Curve::X25519, public)) => Ok(public),
            _ => Err(XmlEncError::KeyNotFound),
        },
        (KeyAgreementAlgorithm::X448, Party::Xdh(key)) => match key.public() {
            Some((Curve::X448, public)) => Ok(public),
            _ => Err(XmlEncError::KeyNotFound),
        },
        _ => Err(XmlEncError::KeyNotFound),
    }
}

/// Agrees by `algorithm` between `mine` and `peer` and derives `width`
/// octets by `method` under `policy`, counting on from `usage`, the
/// operation's earlier reservations, and leaving it what the operation has
/// reserved, failed attempts included.
fn agree(
    algorithm: KeyAgreementAlgorithm,
    method: &KeyDerivationMethod,
    width: usize,
    mine: Party<'_>,
    peer: Party<'_>,
    policy: &xml_sec::policy::KeyEstablishmentPolicy,
    usage: &mut xml_sec::key_establishment::KeyEstablishmentUsage,
) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
    let agreement = KeyAgreementParameters {
        algorithm: algorithm.uri(),
        peer_public_key: peer_public(algorithm, mine, peer)?,
    };
    let parameters = method.parameters(width)?;
    let mut budget = KeyEstablishmentBudget::resume(policy, *usage)?;
    let derived = agreement_key(algorithm, mine, &mut budget).and_then(|key| {
        budget.agree_and_derive(
            xml_sec::provider::default_provider(),
            key.as_ref(),
            &agreement,
            &parameters,
        )
    });
    *usage = budget.usage();
    derived
}

// ----------------------------------------------------------------------------
// ka-params

/// libxmlsec1's internal `ka-params` key data: the two parties' keys an
/// agreement found, kept by the context that ran it and carried to the key
/// it yields, so writing the key reuses them.
#[repr(C)]
struct KamData {
    data: XmlSecKeyData,
    originator: *mut XmlSecKey,
    recipient: *mut XmlSecKey,
}

static KAM_DATA: XmlSecKeyDataKlass = XmlSecKeyDataKlass {
    klass_size: size_of::<XmlSecKeyDataKlass>(),
    obj_size: size_of::<KamData>(),
    name: c"ka-params".as_ptr().cast(),
    usage: DATA_USAGE_UNKNOWN,
    href: std::ptr::null(),
    data_node_name: std::ptr::null(),
    data_node_ns: std::ptr::null(),
    initialize: Some(kam_initialize),
    duplicate: Some(kam_duplicate),
    finalize: Some(kam_finalize),
    generate: None,
    get_type: None,
    get_size: None,
    deprecated0: std::ptr::null_mut(),
    xml_read: None,
    xml_write: None,
    bin_read: None,
    bin_write: None,
    debug_dump: Some(kam_debug_dump),
    debug_xml_dump: Some(kam_debug_xml_dump),
    reserved0: std::ptr::null_mut(),
    reserved1: std::ptr::null_mut(),
};

/// The `ka-params` klass.
pub(crate) fn kam_klass_id() -> *const XmlSecKeyDataKlass {
    &raw const KAM_DATA
}

/// The object of valid `ka-params` key data.
///
/// # Safety
/// `data` is null or a key-data object.
unsafe fn kam_data<'a>(data: *mut XmlSecKeyData) -> Option<&'a mut KamData> {
    // SAFETY: by the caller's contract; a valid object of the klass has the
    // `ka-params` layout.
    unsafe {
        (data_valid(data) && check_id(data, &raw const KAM_DATA))
            .then(|| &mut *data.cast::<KamData>())
    }
}

unsafe extern "C" fn kam_initialize(data: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass.
        let Some(object) = (unsafe { kam_data(data) }) else {
            errors::assertion(
                here!("xmlSecKeyDataKAMInitialize"),
                c"xmlSecKeyDataIsValid(data)",
            );
            return -1;
        };
        object.originator = std::ptr::null_mut();
        object.recipient = std::ptr::null_mut();
        0
    })
}

/// Destroys the keys `object` holds.
///
/// # Safety
/// `object` is initialized `ka-params` key data.
unsafe fn release(object: &mut KamData) {
    for key in [&mut object.originator, &mut object.recipient] {
        if !key.is_null() {
            // SAFETY: a key the object owns.
            unsafe { xmlSecKeyDestroy(*key) };
            *key = std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn kam_duplicate(dst: *mut XmlSecKeyData, src: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecKeyDataKAMDuplicate");
        // SAFETY: the registry passes key data of this klass.
        let (Some(target), Some(source)) = (unsafe { kam_data(dst) }, unsafe { kam_data(src) })
        else {
            errors::assertion(
                here,
                c"xmlSecKeyDataIsValid(dst) && xmlSecKeyDataIsValid(src)",
            );
            return -1;
        };
        // SAFETY: keys the objects own.
        unsafe {
            release(target);
            for (to, from, what) in [
                (
                    &mut target.originator,
                    source.originator,
                    c"xmlSecKeyDuplicate(keyOriginator)",
                ),
                (
                    &mut target.recipient,
                    source.recipient,
                    c"xmlSecKeyDuplicate(keyRecipient)",
                ),
            ] {
                if from.is_null() {
                    continue;
                }
                *to = xmlSecKeyDuplicate(from);
                if to.is_null() {
                    errors::internal(here, c"ka-params".as_ptr(), what);
                    return -1;
                }
            }
        }
        0
    })
}

unsafe extern "C" fn kam_finalize(data: *mut XmlSecKeyData) {
    contain((), || {
        // SAFETY: the registry passes key data of this klass.
        if let Some(object) = unsafe { kam_data(data) } {
            // SAFETY: an initialized object.
            unsafe { release(object) };
        }
    });
}

unsafe extern "C" fn kam_debug_dump(_data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes a C stream.
        unsafe { write_stream(output, "=== ka-params key: size = 0\n") };
    });
}

unsafe extern "C" fn kam_debug_xml_dump(_data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes a C stream.
        unsafe { write_stream(output, "<ka-params size=\"0\"/>\n") };
    });
}
