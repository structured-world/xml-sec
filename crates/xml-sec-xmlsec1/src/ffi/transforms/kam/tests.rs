use std::collections::BTreeSet;

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use super::super::super::app::key_load_memory;
use super::super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::super::crypto::{
    xmlSecCryptoAppDefaultKeysMngrAdoptKey, xmlSecCryptoAppDefaultKeysMngrInit,
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use super::super::super::keys::{xmlSecKeyGenerate, xmlSecKeySetName};
use super::super::super::keysmngr::{XmlSecKeysMngr, xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
use super::super::super::library::{xmlSecInit, xmlSecShutdown};
use super::super::super::symkeys;
use super::super::super::tests::own_process;
use super::super::super::tree::XmlDoc;
use super::super::super::xmlenc::{
    xmlSecEncCtxBinaryEncrypt, xmlSecEncCtxCreate, xmlSecEncCtxDecryptToBuffer, xmlSecEncCtxDestroy,
};
use super::*;

/// `xmlSecKeyDataFormatPem`.
const FORMAT_PEM: c_int = 2;
/// `xmlSecKeyDataTypeSession`.
const TYPE_SESSION: c_uint = 0x0008;

const ORIGINATOR_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-key.pem");
const ORIGINATOR_PUBLIC: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-pubkey.pem");
const RECIPIENT_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-second-key.pem");
const RECIPIENT_PUBLIC: &[u8] = include_bytes!(
    "../../../../../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-second-pubkey.pem"
);
const RSA_KEY: &[u8] = include_bytes!("../../../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
/// The donor's ECDH-ES template: an AES-128-GCM `EncryptedData` whose key an
/// `EncryptedKey` wraps with AES-256 KW under a key the `AgreementMethod`
/// agrees on by `ConcatKDF` over SHA-256, the parties named by `KeyName`.
const TEMPLATE: &str = include_str!(
    "../../../../../../tests/fixtures/xmlenc/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm.tmpl"
);

/// Initializes the library and its crypto, runs `test` and shuts both down.
fn with_library(test: impl FnOnce()) {
    own_process();
    // SAFETY: the library initialized and shut down on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
    }
    test();
    // SAFETY: every object of the test is released.
    unsafe {
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// The PEM key `pem`, loaded.
fn pem_key(pem: &[u8]) -> *mut XmlSecKey {
    // SAFETY: the fixture's bytes; no password is needed.
    let key = unsafe {
        key_load_memory(
            pem.as_ptr(),
            pem.len(),
            FORMAT_PEM,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(!key.is_null(), "the fixture loads");
    key.cast()
}

/// A keys manager holding each PEM key under its name.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn manager(keys: &[(&[u8], &CStr)]) -> *mut XmlSecKeysMngr {
    // SAFETY: by the caller's contract; each key is adopted by the manager.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(xmlSecCryptoAppDefaultKeysMngrInit(mngr.cast()), 0);
        for (pem, name) in keys {
            let key = pem_key(pem);
            assert_eq!(xmlSecKeySetName(key, name.as_ptr().cast()), 0);
            assert_eq!(
                xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr.cast(), key.cast()),
                0
            );
        }
        mngr
    }
}

/// The originator's side: its private key and the recipient's public key.
///
/// # Safety
/// The library and its crypto are initialized.
unsafe fn originator() -> *mut XmlSecKeysMngr {
    // SAFETY: by the caller's contract.
    unsafe {
        manager(&[
            (ORIGINATOR_KEY, c"originator-key-name"),
            (RECIPIENT_PUBLIC, c"recipient-key-name"),
        ])
    }
}

/// `template` read as a document.
fn document(template: &str) -> *mut XmlDoc {
    // SAFETY: the template's bytes.
    let doc = unsafe {
        xsReadMemory(
            template.as_ptr().cast(),
            c_int::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    assert!(!doc.is_null(), "the template parses");
    doc.cast()
}

/// Encrypts `plaintext` into `doc` with a fresh AES-128 session key, the
/// agreement run by the side `mngr` holds; whether it succeeded.
///
/// # Safety
/// The library is initialized; `doc` and `mngr` are live.
unsafe fn encrypt(doc: *mut XmlDoc, mngr: *mut XmlSecKeysMngr, plaintext: &[u8]) -> bool {
    // SAFETY: by the caller's contract; a context created and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(mngr);
        (*ctx).key_info_read_ctx.max_encrypted_key_level = 3;
        (*ctx).key_info_write_ctx.max_encrypted_key_level = 3;
        (*ctx).enc_key = xmlSecKeyGenerate(symkeys::aes(), 128, TYPE_SESSION);
        let done = xmlSecEncCtxBinaryEncrypt(
            ctx,
            xsDocGetRootElement(doc.cast()),
            plaintext.as_ptr(),
            plaintext.len(),
        ) == 0;
        xmlSecEncCtxDestroy(ctx);
        done
    }
}

/// What decrypting `doc` with a context over `mngr` yields, `None` when it
/// fails.
///
/// # Safety
/// The library is initialized; `doc` and `mngr` are live.
unsafe fn decrypted(doc: *mut XmlDoc, mngr: *mut XmlSecKeysMngr) -> Option<Vec<u8>> {
    // SAFETY: by the caller's contract; a context created and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(mngr);
        (*ctx).key_info_read_ctx.max_encrypted_key_level = 3;
        let result = xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc.cast()));
        let plaintext = (!result.is_null()).then(|| {
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                .to_vec()
        });
        xmlSecEncCtxDestroy(ctx);
        plaintext
    }
}

/// Encrypts with [`originator`] into `template`, then decrypts with the
/// recipient side `keys` holds: the plaintext, `None` when the decryption
/// fails. The encryption must succeed.
fn round_trip(template: &str, keys: &[(&[u8], &CStr)]) -> Option<Vec<u8>> {
    let plaintext = b"agreed content";
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(template);
        let sender = originator();
        assert!(encrypt(doc, sender, plaintext), "the originator encrypts");
        let recipient = manager(keys);
        let result = decrypted(doc, recipient);
        xmlSecKeysMngrDestroy(recipient);
        xmlSecKeysMngrDestroy(sender);
        xsFreeDoc(doc.cast());
        result
    }
}

/// Whether the originator side ([`originator`]) encrypts into `template`.
fn encrypts(template: &str) -> bool {
    encrypts_with(
        template,
        &[
            (ORIGINATOR_KEY, c"originator-key-name"),
            (RECIPIENT_PUBLIC, c"recipient-key-name"),
        ],
    )
}

/// Whether the originator side `keys` holds encrypts into `template`.
fn encrypts_with(template: &str, keys: &[(&[u8], &CStr)]) -> bool {
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(template);
        let sender = manager(keys);
        let sent = encrypt(doc, sender, b"content");
        xmlSecKeysMngrDestroy(sender);
        xsFreeDoc(doc.cast());
        sent
    }
}

/// Encrypts with the side `sender` holds into `template`, which must
/// succeed, then decrypts with the side `recipient` holds: the plaintext,
/// `None` when the decryption fails.
fn round_trip_between(
    template: &str,
    sender: &[(&[u8], &CStr)],
    recipient: &[(&[u8], &CStr)],
) -> Option<Vec<u8>> {
    // SAFETY: the library is initialized by the caller; every object is
    // released.
    unsafe {
        let doc = document(template);
        let originator = manager(sender);
        assert!(
            encrypt(doc, originator, b"agreed content"),
            "the originator encrypts"
        );
        let receiver = manager(recipient);
        let result = decrypted(doc, receiver);
        xmlSecKeysMngrDestroy(receiver);
        xmlSecKeysMngrDestroy(originator);
        xsFreeDoc(doc.cast());
        result
    }
}

const X25519_FIRST_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-first-key.pem");
const X25519_FIRST_PUBLIC: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-first-pubkey.pem");
const X25519_SECOND_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-second-key.pem");
const X25519_SECOND_PUBLIC: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x25519-second-pubkey.pem");
const X448_FIRST_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x448-first-key.pem");
const X448_SECOND_PUBLIC: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x448-second-pubkey.pem");
const X448_SECOND_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x448-second-key.pem");
const X448_FIRST_PUBLIC: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/xdh/xdh-x448-first-pubkey.pem");
/// The donor's X25519 template, its parties named as in [`TEMPLATE`].
const X25519_TEMPLATE: &str = include_str!(
    "../../../../../../tests/fixtures/xmlenc/aleksey-xmlenc-01/enc_xdh_x25519_concatkdf_sha256_kw_aes256_aes128gcm.tmpl"
);
/// The donor's X448 template.
const X448_TEMPLATE: &str = include_str!(
    "../../../../../../tests/fixtures/xmlenc/aleksey-xmlenc-01/enc_xdh_x448_concatkdf_sha256_kw_aes256_aes128gcm.tmpl"
);

/// The recipient's side: its private key and the originator's public key.
const RECIPIENT: [(&[u8], &CStr); 2] = [
    (RECIPIENT_KEY, c"recipient-key-name"),
    (ORIGINATOR_PUBLIC, c"originator-key-name"),
];

#[test]
fn both_parties_agree_on_the_key_encryption_key() {
    // The originator agrees with its private key and the recipient's public
    // key, the recipient with its private key and the originator's public
    // key: ECDH-ES gives both the same secret (XML Encryption 1.1 section
    // 5.6.4), so the session key the originator wrapped unwraps.
    with_library(|| {
        assert_eq!(
            round_trip(TEMPLATE, &RECIPIENT).as_deref(),
            Some(&b"agreed content"[..])
        );
    });
}

#[test]
fn a_recipient_without_the_originators_key_agrees_on_nothing() {
    // The recipient's keys manager knows no originator key: the agreement
    // finds no peer and the decryption fails rather than using some other
    // key for the role.
    with_library(|| {
        assert_eq!(
            round_trip(TEMPLATE, &[(RECIPIENT_KEY, c"recipient-key-name")]),
            None
        );
    });
}

#[test]
fn another_originator_key_yields_a_key_that_does_not_unwrap() {
    // The recipient holds a different public key under the originator's
    // name: the agreement succeeds on another secret, whose KEK fails the
    // key wrap's integrity check, so nothing decrypts.
    with_library(|| {
        assert_eq!(
            round_trip(
                TEMPLATE,
                &[
                    (RECIPIENT_KEY, c"recipient-key-name"),
                    (RECIPIENT_PUBLIC, c"originator-key-name"),
                ],
            ),
            None
        );
    });
}

#[test]
fn a_key_of_another_family_is_no_party() {
    // An RSA key under the originator's name is not an EC key: the role's
    // requirements, the agreement's key-data klass, refuse it.
    with_library(|| {
        assert_eq!(
            round_trip(
                TEMPLATE,
                &[
                    (RECIPIENT_KEY, c"recipient-key-name"),
                    (RSA_KEY, c"originator-key-name"),
                ],
            ),
            None
        );
    });
}

#[test]
fn an_agreement_names_both_parties_in_order() {
    // libxmlsec1 requires OriginatorKeyInfo then RecipientKeyInfo and nothing
    // after them, though the schema lets both be omitted: a template without
    // the recipient's role, with the roles swapped, or with an element after
    // them agrees on nothing, while the template as it is does.
    with_library(|| {
        assert!(encrypts(TEMPLATE));
        let start = TEMPLATE.find("<xenc:RecipientKeyInfo").expect("the role");
        let end = TEMPLATE.find("</xenc:RecipientKeyInfo>").expect("the role")
            + "</xenc:RecipientKeyInfo>".len();
        let recipient_role = &TEMPLATE[start..end];
        let without = format!("{}{}", &TEMPLATE[..start], &TEMPLATE[end..]);
        assert!(!encrypts(&without));
        let swapped = without.replace(
            "<xenc:OriginatorKeyInfo",
            &format!("{recipient_role}<xenc:OriginatorKeyInfo"),
        );
        assert!(!encrypts(&swapped));
        let trailing = TEMPLATE.replace(
            "</xenc:AgreementMethod>",
            "<extra xmlns=\"urn:extra\"/></xenc:AgreementMethod>",
        );
        assert!(!encrypts(&trailing));
    });
}

#[test]
fn an_agreement_needs_a_known_derivation() {
    // The KeyDerivationMethod names an algorithm no klass implements: the
    // registry refuses it before any key is looked up.
    with_library(|| {
        let unknown = TEMPLATE.replace(
            "http://www.w3.org/2009/xmlenc11#ConcatKDF",
            "urn:unknown:kdf",
        );
        assert!(!encrypts(&unknown));
    });
}

#[test]
fn the_policy_decides_whether_the_parties_may_agree() {
    // The agreement runs under the operation's key establishment policy: one
    // admitting no agreement refuses it before any provider work, one
    // admitting ECDH-ES derives the key, and either way the attempt is
    // charged to the operation's allowance.
    with_library(|| {
        let mine = pem_key(RECIPIENT_KEY);
        let peer = pem_key(ORIGINATOR_PUBLIC);
        let method_xml = "<xenc11:KeyDerivationMethod \
             xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" \
             xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" \
             Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\
             <xenc11:ConcatKDFParams AlgorithmID=\"00\" PartyUInfo=\"00\" PartyVInfo=\"00\">\
             <dsig:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
             </xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>";
        let method = xml_sec::xmlenc::parse_key_derivation_method(
            method_xml,
            &xml_sec::policy::DecryptionPolicy::default(),
        )
        .expect("the method parses");
        // SAFETY: the keys loaded above, released below.
        unsafe {
            let mine_material =
                Party::Value(material_of(xmlSecKeyGetValue(mine)).expect("an EC key"));
            let peer_material =
                Party::Value(material_of(xmlSecKeyGetValue(peer)).expect("an EC key"));
            let refusing = xml_sec::policy::KeyEstablishmentPolicy {
                agreement_algorithms: Some(BTreeSet::new()),
                ..xml_sec::policy::KeyEstablishmentPolicy::default()
            };
            let mut usage = xml_sec::key_establishment::KeyEstablishmentUsage::default();
            let refused = agree(
                KeyAgreementAlgorithm::EcdhEs,
                &method,
                32,
                mine_material,
                peer_material,
                &refusing,
                &mut usage,
            );
            assert!(
                matches!(refused, Err(XmlEncError::Policy(_))),
                "{refused:?}"
            );
            let admitting = xml_sec::policy::KeyEstablishmentPolicy::default();
            let derived = agree(
                KeyAgreementAlgorithm::EcdhEs,
                &method,
                32,
                mine_material,
                peer_material,
                &admitting,
                &mut usage,
            )
            .expect("ECDH-ES is admitted by default");
            assert_eq!(derived.len(), 32);
            let charged = KeyEstablishmentBudget::resume(&admitting, usage).expect("valid");
            assert!(charged.hash_blocks() > 0, "the derivation was charged");
            // The public key alone holds no private key to agree with.
            let public_only = agree(
                KeyAgreementAlgorithm::EcdhEs,
                &method,
                32,
                peer_material,
                mine_material,
                &admitting,
                &mut usage,
            );
            assert!(matches!(public_only, Err(XmlEncError::KeyNotFound)));
            xmlSecKeyDestroy(mine);
            xmlSecKeyDestroy(peer);
        }
    });
}

#[test]
fn x25519_parties_agree_on_the_key_encryption_key() {
    // X25519 keys loaded from key files agree as EC keys do (RFC 7748
    // section 6.1): the recipient unwraps what the originator wrapped, and
    // a recipient holding the wrong originator key unwraps nothing.
    with_library(|| {
        let sender = [
            (X25519_FIRST_KEY, c"originator-key-name"),
            (X25519_SECOND_PUBLIC, c"recipient-key-name"),
        ];
        let recipient = [
            (X25519_SECOND_KEY, c"recipient-key-name"),
            (X25519_FIRST_PUBLIC, c"originator-key-name"),
        ];
        assert_eq!(
            round_trip_between(X25519_TEMPLATE, &sender, &recipient).as_deref(),
            Some(&b"agreed content"[..])
        );
        let wrong = [
            (X25519_SECOND_KEY, c"recipient-key-name"),
            (X25519_SECOND_PUBLIC, c"originator-key-name"),
        ];
        assert_eq!(round_trip_between(X25519_TEMPLATE, &sender, &wrong), None);
    });
}

#[test]
fn an_x448_key_is_no_party_to_an_x25519_agreement() {
    // Both curves are XDH key data, so the role lookup admits either; the
    // agreement takes only a key of its own curve, as libxmlsec1 refuses
    // the cross-curve pair by the secret's size.
    with_library(|| {
        let sender = [
            (X448_FIRST_KEY, c"originator-key-name"),
            (X25519_SECOND_PUBLIC, c"recipient-key-name"),
        ];
        assert!(!encrypts_with(X25519_TEMPLATE, &sender));
        let mixed_peer = [
            (X25519_FIRST_KEY, c"originator-key-name"),
            (X448_SECOND_PUBLIC, c"recipient-key-name"),
        ];
        assert!(!encrypts_with(X25519_TEMPLATE, &mixed_peer));
    });
}

#[test]
fn x448_agrees_while_the_policy_admits_it() {
    // The library's compatible profile admits X448, as libxmlsec1 agrees
    // with it: both parties agree on the key encryption key. Once the
    // published policy is narrowed to the other agreements, the same
    // template is refused on either side.
    with_library(|| {
        let sender = [
            (X448_FIRST_KEY, c"originator-key-name"),
            (X448_SECOND_PUBLIC, c"recipient-key-name"),
        ];
        let recipient = [
            (X448_SECOND_KEY, c"recipient-key-name"),
            (X448_FIRST_PUBLIC, c"originator-key-name"),
        ];
        assert_eq!(
            round_trip_between(X448_TEMPLATE, &sender, &recipient).as_deref(),
            Some(&b"agreed content"[..])
        );
        let without_x448 = |policy: &mut xml_sec::policy::KeyEstablishmentPolicy| {
            policy.agreement_algorithms = Some(BTreeSet::from([
                KeyAgreementAlgorithm::EcdhEs,
                KeyAgreementAlgorithm::X25519,
            ]));
        };
        xml_sec_libxml2::policy::republish_encryption(
            |encryption| without_x448(&mut encryption.key_establishment),
            |decryption| without_x448(&mut decryption.key_establishment),
        )
        .expect("the library policy compiles");
        assert!(!encrypts_with(X448_TEMPLATE, &sender));
    });
}

const DH_FIRST_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-first-key.pem");
const DH_SECOND_KEY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-second-key.pem");
const DH_SECOND_PUBLIC: &[u8] = include_bytes!(
    "../../../../../../tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-second-pubkey.pem"
);
const DH_FIRST_PUBLIC: &[u8] = include_bytes!(
    "../../../../../../tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-first-pubkey.pem"
);
/// The donor's DH-ES template: the originator's `KeyValue` an empty
/// `DHKeyValue` the encryption fills, the parties named by `KeyName`.
const DH_TEMPLATE: &str = include_str!(
    "../../../../../../tests/fixtures/xmlenc/aleksey-xmlenc-01/enc_dh_concatkdf_sha256_kw_aes128_aes128gcm.tmpl"
);

/// Enables in the `KeyInfo` context `ctx` the klasses the donor's DH-ES
/// recipe names (`agreement-method,enc-key,key-value,key-name,dh`):
/// libxmlsec1 registers `KeyValue` disabled.
///
/// # Safety
/// `ctx` is an initialized `KeyInfo` context.
unsafe fn enable_dh_recipe(ctx: *mut XmlSecKeyInfoCtx) {
    use super::super::super::keysdata::{
        xmlSecKeyDataAgreementMethodGetKlass, xmlSecKeyDataEncryptedKeyGetKlass,
        xmlSecKeyDataNameGetKlass, xmlSecKeyDataValueGetKlass,
    };
    let klasses = [
        xmlSecKeyDataAgreementMethodGetKlass(),
        xmlSecKeyDataEncryptedKeyGetKlass(),
        xmlSecKeyDataValueGetKlass(),
        xmlSecKeyDataNameGetKlass(),
        asymkeys::dh(),
    ];
    for klass in klasses {
        // SAFETY: by the caller's contract; the klasses are static.
        let added = unsafe {
            super::super::super::list::xmlSecPtrListAdd(
                &raw mut (*ctx).enabled_key_data,
                klass.cast_mut().cast(),
            )
        };
        assert_eq!(added, 0);
    }
}

#[test]
fn dh_parties_agree_through_the_originators_key_value() {
    // DH-ES over RFC 5114 group 3 keys loaded from key files, with the
    // donor's enabled klasses: the originator writes its public key as the
    // DHKeyValue of its role (XML Encryption 1.1 section 5.6.1), and a
    // recipient that holds only its own private key reads it from there and
    // unwraps what the originator wrapped.
    with_library(|| {
        let plaintext = b"agreed content";
        // SAFETY: the library is initialized; every object is released.
        unsafe {
            let doc = document(DH_TEMPLATE);
            let sender = manager(&[
                (DH_FIRST_KEY, c"dhx-rfc5114-3-first"),
                (DH_SECOND_PUBLIC, c"dhx-rfc5114-3-second"),
            ]);
            let ctx = xmlSecEncCtxCreate(sender);
            (*ctx).key_info_read_ctx.max_encrypted_key_level = 3;
            (*ctx).key_info_write_ctx.max_encrypted_key_level = 3;
            enable_dh_recipe(&raw mut (*ctx).key_info_read_ctx);
            enable_dh_recipe(&raw mut (*ctx).key_info_write_ctx);
            (*ctx).enc_key = xmlSecKeyGenerate(symkeys::aes(), 128, TYPE_SESSION);
            let encrypted = xmlSecEncCtxBinaryEncrypt(
                ctx,
                xsDocGetRootElement(doc.cast()),
                plaintext.as_ptr(),
                plaintext.len(),
            );
            xmlSecEncCtxDestroy(ctx);
            assert_eq!(encrypted, 0, "the originator encrypts");
            let recipient = manager(&[(DH_SECOND_KEY, c"dhx-rfc5114-3-second")]);
            let ctx = xmlSecEncCtxCreate(recipient);
            (*ctx).key_info_read_ctx.max_encrypted_key_level = 3;
            enable_dh_recipe(&raw mut (*ctx).key_info_read_ctx);
            let result = xmlSecEncCtxDecryptToBuffer(ctx, xsDocGetRootElement(doc.cast()));
            let decrypted = (!result.is_null()).then(|| {
                std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                    .to_vec()
            });
            xmlSecEncCtxDestroy(ctx);
            xmlSecKeysMngrDestroy(recipient);
            xmlSecKeysMngrDestroy(sender);
            xsFreeDoc(doc.cast());
            assert_eq!(decrypted.as_deref(), Some(&plaintext[..]));
        }
    });
}

#[test]
fn a_dh_peer_of_another_group_is_no_party() {
    // DH-ES agrees only between keys of one group (RFC 2631 section 2.1.1):
    // the peer of the recipient's own group derives the key under a policy
    // admitting DH-ES, the same public value declared with another generator
    // is no peer, and the default policy, which admits no DH-ES, refuses it.
    with_library(|| {
        let mine = pem_key(DH_SECOND_KEY);
        let peer = pem_key(DH_FIRST_PUBLIC);
        let method = xml_sec::xmlenc::parse_key_derivation_method(
            "<xenc11:KeyDerivationMethod \
             xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" \
             xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" \
             Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\
             <xenc11:ConcatKDFParams AlgorithmID=\"00\" PartyUInfo=\"00\" PartyVInfo=\"00\">\
             <dsig:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
             </xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>",
            &xml_sec::policy::DecryptionPolicy::default(),
        )
        .expect("the method parses");
        let admitting = xml_sec::policy::KeyEstablishmentPolicy {
            agreement_algorithms: Some(BTreeSet::from([KeyAgreementAlgorithm::DhEs])),
            ..xml_sec::policy::KeyEstablishmentPolicy::default()
        };
        // SAFETY: the keys loaded above, released below.
        unsafe {
            let mine_material = material_of(xmlSecKeyGetValue(mine)).expect("a DH key");
            let peer_material = material_of(xmlSecKeyGetValue(peer)).expect("a DH key");
            let mut usage = xml_sec::key_establishment::KeyEstablishmentUsage::default();
            let agree_with = |peer: &Material, policy, usage: &mut _| {
                agree(
                    KeyAgreementAlgorithm::DhEs,
                    &method,
                    16,
                    Party::Value(mine_material),
                    Party::Value(peer),
                    policy,
                    usage,
                )
            };
            let derived = agree_with(peer_material, &admitting, &mut usage)
                .expect("the parties share a group");
            assert_eq!(derived.len(), 16);
            let mut other = peer_material.clone();
            let KeyValueInfo::Dh {
                generator: Some(generator),
                ..
            } = &mut other.value
            else {
                panic!("a DH key value with its group");
            };
            generator[0] ^= 1;
            assert!(matches!(
                agree_with(&other, &admitting, &mut usage),
                Err(XmlEncError::KeyNotFound)
            ));
            let default = xml_sec::policy::KeyEstablishmentPolicy::default();
            assert!(matches!(
                agree_with(peer_material, &default, &mut usage),
                Err(XmlEncError::Policy(_))
            ));
            xmlSecKeyDestroy(mine);
            xmlSecKeyDestroy(peer);
        }
    });
}

#[test]
fn a_concat_kdf_defaults_to_its_digest_width() {
    // A reader that expects no width gets the ConcatKDF digest's output, as
    // libxmlsec1 falls back to it; any other derivation has no default.
    let parse = |xml: &str| {
        xml_sec::xmlenc::parse_key_derivation_method(
            xml,
            &xml_sec::policy::DecryptionPolicy::default(),
        )
        .expect("the method parses")
    };
    let concat = parse(
        "<xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" \
         xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" \
         Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\
         <xenc11:ConcatKDFParams AlgorithmID=\"00\" PartyUInfo=\"00\" PartyVInfo=\"00\">\
         <dsig:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha384\"/>\
         </xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>",
    );
    assert_eq!(default_width(&concat), 48);
    let hkdf = parse(
        "<xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" \
         Algorithm=\"http://www.w3.org/2021/04/xmldsig-more#hkdf\">\
         <m:HKDFParams xmlns:m=\"http://www.w3.org/2021/04/xmldsig-more#\">\
         <m:PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>\
         <m:KeyLength>32</m:KeyLength></m:HKDFParams></xenc11:KeyDerivationMethod>",
    );
    assert_eq!(default_width(&hkdf), 0);
}
