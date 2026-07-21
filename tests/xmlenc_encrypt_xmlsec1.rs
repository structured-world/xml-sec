//! External decryption interoperability for XMLEnc produced by xml-sec.

#![cfg(feature = "xmlenc")]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, EncryptedDataBuilder, EncryptionRecipient, OaepDigestAlgorithm,
    RsaOaepParameters,
};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn path(label: &str, extension: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_nanos();
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            path: std::env::temp_dir().join(format!(
                "xml-sec-{label}-{}-{timestamp}-{sequence}.{extension}",
                std::process::id()
            )),
        }
    }

    fn write(label: &str, extension: &str, contents: &[u8]) -> Self {
        let file = Self::path(label, extension);
        fs::write(&file.path, contents)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", file.path.display()));
        file
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn xmlsec1_version_supports_interop(version: &str) -> bool {
    version
        .split_whitespace()
        .find_map(|token| {
            let mut components = token.split('.');
            Some((
                components.next()?.parse::<u16>().ok()?,
                components.next()?.parse::<u16>().ok()?,
                components.next()?.parse::<u16>().ok()?,
            ))
        })
        .is_some_and(|version| version >= (1, 3, 8))
}

fn xmlsec1_is_available() -> bool {
    let Ok(output) = Command::new("xmlsec1").arg("--version").output() else {
        return false;
    };
    output.status.success()
        && std::str::from_utf8(&output.stdout).is_ok_and(xmlsec1_version_supports_interop)
}

fn decrypt_with_xmlsec1(encrypted_xml: &str, key_option: &str, key_path: &Path) -> Vec<u8> {
    let input = TemporaryFile::write("xmlenc-input", "xml", encrypted_xml.as_bytes());
    let output = TemporaryFile::path("xmlenc-output", "data");
    let command_output = Command::new("xmlsec1")
        .arg("decrypt")
        .arg("--lax-key-search")
        .arg(key_option)
        .arg(key_path)
        .arg("--output")
        .arg(&output.path)
        .arg(&input.path)
        .output()
        .expect("xmlsec1 must be installed for XMLEnc interoperability tests");
    assert!(
        command_output.status.success(),
        "xmlsec1 rejected xml-sec ciphertext:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&command_output.stdout),
        String::from_utf8_lossy(&command_output.stderr)
    );
    fs::read(&output.path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", output.path.display()))
}

#[test]
fn xmlsec1_version_gate_accepts_ci_version() {
    assert!(!xmlsec1_version_supports_interop("xmlsec1 1.3.7 (openssl)"));
    assert!(xmlsec1_version_supports_interop("xmlsec1 1.3.8 (openssl)"));
    assert!(xmlsec1_version_supports_interop("xmlsec1 1.3.12 (openssl)"));
}

#[test]
fn xmlsec1_decrypts_direct_aes_gcm_from_xml_sec() {
    // This validates nonce/tag framing and direct KeyName XML against an
    // independent implementation rather than our reciprocal decrypt path.
    if !xmlsec1_is_available() {
        eprintln!("skipping XMLEnc interop: xmlsec1 >= 1.3.8 is not installed");
        return;
    }
    let key = [0x4a; 16];
    let plaintext = b"xmlsec1 direct AES-GCM interoperability";
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .direct_key_name("interop-aes")
        .encrypt_binary(plaintext)
        .expect("direct AES-GCM encryption must succeed");
    let key_file = TemporaryFile::write("xmlenc-aes-key", "bin", &key);

    assert_eq!(
        decrypt_with_xmlsec1(
            &encrypted.encrypted_data_xml,
            "--aeskey:interop-aes",
            &key_file.path
        ),
        plaintext
    );
}

#[test]
fn xmlsec1_decrypts_rsa_oaep_wrapped_aes_cbc_from_xml_sec() {
    // This covers generated session-key transport, OAEP digest/MGF metadata,
    // nested EncryptedKey lookup, and XMLEnc CBC random-padding framing.
    if !xmlsec1_is_available() {
        eprintln!("skipping XMLEnc interop: xmlsec1 >= 1.3.8 is not installed");
        return;
    }
    let public_key_path = Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let private_key_path = Path::new("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let public_key = RsaPublicKey::from_public_key_pem(
        &fs::read_to_string(public_key_path).expect("RSA public-key fixture must load"),
    )
    .expect("RSA public-key fixture must contain SPKI PEM");
    let plaintext = b"xmlsec1 RSA-OAEP and AES-CBC interoperability";
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Cbc)
        .add_recipient(
            EncryptionRecipient::rsa_oaep(public_key)
                .oaep_parameters(
                    RsaOaepParameters::xmlenc11(
                        OaepDigestAlgorithm::Sha256,
                        OaepDigestAlgorithm::Sha256,
                    )
                    .label(b"xmlsec1-interop-label".to_vec()),
                )
                .key_name("interop-rsa"),
        )
        .encrypt_binary(plaintext)
        .expect("RSA-OAEP encryption must succeed");

    assert_eq!(
        decrypt_with_xmlsec1(
            &encrypted.encrypted_data_xml,
            "--privkey-pem:interop-rsa",
            private_key_path
        ),
        plaintext
    );
}
