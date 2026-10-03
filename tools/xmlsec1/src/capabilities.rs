use std::{ffi::OsString, io::Write};

pub const TRANSFORMS: &[&str] = &[
    "base64",
    "enveloped-signature",
    "c14n",
    "c14n-with-comments",
    "c14n11",
    "c14n11-with-comments",
    "exc-c14n",
    "exc-c14n-with-comments",
    "xpath",
    "xpath2",
    "dsa-sha1",
    "ecdsa-sha256",
    "ecdsa-sha384",
    "ecdsa-sha1",
    "ecdsa-sha224",
    "ecdsa-sha512",
    "ecdsa-sha3-224",
    "ecdsa-sha3-256",
    "ecdsa-sha3-384",
    "ecdsa-sha3-512",
    "eddsa-ed25519",
    "eddsa-ed25519ctx",
    "eddsa-ed25519ph",
    "eddsa-ed448",
    "eddsa-ed448ph",
    #[cfg(feature = "experimental-pq")]
    "ml-dsa-44",
    #[cfg(feature = "experimental-pq")]
    "ml-dsa-65",
    #[cfg(feature = "experimental-pq")]
    "ml-dsa-87",
    #[cfg(feature = "experimental-pq")]
    "slh-dsa-sha2-128s",
    #[cfg(feature = "experimental-pq")]
    "slh-dsa-sha2-128f",
    #[cfg(feature = "experimental-pq")]
    "slh-dsa-sha2-192s",
    #[cfg(feature = "experimental-pq")]
    "slh-dsa-sha2-192f",
    #[cfg(feature = "experimental-pq")]
    "slh-dsa-sha2-256s",
    #[cfg(feature = "experimental-pq")]
    "slh-dsa-sha2-256f",
    "rsa-sha1",
    "rsa-sha256",
    "rsa-sha384",
    "rsa-sha512",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "aes128-cbc",
    "aes256-cbc",
    "aes128-gcm",
    "aes256-gcm",
    "rsa-oaep-mgf1p",
    "rsa-oaep-enc11",
];

// Key-data names describe complete CLI loading/resolution paths. They do not
// advertise `keys --gen-key` algorithms; that command has a separate registry.
pub const KEY_DATA: &[&str] = &[
    "key-value",
    "der-encoded-key-value",
    "aes",
    "rsa",
    "ec",
    "eddsa",
    #[cfg(feature = "experimental-pq")]
    "ml-dsa",
    #[cfg(feature = "experimental-pq")]
    "slh-dsa",
    "x509",
    "raw-x509-cert",
];

pub const KEY_GENERATION_ALGORITHMS: &[(&str, usize)] =
    &[("aes-128", 16), ("aes-192", 24), ("aes-256", 32)];

pub fn generated_key_len(algorithm: &str) -> Option<usize> {
    KEY_GENERATION_ALGORITHMS
        .iter()
        .find_map(|(name, bytes)| (*name == algorithm).then_some(*bytes))
}

pub fn list(label: &str, values: &[&str], output: &mut dyn Write) -> std::io::Result<()> {
    writeln!(output, "Registered {label}:")?;
    if values.is_empty() {
        return writeln!(output, "(none)");
    }
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            write!(output, ",")?;
        }
        write!(output, "\"{value}\"")?;
    }
    writeln!(output)
}

pub fn all_requested_available(values: &[&str], requested: &[OsString]) -> bool {
    // libxmlsec1 treats an empty check as a vacuously successful query. Keep
    // that process contract distinct from fail-closed handling of unknown names.
    requested
        .iter()
        .map(|value| value.to_str())
        .flat_map(|value| value.into_iter().flat_map(|value| value.split(',')))
        .all(|value| values.contains(&value))
        && requested.iter().all(|value| value.to_str().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_signature_and_digest_capabilities_are_discoverable() {
        // Capability queries must agree with the actual public signing path.
        for name in ["ecdsa-sha3-256", "sha3-256", "eddsa-ed25519", "eddsa-ed448"] {
            assert!(TRANSFORMS.contains(&name), "missing {name}");
        }
        assert!(KEY_DATA.contains(&"eddsa"));
        assert_eq!(
            TRANSFORMS.contains(&"ml-dsa-44"),
            cfg!(feature = "experimental-pq")
        );
    }

    #[test]
    fn checks_comma_separated_and_repeated_capabilities() {
        assert!(all_requested_available(
            TRANSFORMS,
            &["c14n,rsa-sha256".into(), "sha256".into()]
        ));
        assert!(!all_requested_available(TRANSFORMS, &["xslt".into()]));
        assert!(all_requested_available(
            TRANSFORMS,
            &["rsa-oaep-enc11".into()]
        ));
        assert!(all_requested_available(
            TRANSFORMS,
            &["rsa-oaep-mgf1p".into()]
        ));
        assert!(!all_requested_available(KEY_DATA, &["key-name".into()]));
    }

    #[test]
    fn empty_queries_match_the_donor_vacuous_success_contract() {
        // No requested names means no missing capabilities in libxmlsec1.
        assert!(all_requested_available(TRANSFORMS, &[]));
    }

    #[test]
    fn key_data_capabilities_are_distinct_from_generation_algorithms() {
        assert!(KEY_DATA.contains(&"rsa"));
        assert_eq!(generated_key_len("aes-128"), Some(16));
        assert_eq!(generated_key_len("rsa-1024"), None);
    }

    #[test]
    fn list_has_stable_empty_and_non_empty_representations() {
        let mut output = Vec::new();
        list("transforms", &[], &mut output).unwrap();
        assert_eq!(output, b"Registered transforms:\n(none)\n");

        output.clear();
        list("transforms", &["c14n", "sha256"], &mut output).unwrap();
        assert_eq!(output, b"Registered transforms:\n\"c14n\",\"sha256\"\n");
    }
}
