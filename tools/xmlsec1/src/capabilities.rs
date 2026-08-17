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
    "rsa-sha1",
    "rsa-sha256",
    "rsa-sha384",
    "rsa-sha512",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    "aes128-cbc",
    "aes256-cbc",
    "aes128-gcm",
    "aes256-gcm",
    "rsa-oaep-mgf1p",
    "rsa-oaep-enc11",
];

// Key-data names describe complete CLI loading paths, not provider primitives.
pub const KEY_DATA: &[&str] = &[
    "key-value",
    "der-encoded-key-value",
    "aes",
    "rsa",
    "ec",
    "x509",
    "raw-x509-cert",
];

pub fn list(label: &str, values: &[&str], output: &mut dyn Write) -> std::io::Result<()> {
    writeln!(output, "Registered {label}:")?;
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
}
