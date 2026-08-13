use std::io::Write;

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

pub fn contains_all(values: &[&str], requested: &[String]) -> bool {
    requested
        .iter()
        .flat_map(|value| value.split(','))
        .all(|value| values.contains(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_comma_separated_and_repeated_capabilities() {
        assert!(contains_all(
            TRANSFORMS,
            &["c14n,rsa-sha256".into(), "sha256".into()]
        ));
        assert!(!contains_all(TRANSFORMS, &["xslt".into()]));
        assert!(contains_all(TRANSFORMS, &["rsa-oaep-enc11".into()]));
        assert!(!contains_all(KEY_DATA, &["key-name".into()]));
    }
}
