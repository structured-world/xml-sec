use std::{collections::HashSet, fs, io::Write};

use roxmltree::Document;
use xml_sec::{
    policy::{EncryptionPolicy, SigningPolicy, VerificationPolicy},
    provider::default_provider,
    xmldsig::{
        DefaultKeyResolver, DsigStatus, KeyResolverConfig, SignContext, SignatureAlgorithm,
        UriTypeSet, VerifyContext, X509CertificateKeyInfoWriter,
    },
    xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DecryptionKeyResolver,
        EncryptedDataBuilder, EncryptedDataType, PrivateKeyDecryptor, SymmetricKeyDecryptor,
    },
};

use crate::{
    Command, Invocation,
    capabilities::{self, KEY_DATA, TRANSFORMS},
    key_material,
};

const GENERIC_OPTIONS: &[&str] = &[
    // These options only select this fixed backend or control diagnostics; none
    // authorizes the core library to discover configuration or external data.
    "crypto",
    "crypto-config",
    "verbose",
    "print-crypto-library-errors",
    "print-debug",
    "print-xml-debug",
    "help",
];

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("{0}")]
    Usage(String),
    #[error("unsupported option for this command: --{0}")]
    UnsupportedOption(String),
    #[error("unsupported crypto provider: {0}")]
    UnsupportedProvider(String),
    #[error("I/O error for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Key(#[from] key_material::KeyMaterialError),
    #[error("XML signature operation failed: {0}")]
    Signature(String),
    #[error("signature is invalid")]
    InvalidSignature,
    #[error("XML encryption operation failed: {0}")]
    Encryption(String),
    #[error("requested capability is not available")]
    CapabilityUnavailable,
}

pub fn execute(
    invocation: Invocation,
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> Result<(), CommandError> {
    if invocation.flag("help") {
        return help(stdout);
    }
    validate_provider(&invocation)?;
    match invocation.command {
        Command::Help
        | Command::HelpAll
        | Command::HelpDsig
        | Command::HelpEnc
        | Command::HelpKeys
        | Command::HelpX509 => help(stdout),
        Command::Version => writeln!(stdout, "xmlsec1 1.3.13 (rustcrypto)").map_err(stdout_error),
        Command::ListTransforms => {
            validate_options(&invocation, &[])?;
            capabilities::list("transform klasses", TRANSFORMS, stdout).map_err(stdout_error)
        }
        Command::CheckTransforms => {
            validate_options(&invocation, &[])?;
            if capabilities::contains_all(TRANSFORMS, &invocation.positional) {
                Ok(())
            } else {
                Err(CommandError::CapabilityUnavailable)
            }
        }
        Command::ListKeyData => {
            validate_options(&invocation, &[])?;
            capabilities::list("key data klasses", KEY_DATA, stdout).map_err(stdout_error)
        }
        Command::CheckKeyData => {
            validate_options(&invocation, &[])?;
            if capabilities::contains_all(KEY_DATA, &invocation.positional) {
                Ok(())
            } else {
                Err(CommandError::CapabilityUnavailable)
            }
        }
        Command::Keys => keys(&invocation, stdout),
        Command::Sign | Command::SignTemplate => sign(&invocation, stdout),
        Command::Verify => verify(&invocation, stdout),
        Command::Encrypt => encrypt(&invocation, stdout),
        Command::Decrypt => decrypt(&invocation, stdout),
    }
}

fn help(output: &mut dyn Write) -> Result<(), CommandError> {
    writeln!(
        output,
        "Usage: xmlsec1 <command> [options] [files]\n\
         Commands: sign verify encrypt decrypt keys list-transforms check-transforms \
         list-key-data check-key-data"
    )
    .map_err(stdout_error)
}

fn validate_provider(invocation: &Invocation) -> Result<(), CommandError> {
    if let Some(provider) = invocation.last_value("crypto")
        && !matches!(provider, "rustcrypto" | "default")
    {
        return Err(CommandError::UnsupportedProvider(provider.to_owned()));
    }
    Ok(())
}

fn validate_options(invocation: &Invocation, command_options: &[&str]) -> Result<(), CommandError> {
    for name in invocation.options.keys() {
        if !GENERIC_OPTIONS.contains(&name.as_str()) && !command_options.contains(&name.as_str()) {
            return Err(CommandError::UnsupportedOption(name.clone()));
        }
    }
    Ok(())
}

fn input_path(invocation: &Invocation) -> Result<&str, CommandError> {
    if invocation.positional.len() != 1 {
        return Err(CommandError::Usage(format!(
            "{} expects exactly one input file",
            invocation.command
        )));
    }
    Ok(&invocation.positional[0])
}

fn read_input(invocation: &Invocation) -> Result<String, CommandError> {
    let path = input_path(invocation)?;
    fs::read_to_string(path).map_err(|source| CommandError::Io {
        path: path.to_owned(),
        source,
    })
}

fn write_output(
    invocation: &Invocation,
    bytes: &[u8],
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    if let Some(path) = invocation.last_value("output") {
        fs::write(path, bytes).map_err(|source| CommandError::Io {
            path: path.to_owned(),
            source,
        })
    } else {
        stdout.write_all(bytes).map_err(stdout_error)
    }
}

fn sign(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(
        invocation,
        &[
            "output",
            "privkey-pem",
            "privkey-der",
            "pkcs8-pem",
            "pkcs8-der",
            "pwd",
            "lax-key-search",
            "node-id",
            "node-name",
            "node-xpath",
            "id-attr",
            "add-id-attr",
        ],
    )?;
    reject_unimplemented_selectors(invocation, &[])?;
    if invocation.last_value("pwd").is_some() {
        return Err(CommandError::UnsupportedOption("pwd".into()));
    }
    let key_option = ["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"]
        .into_iter()
        .find_map(|name| invocation.values(name).next());
    let key_option = key_option.ok_or_else(|| {
        CommandError::Usage("sign requires --privkey-pem or --pkcs8-pem/der".into())
    })?;
    let value = key_option.value.as_deref().unwrap_or_default();
    let mut files = value.split(',');
    let key_path = files.next().unwrap_or_default();
    let certificate_path = files.next();
    if files.next().is_some() {
        return Err(CommandError::Usage(
            "private key accepts at most one certificate path".into(),
        ));
    }
    let xml = read_input(invocation)?;
    let key = key_material::load_signing_key(key_path)?;
    let policy = SigningPolicy::default();
    let signed = if let Some(certificate_path) = certificate_path {
        let certificate = key_material::read_text(certificate_path)?;
        let writer = X509CertificateKeyInfoWriter::from_pem(&certificate)
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        SignContext::new(key.as_ref())
            .policy(policy)
            .key_info_writer(&writer)
            .sign_template(&xml)
    } else {
        SignContext::new(key.as_ref())
            .policy(policy)
            .sign_template(&xml)
    }
    .map_err(|error| CommandError::Signature(error.to_string()))?;
    write_output(invocation, signed.as_bytes(), stdout)
}

fn verification_policy(invocation: &Invocation) -> VerificationPolicy {
    let mut policy = VerificationPolicy {
        process_manifests: !invocation.flag("ignore-manifests"),
        reference_uri_types: UriTypeSet::ALL,
        retrieval_uri_types: UriTypeSet::ALL,
        ..VerificationPolicy::default()
    };
    policy.key_trust.allowed_legacy_signature_algorithms = HashSet::from([
        SignatureAlgorithm::RsaSha1,
        SignatureAlgorithm::DsaSha1,
        SignatureAlgorithm::HmacSha1,
    ]);
    policy.key_trust.check_crls = invocation.flag("verify-crls");
    policy.key_trust.verify_x509_chains = !invocation.flag("insecure")
        && (invocation.values("trusted-pem").next().is_some()
            || invocation.values("trusted-der").next().is_some());
    policy
}

fn verify(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(
        invocation,
        &[
            "pubkey-pem",
            "pubkey-der",
            "pubkey-cert-pem",
            "pubkey-cert-der",
            "trusted-pem",
            "trusted-der",
            "untrusted-pem",
            "untrusted-der",
            "enabled-reference-uris",
            "enabled-retrieval-uris",
            "ignore-manifests",
            "lax-key-search",
            "verify-crls",
            "X509-skip-time-checks",
            "insecure",
            "verification-time",
            "depth",
            "node-id",
            "node-name",
            "node-xpath",
            "id-attr",
            "add-id-attr",
            "url-map",
        ],
    )?;
    reject_unimplemented_selectors(invocation, &[])?;
    reject_unimplemented_verification_policy(invocation)?;
    let direct_path = ["pubkey-pem", "pubkey-der"]
        .into_iter()
        .find_map(|name| invocation.last_value(name));
    // With an explicit public key there is no key-manager search to relax.
    // Reject the flag on resolver-backed paths until its semantics exist.
    if invocation.flag("lax-key-search") && direct_path.is_none() {
        return Err(CommandError::UnsupportedOption("lax-key-search".into()));
    }
    let xml = read_input(invocation)?;
    let algorithm = key_material::signature_algorithm(&xml)?;
    let policy = verification_policy(invocation);
    let result = if let Some(path) = direct_path {
        let key = key_material::load_verification_key(path, algorithm)?;
        VerifyContext::new().policy(policy).key(&key).verify(&xml)
    } else {
        let mut config = KeyResolverConfig::default();
        for name in [
            "pubkey-cert-pem",
            "pubkey-cert-der",
            "untrusted-pem",
            "untrusted-der",
        ] {
            for option in invocation.values(name) {
                config.lookup_certs.push(key_material::load_certificate(
                    option.value.as_deref().unwrap_or_default(),
                )?);
            }
        }
        for name in ["trusted-pem", "trusted-der"] {
            for option in invocation.values(name) {
                config.trusted_certs.push(key_material::load_certificate(
                    option.value.as_deref().unwrap_or_default(),
                )?);
            }
        }
        let resolver = DefaultKeyResolver::new(config);
        VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .verify(&xml)
    }
    .map_err(|error| CommandError::Signature(error.to_string()))?;
    if result.status != DsigStatus::Valid
        || result
            .manifest_references
            .iter()
            .any(|reference| reference.status != DsigStatus::Valid)
    {
        return Err(CommandError::InvalidSignature);
    }
    if invocation.flag("print-debug") || invocation.flag("print-xml-debug") {
        writeln!(stdout, "Status: valid").map_err(stdout_error)?;
    }
    Ok(())
}

fn encrypt(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(
        invocation,
        &[
            "output",
            "binary-data",
            "xml-data",
            "aes-key",
            "pubkey-pem",
            "pubkey-der",
            "lax-key-search",
            "node-id",
            "node-name",
            "node-xpath",
            "id-attr",
            "add-id-attr",
        ],
    )?;
    reject_unimplemented_selectors(invocation, &[])?;
    let template = read_input(invocation)?;
    let (algorithm, encrypted_type) = encryption_template(&template)?;
    let mut builder = EncryptedDataBuilder::new(algorithm).policy(EncryptionPolicy::default());
    if let Some(option) = invocation.values("aes-key").next() {
        let key = key_material::load_symmetric(
            option.value.as_deref().unwrap_or_default(),
            Some(algorithm.key_len()),
        )?;
        builder = builder.direct_key(key);
        if let Some(name) = option.parameter.as_deref() {
            builder = builder.direct_key_name(name);
        }
    } else if let Some(path) = ["pubkey-pem", "pubkey-der"]
        .into_iter()
        .find_map(|name| invocation.last_value(name))
    {
        builder = builder.recipient_rsa_oaep(key_material::load_rsa_public(path)?);
    } else {
        return Err(CommandError::Usage(
            "encrypt requires --aes-key or --pubkey-pem".into(),
        ));
    }
    builder = builder.encryption_type(encrypted_type);
    let result = if let Some(path) = invocation.last_value("binary-data") {
        let data = key_material::read(path)?;
        builder.encrypt_binary(&data)
    } else if let Some(path) = invocation.last_value("xml-data") {
        let data = key_material::read_text(path)?;
        builder.encrypt_xml(&data)
    } else {
        return Err(CommandError::Usage(
            "encrypt requires --binary-data or --xml-data".into(),
        ));
    }
    .map_err(|error| CommandError::Encryption(error.to_string()))?;
    write_output(invocation, result.encrypted_data_xml.as_bytes(), stdout)
}

fn decrypt(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(
        invocation,
        &[
            "output",
            "aes-key",
            "privkey-pem",
            "privkey-der",
            "pkcs8-pem",
            "pkcs8-der",
            "pwd",
            "lax-key-search",
            "node-id",
            "node-name",
            "node-xpath",
            "id-attr",
            "add-id-attr",
        ],
    )?;
    reject_unimplemented_selectors(invocation, &["node-id"])?;
    if invocation.last_value("pwd").is_some() {
        return Err(CommandError::UnsupportedOption("pwd".into()));
    }
    let xml = read_input(invocation)?;
    let encrypted_data_id = invocation.last_value("node-id");
    let bytes = if let Some(option) = invocation.values("aes-key").next() {
        let key = key_material::load_symmetric(option.value.as_deref().unwrap_or_default(), None)?;
        decrypt_input(&SymmetricKeyDecryptor::new(key), &xml, encrypted_data_id)?
    } else if let Some(path) = ["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"]
        .into_iter()
        .find_map(|name| invocation.last_value(name))
    {
        let resolver = PrivateKeyDecryptor::new(key_material::load_rsa_private(path)?);
        decrypt_input(&resolver, &xml, encrypted_data_id)?
    } else {
        return Err(CommandError::Usage(
            "decrypt requires --aes-key or an RSA private key".into(),
        ));
    };
    write_output(invocation, &bytes, stdout)
}

fn decrypt_input(
    resolver: &dyn DecryptionKeyResolver,
    xml: &str,
    encrypted_data_id: Option<&str>,
) -> Result<Vec<u8>, CommandError> {
    let document =
        Document::parse(xml).map_err(|error| CommandError::Encryption(error.to_string()))?;
    let standalone = document
        .root_element()
        .has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData"));
    let context = DecryptContext::new(resolver);
    if standalone && encrypted_data_id.is_none() {
        return context
            .decrypt(xml)
            .map(|content| match content {
                DecryptedContent::Xml(xml) => xml.into_bytes(),
                DecryptedContent::Bytes(bytes) => bytes,
            })
            .map_err(|error| CommandError::Encryption(error.to_string()));
    }
    context
        .decrypt_document(xml, encrypted_data_id)
        .map(String::into_bytes)
        .map_err(|error| CommandError::Encryption(error.to_string()))
}

fn encryption_template(
    xml: &str,
) -> Result<(DataEncryptionAlgorithm, EncryptedDataType), CommandError> {
    let document =
        Document::parse(xml).map_err(|error| CommandError::Encryption(error.to_string()))?;
    let encrypted_data = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "EncryptedData")
        .ok_or_else(|| CommandError::Encryption("template has no EncryptedData".into()))?;
    let method = encrypted_data
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "EncryptionMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .ok_or_else(|| CommandError::Encryption("template has no encryption algorithm".into()))?;
    let algorithm = DataEncryptionAlgorithm::from_uri(method)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let encrypted_type = match encrypted_data.attribute("Type") {
        Some("http://www.w3.org/2001/04/xmlenc#Content") => EncryptedDataType::Content,
        _ => EncryptedDataType::Element,
    };
    Ok((algorithm, encrypted_type))
}

fn keys(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, &["gen-key"])?;
    let generated = invocation.values("gen-key").collect::<Vec<_>>();
    if generated.is_empty() {
        return Err(CommandError::Usage(
            "keys requires --gen-key:name algorithm".into(),
        ));
    }
    let mut entries = String::new();
    for generated in generated {
        let name = generated
            .parameter
            .as_deref()
            .ok_or_else(|| CommandError::Usage("--gen-key requires a key name".into()))?;
        let algorithm = generated.value.as_deref().unwrap_or_default();
        let size = match algorithm {
            "aes-128" => 16,
            "aes-192" => 24,
            "aes-256" => 32,
            _ => return Err(CommandError::CapabilityUnavailable),
        };
        let mut key = vec![0_u8; size];
        default_provider()
            .fill_random(&mut key)
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
        let name = quick_xml::escape::escape(name);
        entries.push_str(&format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n\
             <KeyName>{name}</KeyName>\n\
             <KeyValue>\n\
             <AESKeyValue xmlns=\"http://www.aleksey.com/xmlsec/2002\">{encoded}</AESKeyValue>\n\
             </KeyValue>\n\
             </KeyInfo>\n"
        ));
    }
    let document = format!(
        "<?xml version=\"1.0\"?>\n<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\">\n\
         {entries}</Keys>\n"
    );
    if invocation.positional.len() > 1 {
        return Err(CommandError::Usage(
            "keys accepts at most one key-store path".into(),
        ));
    }
    if let Some(path) = invocation.positional.first() {
        fs::write(path, document.as_bytes()).map_err(|source| CommandError::Io {
            path: path.clone(),
            source,
        })
    } else {
        stdout.write_all(document.as_bytes()).map_err(stdout_error)
    }
}

fn reject_unimplemented_selectors(
    invocation: &Invocation,
    supported: &[&str],
) -> Result<(), CommandError> {
    for name in [
        "node-id",
        "node-name",
        "node-xpath",
        "id-attr",
        "add-id-attr",
    ] {
        if !supported.contains(&name) && invocation.options.contains_key(name) {
            return Err(CommandError::UnsupportedOption(name.into()));
        }
    }
    Ok(())
}

fn reject_unimplemented_verification_policy(invocation: &Invocation) -> Result<(), CommandError> {
    for name in [
        "enabled-reference-uris",
        "enabled-retrieval-uris",
        "X509-skip-time-checks",
        "verification-time",
        "depth",
        "url-map",
    ] {
        if invocation.options.contains_key(name) {
            return Err(CommandError::UnsupportedOption(name.into()));
        }
    }
    Ok(())
}

fn stdout_error(source: std::io::Error) -> CommandError {
    CommandError::Io {
        path: "stdout".into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn invocation(arguments: &[&str]) -> Invocation {
        Invocation::parse(arguments.iter().map(OsString::from)).unwrap()
    }

    #[test]
    fn capability_checks_fail_closed() {
        let mut output = Vec::new();
        assert!(
            execute(
                invocation(&["xmlsec1", "check-transforms", "c14n", "rsa-sha256"]),
                &mut output,
                &mut Vec::new()
            )
            .is_ok()
        );
        assert!(matches!(
            execute(
                invocation(&["xmlsec1", "check-transforms", "xslt"]),
                &mut output,
                &mut Vec::new()
            ),
            Err(CommandError::CapabilityUnavailable)
        ));
    }

    #[test]
    fn unsupported_provider_never_falls_back() {
        let error = execute(
            invocation(&["xmlsec1", "version", "--crypto", "openssl"]),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(error, CommandError::UnsupportedProvider(_)));
    }

    #[test]
    fn command_help_is_an_action_and_semantic_no_ops_fail_closed() {
        let mut output = Vec::new();
        execute(
            invocation(&["xmlsec1", "verify", "--help"]),
            &mut output,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(String::from_utf8(output).unwrap().starts_with("Usage:"));

        let error = execute(
            invocation(&["xmlsec1", "verify", "--lax-key-search", "input.xml"]),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(error, CommandError::UnsupportedOption(_)));
    }
}
