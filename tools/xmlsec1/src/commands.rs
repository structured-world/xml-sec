use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use roxmltree::Document;
use xml_sec::{
    policy::{DecryptionPolicy, EncryptionPolicy, SigningPolicy, VerificationPolicy},
    provider::default_provider,
    xmldsig::{
        DefaultKeyResolver, DsigStatus, KeyResolver, KeyResolverConfig, SignContext,
        SignatureAlgorithm, UriTypeSet, VerifyContext, X509CertificateKeyInfoWriter,
        parse_key_info,
    },
    xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DecryptionKeyResolver,
        EncryptedDataBuilder, EncryptedDataType, EncryptionRecipient, KeyTransportAlgorithm,
        OaepDigestAlgorithm, PrivateKeyDecryptor, RsaOaepParameters, SymmetricKeyDecryptor,
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
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const XMLENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("{0}")]
    Usage(String),
    #[error("unsupported option for this command: --{0}")]
    UnsupportedOption(String),
    #[error("unsupported crypto provider: {0}")]
    UnsupportedProvider(String),
    #[error("I/O error for {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("input XML exceeds policy limit of {maximum} bytes")]
    InputTooLarge { maximum: usize },
    #[error("input XML is not valid UTF-8")]
    InvalidUtf8Input,
    #[error("encryption plaintext exceeds policy limit of {maximum} bytes")]
    PlaintextTooLarge { maximum: usize },
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
    validate_crypto_config(&invocation)?;
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
            if capabilities::all_requested_available(TRANSFORMS, &invocation.positional) {
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
            if capabilities::all_requested_available(KEY_DATA, &invocation.positional) {
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
    if let Some(provider) = option_text(invocation, "crypto")?
        && !matches!(provider, "rustcrypto" | "default")
    {
        return Err(CommandError::UnsupportedProvider(provider.to_owned()));
    }
    Ok(())
}

fn validate_crypto_config(invocation: &Invocation) -> Result<(), CommandError> {
    let Some(path) = invocation.last_value("crypto-config") else {
        return Ok(());
    };
    let path = Path::new(path);
    if !path.exists() {
        // The upstream runners always pass their backend-specific config path;
        // for providers without external configuration that path is absent.
        return Ok(());
    }
    let empty_directory = path.is_dir()
        && fs::read_dir(path)
            .map_err(|source| CommandError::Io {
                path: path.to_owned(),
                source,
            })?
            .next()
            .is_none();
    if empty_directory {
        Ok(())
    } else {
        Err(CommandError::UnsupportedOption("crypto-config".into()))
    }
}

fn validate_options(invocation: &Invocation, command_options: &[&str]) -> Result<(), CommandError> {
    for name in invocation.options.keys() {
        if !GENERIC_OPTIONS.contains(&name.as_str()) && !command_options.contains(&name.as_str()) {
            return Err(CommandError::UnsupportedOption(name.clone()));
        }
    }
    Ok(())
}

fn input_path(invocation: &Invocation) -> Result<&OsStr, CommandError> {
    if invocation.positional.len() != 1 {
        return Err(CommandError::Usage(format!(
            "{} expects exactly one input file",
            invocation.command
        )));
    }
    Ok(&invocation.positional[0])
}

fn read_input(invocation: &Invocation, maximum: usize) -> Result<String, CommandError> {
    let path = input_path(invocation)?;
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    if path == OsStr::new("-") {
        std::io::stdin()
            .lock()
            .take(maximum.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| CommandError::Io {
                path: PathBuf::from("stdin"),
                source,
            })?;
    } else {
        File::open(path)
            .map_err(|source| CommandError::Io {
                path: PathBuf::from(path),
                source,
            })?
            .take(maximum.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| CommandError::Io {
                path: PathBuf::from(path),
                source,
            })?;
    }
    if bytes.len() > maximum {
        return Err(CommandError::InputTooLarge { maximum });
    }
    String::from_utf8(bytes).map_err(|_| CommandError::InvalidUtf8Input)
}

fn write_output(
    invocation: &Invocation,
    bytes: &[u8],
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    if let Some(template) = invocation.last_value("output") {
        let path = expand_output_path(invocation, template)?;
        fs::write(&path, bytes).map_err(|source| CommandError::Io { path, source })
    } else {
        stdout.write_all(bytes).map_err(stdout_error)
    }
}

fn expand_output_path(invocation: &Invocation, template: &OsStr) -> Result<PathBuf, CommandError> {
    const PLACEHOLDER: &[u8] = b"{inputfile}";
    let template_bytes = template.as_encoded_bytes();
    let Some(start) = template_bytes
        .windows(PLACEHOLDER.len())
        .position(|candidate| candidate == PLACEHOLDER)
    else {
        return Ok(PathBuf::from(template));
    };
    let input = input_path(invocation)?;
    let basename = Path::new(input)
        .file_name()
        .unwrap_or(input)
        .as_encoded_bytes();
    let stem = basename
        .iter()
        .rposition(|byte| *byte == b'.')
        .map_or(basename, |dot| &basename[..dot]);
    let mut expanded = Vec::with_capacity(template_bytes.len() - PLACEHOLDER.len() + stem.len());
    expanded.extend_from_slice(&template_bytes[..start]);
    expanded.extend_from_slice(stem);
    expanded.extend_from_slice(&template_bytes[start + PLACEHOLDER.len()..]);
    // The placeholder is ASCII and every other boundary comes from a complete
    // OsStr, so concatenation preserves the platform's encoded-byte contract.
    Ok(PathBuf::from(unsafe {
        OsString::from_encoded_bytes_unchecked(expanded)
    }))
}

fn read_plaintext(path: &OsStr, maximum: usize) -> Result<Vec<u8>, CommandError> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    File::open(path)
        .map_err(|source| CommandError::Io {
            path: PathBuf::from(path),
            source,
        })?
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CommandError::Io {
            path: PathBuf::from(path),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(CommandError::PlaintextTooLarge { maximum });
    }
    Ok(bytes)
}

fn option_text<'a>(
    invocation: &'a Invocation,
    name: &str,
) -> Result<Option<&'a str>, CommandError> {
    invocation
        .last_value(name)
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| CommandError::Usage(format!("--{name} value must be valid UTF-8")))
        })
        .transpose()
}

fn option_value_text(option: &crate::OptionValue) -> Result<&str, CommandError> {
    option
        .value
        .as_deref()
        .and_then(OsStr::to_str)
        .ok_or_else(|| CommandError::Usage(format!("--{} value must be valid UTF-8", option.name)))
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
    let policy = SigningPolicy::default();
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let (key_option, certificate_is_der) = select_signing_key(invocation, &xml)?;
    let value = key_option.value.as_deref().unwrap_or_default();
    let (key_path, certificate_paths) = split_key_and_certificates(value)?;
    let key = key_material::load_signing_key(key_path)?;
    let signed = if !certificate_paths.is_empty() {
        let writer = if certificate_is_der {
            let certificates = certificate_paths
                .iter()
                .map(key_material::read)
                .collect::<Result<Vec<_>, _>>()?;
            X509CertificateKeyInfoWriter::from_der_chain(&certificates)
        } else {
            let certificates = certificate_paths
                .iter()
                .map(key_material::read_text)
                .collect::<Result<Vec<_>, _>>()?;
            X509CertificateKeyInfoWriter::from_pem_chain(&certificates)
        }
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

fn select_signing_key<'a>(
    invocation: &'a Invocation,
    xml: &str,
) -> Result<(&'a crate::OptionValue, bool), CommandError> {
    let mut keys = Vec::new();
    for (name, certificate_is_der) in [
        ("privkey-pem", false),
        ("privkey-der", true),
        ("pkcs8-pem", false),
        ("pkcs8-der", true),
    ] {
        keys.extend(invocation.values(name).map(|key| (key, certificate_is_der)));
    }
    if keys.is_empty() {
        return Err(CommandError::Usage(
            "sign requires --privkey-pem or --pkcs8-pem/der".into(),
        ));
    }
    if let [selected] = keys.as_slice()
        && (selected.0.parameter.is_none() || invocation.flag("lax-key-search"))
    {
        return Ok(*selected);
    }
    let requested_name = template_key_name(xml)?;
    if let Some(requested_name) = requested_name {
        let matching = keys
            .into_iter()
            .filter(|(key, _)| key.parameter.as_deref() == Some(requested_name.as_str()))
            .collect::<Vec<_>>();
        return match matching.as_slice() {
            [selected] => Ok(*selected),
            [] => Err(CommandError::Usage(format!(
                "signature template requests unknown KeyName {requested_name}"
            ))),
            _ => Err(CommandError::Usage(format!(
                "multiple private keys use KeyName {requested_name}"
            ))),
        };
    }
    Err(CommandError::Usage(
        "multiple private keys require a template KeyName and named options".into(),
    ))
}

fn template_key_name(xml: &str) -> Result<Option<String>, CommandError> {
    let document =
        Document::parse(xml).map_err(|error| CommandError::Signature(error.to_string()))?;
    let signature = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")));
    Ok(signature.and_then(|signature| {
        signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .and_then(|key_info| {
                key_info
                    .children()
                    .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyName")))
            })
            .and_then(|key_name| key_name.text())
            .map(str::to_owned)
    }))
}

fn split_key_and_certificates(value: &OsStr) -> Result<(&OsStr, Vec<&OsStr>), CommandError> {
    let bytes = value.as_encoded_bytes();
    // Splitting at an ASCII byte preserves encoded-byte boundaries on every
    // platform covered by OsStr's encoded-byte contract.
    let mut components = bytes
        .split(|byte| *byte == b',')
        .map(|component| unsafe { OsStr::from_encoded_bytes_unchecked(component) });
    let key = components.next().unwrap_or(OsStr::new(""));
    let certificates = components.collect::<Vec<_>>();
    if key.is_empty() || certificates.iter().any(|path| path.is_empty()) {
        return Err(CommandError::Usage(
            "private key and certificate paths must not be empty".into(),
        ));
    }
    Ok((key, certificates))
}

fn xmlsec_compatibility_verification_policy(invocation: &Invocation) -> VerificationPolicy {
    // Running the xmlsec1-compatible binary is the explicit compatibility
    // boundary: donor verification accepts legacy signatures, while the core
    // library's default policy and every signing path remain secure by default.
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
            // libxmlsec uses this to relax provider security levels for legacy
            // certificate signatures. RustCrypto has no provider strict mode and
            // already verifies every certificate signature algorithm it implements.
            "X509-skip-strict-checks",
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
    reject_unimplemented_selectors(invocation, &["node-id"])?;
    reject_unimplemented_verification_policy(invocation)?;
    let direct_keys = ["pubkey-pem", "pubkey-der"]
        .into_iter()
        .flat_map(|name| invocation.values(name))
        .collect::<Vec<_>>();
    let explicit_certificates = ["pubkey-cert-pem", "pubkey-cert-der"]
        .into_iter()
        .flat_map(|name| invocation.values(name))
        .collect::<Vec<_>>();
    if direct_keys.len() + explicit_certificates.len() > 1 {
        return Err(CommandError::Usage(
            "verify accepts exactly one explicit public key or certificate".into(),
        ));
    }
    let direct_path = direct_keys
        .first()
        .and_then(|option| option.value.as_deref());
    // With an explicit public key there is no key-manager search to relax.
    // Reject the flag on resolver-backed paths until its semantics exist.
    if invocation.flag("lax-key-search")
        && direct_path.is_none()
        && explicit_certificates.is_empty()
    {
        return Err(CommandError::UnsupportedOption("lax-key-search".into()));
    }
    let policy = xmlsec_compatibility_verification_policy(invocation);
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let algorithm = key_material::signature_algorithm(&xml, start_node_id)?;
    let result = if let Some(path) = direct_path {
        let key = key_material::load_verification_key(path, algorithm)?;
        verification_context(policy, start_node_id)
            .key(&key)
            .verify(&xml)
            .map_err(|error| CommandError::Signature(error.to_string()))?
    } else if let [certificate] = explicit_certificates.as_slice() {
        verify_with_explicit_certificate(
            invocation,
            certificate,
            algorithm,
            policy,
            start_node_id,
            &xml,
        )?
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
        verification_context(policy, start_node_id)
            .key_resolver(&resolver)
            .verify(&xml)
            .map_err(|error| CommandError::Signature(error.to_string()))?
    };
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

fn verification_context(
    policy: VerificationPolicy,
    start_node_id: Option<&str>,
) -> VerifyContext<'_> {
    let context = VerifyContext::new().policy(policy);
    match start_node_id {
        Some(id) => context.start_node_id(id),
        None => context,
    }
}

fn verify_with_explicit_certificate(
    invocation: &Invocation,
    certificate: &crate::OptionValue,
    algorithm: SignatureAlgorithm,
    policy: VerificationPolicy,
    start_node_id: Option<&str>,
    xml: &str,
) -> Result<xml_sec::xmldsig::VerifyResult, CommandError> {
    let certificate_der =
        key_material::load_certificate(certificate.value.as_deref().unwrap_or_default())?;
    // Model the caller-pinned leaf as the sole document key source. The core
    // resolver can then build its path through caller-supplied intermediates
    // and anchors without allowing the document's embedded KeyInfo to replace
    // the explicitly selected identity.
    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, certificate_der);
    let key_info_xml = format!(
        "<KeyInfo xmlns=\"{XMLDSIG_NS}\"><X509Data><X509Certificate>{encoded}</X509Certificate></X509Data></KeyInfo>"
    );
    let document = Document::parse(&key_info_xml)
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    let key_info = parse_key_info(document.root_element())
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    let mut config = KeyResolverConfig::default();
    for name in ["untrusted-pem", "untrusted-der"] {
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
    let key = resolver
        .resolve_with_policy(Some(&key_info), algorithm, &policy)
        .map_err(|error| CommandError::Signature(error.to_string()))?
        .ok_or_else(|| CommandError::Signature("explicit certificate was not resolved".into()))?;
    verification_context(policy, start_node_id)
        .key(key.as_ref())
        .verify(xml)
        .map_err(|error| CommandError::Signature(error.to_string()))
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
    let policy = EncryptionPolicy::default();
    let maximum_document_bytes = policy.resources.max_xml_document_bytes;
    let maximum_plaintext_bytes = policy.resources.max_encryption_plaintext_bytes;
    let template = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let (algorithm, encrypted_type) = encryption_template(&template)?;
    let mut builder = EncryptedDataBuilder::new(algorithm).policy(policy);
    let aes_keys = invocation.values("aes-key").collect::<Vec<_>>();
    let public_keys = ["pubkey-pem", "pubkey-der"]
        .into_iter()
        .flat_map(|name| invocation.values(name))
        .collect::<Vec<_>>();
    if aes_keys.len() + public_keys.len() > 1 {
        return Err(CommandError::Usage(
            "encrypt accepts exactly one AES key or RSA public key".into(),
        ));
    }
    if let [option] = aes_keys.as_slice() {
        let key = key_material::load_symmetric(
            option.value.as_deref().unwrap_or_default(),
            Some(algorithm.key_len()),
        )?;
        builder = builder.direct_key(key);
        if let Some(name) = option.parameter.as_deref() {
            builder = builder.direct_key_name(name);
        }
    } else if let [option] = public_keys.as_slice() {
        let path = option.value.as_deref().unwrap_or_default();
        let mut recipient = EncryptionRecipient::rsa_oaep(key_material::load_rsa_public(path)?);
        if let Some(parameters) = template_oaep_parameters(&template)? {
            recipient = recipient.oaep_parameters(parameters);
        }
        builder = builder.add_recipient(recipient);
    } else {
        return Err(CommandError::Usage(
            "encrypt requires --aes-key or --pubkey-pem".into(),
        ));
    }
    builder = builder.encryption_type(encrypted_type);
    let result = if let Some(path) = invocation.last_value("binary-data") {
        let data = read_plaintext(path, maximum_plaintext_bytes)?;
        builder.encrypt_binary(&data)
    } else if let Some(path) = invocation.last_value("xml-data") {
        let data = String::from_utf8(read_plaintext(path, maximum_plaintext_bytes)?)
            .map_err(|_| CommandError::InvalidUtf8Input)?;
        builder.encrypt_xml(&data)
    } else {
        return Err(CommandError::Usage(
            "encrypt requires --binary-data or --xml-data".into(),
        ));
    }
    .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let rendered = apply_encryption_template(&template, &result.encrypted_data_xml)?;
    if rendered.len() > maximum_document_bytes {
        return Err(CommandError::Encryption(
            "encrypted template output exceeds XML document policy".into(),
        ));
    }
    write_output(invocation, rendered.as_bytes(), stdout)
}

fn template_oaep_parameters(xml: &str) -> Result<Option<RsaOaepParameters>, CommandError> {
    let document =
        Document::parse(xml).map_err(|error| CommandError::Encryption(error.to_string()))?;
    let Some(method) = document
        .descendants()
        .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .and_then(|key| {
            key.children()
                .find(|node| node.has_tag_name((XMLENC_NS, "EncryptionMethod")))
        })
    else {
        return Ok(None);
    };
    let algorithm = method
        .attribute("Algorithm")
        .ok_or_else(|| CommandError::Encryption("EncryptedKey has no algorithm".into()))?;
    let transport = KeyTransportAlgorithm::from_uri(algorithm)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let digest = method
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestMethod")))
        .and_then(|node| node.attribute("Algorithm"));
    let mgf = method
        .children()
        .find(|node| node.has_tag_name((XMLENC11_NS, "MGF")))
        .and_then(|node| node.attribute("Algorithm"));
    let digest = oaep_digest_from_uri(digest.unwrap_or(OaepDigestAlgorithm::Sha1.uri()))?;
    let mgf_digest = if transport == KeyTransportAlgorithm::RsaOaepMgf1p {
        OaepDigestAlgorithm::Sha1
    } else {
        oaep_mgf_from_uri(mgf.unwrap_or(OaepDigestAlgorithm::Sha1.mgf_uri()))?
    };
    let label = method
        .children()
        .find(|node| node.has_tag_name((XMLENC_NS, "OAEPparams")))
        .and_then(|node| node.text())
        .map_or_else(
            || Ok(Vec::new()),
            |encoded| {
                base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    encoded.split_ascii_whitespace().collect::<String>(),
                )
                .map_err(|error| CommandError::Encryption(format!("invalid OAEPparams: {error}")))
            },
        )?;
    Ok(Some(RsaOaepParameters {
        algorithm: transport,
        digest,
        mgf_digest,
        label,
    }))
}

fn oaep_digest_from_uri(uri: &str) -> Result<OaepDigestAlgorithm, CommandError> {
    [
        OaepDigestAlgorithm::Sha1,
        OaepDigestAlgorithm::Sha256,
        OaepDigestAlgorithm::Sha384,
        OaepDigestAlgorithm::Sha512,
    ]
    .into_iter()
    .find(|digest| digest.uri() == uri)
    .ok_or_else(|| CommandError::Encryption(format!("unsupported OAEP digest: {uri}")))
}

fn oaep_mgf_from_uri(uri: &str) -> Result<OaepDigestAlgorithm, CommandError> {
    [
        OaepDigestAlgorithm::Sha1,
        OaepDigestAlgorithm::Sha256,
        OaepDigestAlgorithm::Sha384,
        OaepDigestAlgorithm::Sha512,
    ]
    .into_iter()
    .find(|digest| digest.mgf_uri() == uri)
    .ok_or_else(|| CommandError::Encryption(format!("unsupported OAEP MGF: {uri}")))
}

fn apply_encryption_template(template: &str, generated: &str) -> Result<String, CommandError> {
    let template_document =
        Document::parse(template).map_err(|error| CommandError::Encryption(error.to_string()))?;
    let generated_document =
        Document::parse(generated).map_err(|error| CommandError::Encryption(error.to_string()))?;
    let template_data = template_document
        .descendants()
        .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
        .ok_or_else(|| CommandError::Encryption("template has no EncryptedData".into()))?;
    let generated_data = generated_document.root_element();
    let template_cipher = encrypted_data_cipher_value(template_data)
        .ok_or_else(|| CommandError::Encryption("template has no CipherValue".into()))?;
    let generated_cipher = encrypted_data_cipher_value(generated_data)
        .ok_or_else(|| CommandError::Encryption("generated data has no CipherValue".into()))?;
    let mut replacements = vec![(
        template_cipher.range(),
        standalone_cipher_value(generated_cipher),
    )];

    let template_key_info = direct_child_element(template_data, XMLDSIG_NS, "KeyInfo");
    let generated_key_info = direct_child_element(generated_data, XMLDSIG_NS, "KeyInfo");
    match (template_key_info, generated_key_info) {
        (Some(template_key_info), Some(generated_key_info)) => {
            let template_values = template_key_info
                .descendants()
                .filter(|node| node.has_tag_name((XMLENC_NS, "CipherValue")))
                .collect::<Vec<_>>();
            let generated_values = generated_key_info
                .descendants()
                .filter(|node| node.has_tag_name((XMLENC_NS, "CipherValue")))
                .collect::<Vec<_>>();
            if template_values.len() != generated_values.len() {
                return Err(CommandError::Encryption(
                    "template KeyInfo does not contain one CipherValue per generated recipient"
                        .into(),
                ));
            }
            replacements.extend(template_values.into_iter().zip(generated_values).map(
                |(template_value, generated_value)| {
                    (
                        template_value.range(),
                        standalone_cipher_value(generated_value),
                    )
                },
            ));
        }
        (None, Some(generated_key_info)) => {
            let cipher_data = direct_child_element(template_data, XMLENC_NS, "CipherData")
                .ok_or_else(|| CommandError::Encryption("template has no CipherData".into()))?;
            let key_info = generated[generated_key_info.range()].replacen(
                "<ds:KeyInfo",
                "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\"",
                1,
            );
            replacements.push((
                cipher_data.range().start..cipher_data.range().start,
                key_info,
            ));
        }
        _ => {}
    }
    replacements.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut output = template.to_owned();
    for (range, replacement) in replacements {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn standalone_cipher_value(node: roxmltree::Node<'_, '_>) -> String {
    format!(
        "<CipherValue xmlns=\"http://www.w3.org/2001/04/xmlenc#\">{}</CipherValue>",
        node.text().unwrap_or_default()
    )
}

fn direct_child_element<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| child.has_tag_name((namespace, name)))
}

fn encrypted_data_cipher_value<'a, 'input>(
    data: roxmltree::Node<'a, 'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    direct_child_element(data, XMLENC_NS, "CipherData")
        .and_then(|cipher| direct_child_element(cipher, XMLENC_NS, "CipherValue"))
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
    let policy = DecryptionPolicy::default();
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let encrypted_data_id = option_text(invocation, "node-id")?;
    let aes_keys = invocation.values("aes-key").collect::<Vec<_>>();
    let private_keys = ["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"]
        .into_iter()
        .flat_map(|name| invocation.values(name))
        .collect::<Vec<_>>();
    if aes_keys.len() + private_keys.len() > 1 {
        return Err(CommandError::Usage(
            "decrypt accepts exactly one AES key or RSA private key".into(),
        ));
    }
    let bytes = if let [option] = aes_keys.as_slice() {
        let key = key_material::load_symmetric(option.value.as_deref().unwrap_or_default(), None)?;
        decrypt_input(
            &SymmetricKeyDecryptor::new(key),
            &xml,
            encrypted_data_id,
            policy,
        )?
    } else if let [option] = private_keys.as_slice() {
        let path = option.value.as_deref().unwrap_or_default();
        let resolver = PrivateKeyDecryptor::new(key_material::load_rsa_private(path)?);
        decrypt_input(&resolver, &xml, encrypted_data_id, policy)?
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
    policy: DecryptionPolicy,
) -> Result<Vec<u8>, CommandError> {
    let document =
        Document::parse(xml).map_err(|error| CommandError::Encryption(error.to_string()))?;
    let standalone = document
        .root_element()
        .has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData"));
    let context = DecryptContext::new(resolver).policy(policy);
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
        .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
        .ok_or_else(|| CommandError::Encryption("template has no EncryptedData".into()))?;
    let method = encrypted_data
        .children()
        .find(|node| node.has_tag_name((XMLENC_NS, "EncryptionMethod")))
        .and_then(|node| node.attribute("Algorithm"))
        .ok_or_else(|| CommandError::Encryption("template has no encryption algorithm".into()))?;
    let algorithm = DataEncryptionAlgorithm::from_uri(method)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let encrypted_type = match encrypted_data.attribute("Type") {
        None | Some("http://www.w3.org/2001/04/xmlenc#Element") => EncryptedDataType::Element,
        Some("http://www.w3.org/2001/04/xmlenc#Content") => EncryptedDataType::Content,
        Some(other) => {
            return Err(CommandError::Encryption(format!(
                "unsupported EncryptedData Type: {other}"
            )));
        }
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
        let algorithm = option_value_text(generated)?;
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
        let key_name = generated
            .parameter
            .as_deref()
            .map_or_else(String::new, |name| {
                format!("<KeyName>{}</KeyName>\n", quick_xml::escape::escape(name))
            });
        entries.push_str(&format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n\
             {key_name}\
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
        write_secret_file(path, document.as_bytes())
    } else {
        stdout.write_all(document.as_bytes()).map_err(stdout_error)
    }
}

fn write_secret_file(path: &OsStr, bytes: &[u8]) -> Result<(), CommandError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| CommandError::Io {
        path: PathBuf::from(path),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| CommandError::Io {
                path: PathBuf::from(path),
                source,
            })?;
    }
    file.write_all(bytes).map_err(|source| CommandError::Io {
        path: PathBuf::from(path),
        source,
    })
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
        path: PathBuf::from("stdout"),
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
    fn capability_checks_reject_unknown_names() {
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

    #[test]
    fn input_reader_enforces_the_compiled_policy_limit_before_parsing() {
        // The reader must stop at maximum + 1 rather than allocating an entire
        // attacker-controlled XML file before the operation policy sees it.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized.xml");
        fs::write(&path, b"<root/>").unwrap();
        let invocation = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("verify"),
            path.into_os_string(),
        ])
        .unwrap();
        assert!(matches!(
            read_input(&invocation, 4),
            Err(CommandError::InputTooLarge { maximum: 4 })
        ));
    }

    #[test]
    fn plaintext_reader_enforces_the_compiled_policy_limit_before_encryption() {
        // Payload limits must be enforced by the reader, before the encryption
        // builder receives an attacker-controlled allocation.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized.bin");
        fs::write(&path, b"12345").unwrap();
        assert!(matches!(
            read_plaintext(path.as_os_str(), 4),
            Err(CommandError::PlaintextTooLarge { maximum: 4 })
        ));
    }
}
