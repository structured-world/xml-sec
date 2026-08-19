use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use roxmltree::{Document, Node, ParsingOptions};
use rsa::{
    RsaPublicKey,
    pkcs8::{DecodePublicKey as _, EncodePublicKey as _},
    traits::PublicKeyParts as _,
};
use x509_parser::prelude::FromDer as _;
use xml_sec::{
    IdAttributeRegistration,
    policy::{DecryptionPolicy, EncryptionPolicy, SigningPolicy, VerificationPolicy},
    provider::{CryptoProvider, default_provider},
    xmldsig::{
        DefaultKeyResolver, DsigError, DsigStatus, FailureReason, KeyInfo, KeyInfoSource,
        KeyInfoWriter, KeyResolver, KeyResolverConfig, KeyValueInfo, ReferenceResult, SignContext,
        SignatureAlgorithm, SignatureTemplateSelection, SigningKey, UriTypeSet, VerificationKey,
        VerifyContext, VerifyResult, VerifyingKey, X509CertificateKeyInfoWriter,
        XPathHereSemantics, parse_key_info, uri::UriReferenceResolver, validate_signing_key,
        x509_certificate_matches_selectors,
    },
    xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DecryptionKeyResolver,
        EncryptedDataBuilder, EncryptedDataType, EncryptedKey, EncryptionMethod,
        EncryptionRecipient, KeyTransportAlgorithm, OaepDigestAlgorithm, PrivateKeyDecryptor,
        RsaOaepParameters, XmlEncError, parse_encrypted_data_template_node_with_policy,
        validate_rsa_recipient_key,
    },
};

use crate::{
    Command, Invocation,
    args::{Arity, HelpTarget, OPTION_SPECS},
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
const SIGN_OPTIONS: &[&str] = &[
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
];
const VERIFY_OPTIONS: &[&str] = &[
    "pubkey-pem",
    "pubkey-der",
    "pubkey-cert-pem",
    "pubkey-cert-der",
    "trusted-pem",
    "trusted-der",
    "untrusted-pem",
    "untrusted-der",
    "enabled-reference-uris",
    "enabled-retrieval-method-uris",
    "ignore-manifests",
    "lax-key-search",
    "verify-crls",
    "X509-skip-time-checks",
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
];
const ENCRYPT_OPTIONS: &[&str] = &[
    "output",
    "binary-data",
    "xml-data",
    "aes-key",
    "pubkey-pem",
    "pubkey-der",
    "pubkey-cert-pem",
    "pubkey-cert-der",
    "lax-key-search",
    "node-id",
    "node-name",
    "node-xpath",
    "id-attr",
    "add-id-attr",
];
const DECRYPT_OPTIONS: &[&str] = &[
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
];
const KEYS_OPTIONS: &[&str] = &["gen-key"];
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const XMLSEC_COMPATIBILITY_HERE_SEMANTICS: XPathHereSemantics = XPathHereSemantics::XmlSecLegacy;
const PRIMARY_COMMANDS: &[Command] = &[
    Command::Sign,
    Command::Verify,
    Command::Encrypt,
    Command::Decrypt,
    Command::Keys,
    Command::ListTransforms,
    Command::CheckTransforms,
    Command::ListKeyData,
    Command::CheckKeyData,
];

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
    #[error("configured certificate material exceeds policy limit of {maximum} bytes")]
    CertificateMaterialTooLarge { maximum: usize },
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
    #[error("invalid internal command contract: {0}")]
    InvalidContract(&'static str),
}

pub fn execute(
    invocation: Invocation,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), CommandError> {
    if invocation.flag("help") {
        return command_help(invocation.command, stdout);
    }
    validate_provider(&invocation)?;
    validate_crypto_config(&invocation)?;
    match invocation.command {
        Command::Help => match invocation.help_target {
            Some(HelpTarget::Command(command)) => command_help(command, stdout),
            Some(HelpTarget::Unknown) => {
                writeln!(stderr, "Unknown command").map_err(stdout_error)?;
                help(stdout)
            }
            None => help(stdout),
        },
        Command::HelpAll => help_all(stdout),
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
        Command::Sign => sign(&invocation, stdout),
        Command::Verify => verify(&invocation, stdout),
        Command::Encrypt => encrypt(&invocation, stdout),
        Command::Decrypt => decrypt(&invocation, stdout),
    }
}

fn help(output: &mut dyn Write) -> Result<(), CommandError> {
    writeln!(output, "Usage: xmlsec1 <command> [options] [files]").map_err(stdout_error)?;
    write_command_list(PRIMARY_COMMANDS, output)
}

fn help_all(output: &mut dyn Write) -> Result<(), CommandError> {
    writeln!(output, "Usage: xmlsec1 <command> [options] [files]").map_err(stdout_error)?;
    write_command_list(Command::ALL, output)?;
    writeln!(output, "Options:").map_err(stdout_error)?;
    for spec in OPTION_SPECS {
        let parameter = if spec.accepts_parameter {
            "[:name]"
        } else {
            ""
        };
        let value = if matches!(spec.arity, Arity::Value) {
            " <value>"
        } else {
            ""
        };
        writeln!(output, "  --{}{parameter}{value}", spec.canonical).map_err(stdout_error)?;
    }
    Ok(())
}

fn write_command_list(commands: &[Command], output: &mut dyn Write) -> Result<(), CommandError> {
    write!(output, "Commands:").map_err(stdout_error)?;
    for command in commands {
        write!(output, " {}", command.canonical_name()).map_err(stdout_error)?;
    }
    writeln!(output).map_err(stdout_error)
}

fn command_help(command: Command, output: &mut dyn Write) -> Result<(), CommandError> {
    if command == Command::Help {
        return help(output);
    }
    if command == Command::HelpAll {
        return help_all(output);
    }
    if command == Command::Version {
        return writeln!(output, "Usage: xmlsec1 version").map_err(stdout_error);
    }
    let Some((name, options)) = command_contract(command) else {
        return help(output);
    };
    writeln!(output, "Usage: xmlsec1 {name} [options] [files]").map_err(stdout_error)?;
    writeln!(output, "Options:").map_err(stdout_error)?;
    for option in GENERIC_OPTIONS.iter().chain(options) {
        let spec = OPTION_SPECS
            .iter()
            .find(|spec| spec.canonical == *option)
            .ok_or(CommandError::InvalidContract(
                "command option is absent from OPTION_SPECS",
            ))?;
        let parameter = if spec.accepts_parameter {
            "[:name]"
        } else {
            ""
        };
        let value = if matches!(spec.arity, Arity::Value) {
            " <value>"
        } else {
            ""
        };
        writeln!(output, "  --{}{parameter}{value}", spec.canonical).map_err(stdout_error)?;
    }
    Ok(())
}

fn command_contract(command: Command) -> Option<(&'static str, &'static [&'static str])> {
    let options = match command {
        Command::Sign => SIGN_OPTIONS,
        Command::Verify => VERIFY_OPTIONS,
        Command::Encrypt => ENCRYPT_OPTIONS,
        Command::Decrypt => DECRYPT_OPTIONS,
        Command::Keys => KEYS_OPTIONS,
        Command::ListKeyData
        | Command::CheckKeyData
        | Command::ListTransforms
        | Command::CheckTransforms => &[],
        _ => return None,
    };
    Some((command.canonical_name(), options))
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

fn write_result_then_stdout_diagnostics(
    invocation: &Invocation,
    bytes: &[u8],
    stdout: &mut dyn Write,
    diagnostics: impl FnOnce(&mut dyn Write) -> Result<(), CommandError>,
) -> Result<(), CommandError> {
    // libxmlsec1's sign/encrypt/decrypt commands write the result first and
    // debug dumps second on stdout. Keep that compatibility boundary here;
    // callers that need an unmixed stream select --output for the result.
    write_output(invocation, bytes, stdout)?;
    diagnostics(stdout)
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
    read_bounded_file(path, maximum, |maximum| CommandError::PlaintextTooLarge {
        maximum,
    })
}

fn read_xml_data(path: &OsStr, maximum: usize) -> Result<String, CommandError> {
    String::from_utf8(read_bounded_file(path, maximum, |maximum| {
        CommandError::InputTooLarge { maximum }
    })?)
    .map_err(|_| CommandError::InvalidUtf8Input)
}

fn read_bounded_file(
    path: &OsStr,
    maximum: usize,
    too_large: impl FnOnce(usize) -> CommandError,
) -> Result<Vec<u8>, CommandError> {
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
        return Err(too_large(maximum));
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

fn id_attribute_registrations(
    invocation: &Invocation,
) -> Result<Vec<IdAttributeRegistration>, CommandError> {
    let mut registrations = invocation
        .values("add-id-attr")
        .map(|option| option_value_text(option).map(IdAttributeRegistration::global))
        .collect::<Result<Vec<_>, _>>()?;
    for option in invocation.values("id-attr") {
        let element = option_value_text(option)?;
        let expanded_name = element.rsplit_once(':');
        let local_name = expanded_name.map_or(element, |(_, local_name)| local_name);
        if local_name.is_empty() {
            return Err(CommandError::Usage(
                "--id-attr element local name cannot be empty".into(),
            ));
        }
        let attribute_name = option.parameter.as_deref().unwrap_or("id");
        registrations.push(match expanded_name {
            None => IdAttributeRegistration::scoped_any_namespace(attribute_name, local_name),
            Some((namespace, _)) => IdAttributeRegistration::scoped(
                attribute_name,
                local_name,
                (!namespace.is_empty()).then_some(namespace),
            ),
        });
    }
    Ok(registrations)
}

fn select_named_candidates<'a, T: Copy>(
    candidates: &[(&'a crate::OptionValue, T)],
    requested_names: &[String],
    allow_unconstrained_named_singleton: bool,
    key_kind: &str,
) -> Result<Vec<(&'a crate::OptionValue, T)>, CommandError> {
    if let [selected] = candidates
        && (selected.0.parameter.is_none()
            || (requested_names.is_empty() && allow_unconstrained_named_singleton))
    {
        return Ok(vec![*selected]);
    }
    if !requested_names.is_empty() {
        let mut selected = Vec::new();
        let mut selected_indices = HashSet::new();
        for requested in requested_names {
            let matching = candidates
                .iter()
                .enumerate()
                .filter(|(_, (key, _))| key.parameter.as_deref() == Some(requested.as_str()))
                .collect::<Vec<_>>();
            match matching.as_slice() {
                [(index, candidate)] if selected_indices.insert(*index) => {
                    selected.push(**candidate);
                }
                [(_index, _candidate)] => {}
                [] => {}
                _ => {
                    return Err(CommandError::Usage(format!(
                        "multiple {key_kind} inputs match template KeyNames"
                    )));
                }
            }
        }
        return if selected.is_empty() {
            Err(CommandError::Usage(format!(
                "template requests unknown KeyName for supplied {key_kind}"
            )))
        } else {
            Ok(selected)
        };
    }
    let unnamed = candidates
        .iter()
        .copied()
        .filter(|(key, _)| key.parameter.is_none())
        .collect::<Vec<_>>();
    match unnamed.as_slice() {
        [selected] => return Ok(vec![*selected]),
        [] => {}
        _ => {
            return Err(CommandError::Usage(format!(
                "multiple unnamed {key_kind} inputs match the template recipient"
            )));
        }
    }
    let message = if candidates.len() == 1 {
        format!("a named {key_kind} requires a template KeyName; use --lax-key-search to opt out")
    } else {
        format!("multiple {key_kind} inputs require a template KeyName and named options")
    };
    Err(CommandError::Usage(message))
}

fn named_candidate_search<'a, T: Copy>(
    candidates: &[(&'a crate::OptionValue, T)],
    requested_names: &[String],
    lax_key_search: bool,
    allow_unconstrained_named_singleton: bool,
    key_kind: &str,
) -> Result<Vec<(&'a crate::OptionValue, T)>, CommandError> {
    if lax_key_search {
        if candidates.is_empty() {
            return Err(CommandError::Usage(format!(
                "no compatible {key_kind} input was supplied"
            )));
        }
        return Ok(candidates.to_vec());
    }
    select_named_candidates(
        candidates,
        requested_names,
        allow_unconstrained_named_singleton,
        key_kind,
    )
}

fn sign(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, SIGN_OPTIONS)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    if invocation.last_value("pwd").is_some() {
        return Err(CommandError::UnsupportedOption("pwd".into()));
    }
    // This binary is an explicit libxmlsec1 compatibility boundary. Its sign
    // and verify commands must bind XPath here() identically for round trips.
    let policy = SigningPolicy {
        xpath_here_semantics: XMLSEC_COMPATIBILITY_HERE_SEMANTICS,
        ..SigningPolicy::default()
    };
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let signature =
        key_material::signing_signature_metadata(&xml, start_node_id, &id_attributes, &policy)?;
    let selected = select_signing_key(
        invocation,
        &signature.key_names,
        signature.algorithm,
        &policy,
    )?;
    let mut context = SignContext::new(selected.key.as_ref())
        .policy(policy)
        .signature_template_selection(SignatureTemplateSelection::FirstDescendant);
    if let Some(id) = start_node_id {
        context = context.start_node_id(id);
    }
    context = context.id_attributes(&id_attributes);
    if let Some(writer) = &selected.certificate_writer
        && signature.has_key_info
    {
        context = context.key_info_writer(writer);
    }
    let signed = context
        .sign_template(&xml)
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    write_result_then_stdout_diagnostics(invocation, signed.as_bytes(), stdout, |stdout| {
        write_signing_diagnostics(invocation, signature.algorithm, stdout)
    })
}

fn write_signing_diagnostics(
    invocation: &Invocation,
    algorithm: SignatureAlgorithm,
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    if invocation.flag("print-debug") {
        writeln!(stdout, "== Signature Context").map_err(stdout_error)?;
        writeln!(stdout, "Status: succeeded").map_err(stdout_error)?;
        writeln!(stdout, "Signature Method: {}", algorithm.uri()).map_err(stdout_error)?;
    }
    if invocation.flag("print-xml-debug") {
        writeln!(
            stdout,
            "<SignatureContext status=\"SUCCEEDED\" failureReason=\"UNKNOWN\">"
        )
        .map_err(stdout_error)?;
        write_debug_transform(stdout, "SignatureMethod", algorithm.uri())?;
        writeln!(stdout, "</SignatureContext>").map_err(stdout_error)?;
    }
    Ok(())
}

struct SigningKeyCandidate {
    key: Box<dyn SigningKey>,
    certificate_writer: Option<X509CertificateKeyInfoWriter>,
}

fn select_signing_key(
    invocation: &Invocation,
    requested_names: &[String],
    algorithm: SignatureAlgorithm,
    policy: &SigningPolicy,
) -> Result<SigningKeyCandidate, CommandError> {
    let keys = invocation
        .ordered_values(&["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"])
        .map(|key| (key, ()))
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return Err(CommandError::Usage(
            "sign requires --privkey-pem or --pkcs8-pem/der".into(),
        ));
    }
    let candidates = named_candidate_search(
        &keys,
        requested_names,
        invocation.flag("lax-key-search"),
        false,
        "private key",
    )?;
    let lax_key_search = invocation.flag("lax-key-search");
    let mut last_error: Option<CommandError> = None;
    let mut certificate_budget =
        CertificateBudget::new(policy.resources.max_external_resource_total_bytes);
    for (option, ()) in candidates {
        let attempt =
            prepare_signing_key_candidate(option, algorithm, policy, &mut certificate_budget);
        match attempt {
            Ok(candidate) => return Ok(candidate),
            Err(error) if lax_key_search => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(CommandError::Usage(format!(
        "no private key input supports {}",
        algorithm.uri()
    )))
}

fn prepare_signing_key_candidate(
    option: &crate::OptionValue,
    algorithm: SignatureAlgorithm,
    policy: &SigningPolicy,
    certificate_budget: &mut CertificateBudget,
) -> Result<SigningKeyCandidate, CommandError> {
    let (path, certificate_paths) =
        split_key_and_certificates(option.value.as_deref().unwrap_or_default())?;
    let key = key_material::load_signing_key(path, private_key_format(option))?;
    validate_signing_key(key.as_ref(), algorithm, policy)
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    let certificate_writer = if certificate_paths.is_empty() {
        None
    } else {
        let certificates = load_certificate_companions(
            &certificate_paths,
            if matches!(option.name.as_str(), "privkey-der" | "pkcs8-der") {
                key_material::CertificateEncoding::Der
            } else {
                key_material::CertificateEncoding::Pem
            },
            certificate_budget,
        )?;
        let writer = X509CertificateKeyInfoWriter::from_der_chain(&certificates)
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        // Companion validation belongs to candidate preparation even when the
        // template has no KeyInfo output slot: the option is one key identity.
        writer
            .write_key_info(key.as_ref())
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        Some(writer)
    };
    Ok(SigningKeyCandidate {
        key,
        certificate_writer,
    })
}

fn load_certificate_companions(
    paths: &[&OsStr],
    encoding: key_material::CertificateEncoding,
    budget: &mut CertificateBudget,
) -> Result<Vec<Vec<u8>>, CommandError> {
    paths
        .iter()
        .map(|path| {
            let certificate = key_material::load_certificate(path, encoding)?;
            budget.charge(certificate.len())?;
            Ok(certificate)
        })
        .collect()
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

fn private_key_format(option: &crate::OptionValue) -> key_material::PrivateKeyFormat {
    match option.name.as_str() {
        "privkey-pem" => key_material::PrivateKeyFormat::Pem,
        "privkey-der" => key_material::PrivateKeyFormat::Der,
        "pkcs8-pem" => key_material::PrivateKeyFormat::Pkcs8Pem,
        "pkcs8-der" => key_material::PrivateKeyFormat::Pkcs8Der,
        _ => unreachable!("private key loader called for a non-private-key option"),
    }
}

fn public_key_encoding(option: &crate::OptionValue) -> key_material::PublicKeyEncoding {
    match option.name.as_str() {
        "pubkey-pem" => key_material::PublicKeyEncoding::Pem,
        "pubkey-der" => key_material::PublicKeyEncoding::Der,
        _ => unreachable!("public key loader called for a non-public-key option"),
    }
}

fn certificate_encoding(option: &crate::OptionValue) -> key_material::CertificateEncoding {
    match option.name.as_str() {
        "pubkey-cert-pem" | "trusted-pem" | "untrusted-pem" => {
            key_material::CertificateEncoding::Pem
        }
        "pubkey-cert-der" | "trusted-der" | "untrusted-der" => {
            key_material::CertificateEncoding::Der
        }
        _ => unreachable!("certificate loader called for a non-certificate option"),
    }
}

fn xmlsec_compatibility_verification_policy(invocation: &Invocation) -> VerificationPolicy {
    // Running the xmlsec1-compatible binary is the explicit compatibility
    // boundary: both CLI signing and verification use the donor interpretation,
    // while the core library retains the XMLDSig binding by default.
    let mut policy = VerificationPolicy {
        process_manifests: !invocation.flag("ignore-manifests"),
        reference_uri_types: UriTypeSet::ALL,
        retrieval_uri_types: UriTypeSet::ALL,
        xpath_here_semantics: XMLSEC_COMPATIBILITY_HERE_SEMANTICS,
        ..VerificationPolicy::default()
    };
    policy.key_trust.allowed_legacy_signature_algorithms = HashSet::from([
        SignatureAlgorithm::RsaSha1,
        SignatureAlgorithm::DsaSha1,
        SignatureAlgorithm::HmacSha1,
    ]);
    // X509Data is controlled by the signed document and therefore cannot
    // establish its own trust. Only an explicit insecure opt-out disables
    // path validation for resolver-selected certificates. libxmlsec1 makes
    // that opt-out authoritative over --verify-crls as well: CRLs are part of
    // path validation and cannot remain enabled after trust checks are bypassed.
    let insecure = invocation.flag("insecure");
    policy.key_trust.verify_x509_chains = !insecure;
    policy.key_trust.check_crls = invocation.flag("verify-crls") && !insecure;
    policy
}

fn verify(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, VERIFY_OPTIONS)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    reject_unimplemented_verification_policy(invocation)?;
    let explicit_keys = invocation
        .ordered_values(&[
            "pubkey-pem",
            "pubkey-der",
            "pubkey-cert-pem",
            "pubkey-cert-der",
        ])
        .map(|option| {
            let certificate = matches!(option.name.as_str(), "pubkey-cert-pem" | "pubkey-cert-der");
            (option, certificate)
        })
        .collect::<Vec<_>>();
    // With an explicit public key there is no key-manager search to relax.
    // Reject the flag on resolver-backed paths until its semantics exist.
    if invocation.flag("lax-key-search") && explicit_keys.is_empty() {
        return Err(CommandError::UnsupportedOption("lax-key-search".into()));
    }
    let policy = xmlsec_compatibility_verification_policy(invocation);
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let signature = key_material::verification_signature_metadata(
        &xml,
        start_node_id,
        &id_attributes,
        &policy,
    )?;
    let algorithm = signature.algorithm;
    let selected_keys = if explicit_keys.is_empty() {
        Vec::new()
    } else {
        named_candidate_search(
            &explicit_keys,
            &signature.key_names,
            invocation.flag("lax-key-search"),
            true,
            "verification key",
        )?
    };
    let mut certificate_budget =
        CertificateBudget::new(policy.resources.max_external_resource_total_bytes);
    let configured_certificates = load_configured_certificates(
        invocation,
        selected_keys.is_empty(),
        &mut certificate_budget,
    )?;
    let result = if !selected_keys.is_empty() {
        let mut candidates = Vec::with_capacity(selected_keys.len());
        let mut last_load_error = None;
        for (option, certificate) in selected_keys {
            let candidate = if certificate {
                load_explicit_certificate_key_info(option, &mut certificate_budget)
                    .map(ExplicitVerificationCandidate::Certificate)
            } else {
                key_material::load_verification_key(
                    option.value.as_deref().unwrap_or_default(),
                    public_key_encoding(option),
                    algorithm,
                )
                .map_err(CommandError::from)
                .map(ExplicitVerificationCandidate::Direct)
            };
            match candidate {
                Ok(candidate) => candidates.push(candidate),
                Err(error) => last_load_error = Some(error),
            }
        }
        if candidates.is_empty() {
            return Err(last_load_error.unwrap_or(CommandError::InvalidSignature));
        }
        let resolver = CandidateVerificationResolver::new(candidates, configured_certificates);
        verification_context(policy, start_node_id, &id_attributes)
            .key_resolver(&resolver)
            .verify(&xml)
            .map_err(|error| CommandError::Signature(error.to_string()))?
    } else {
        let config = configured_certificates.into_resolver_config();
        let resolver = DefaultKeyResolver::new(config);
        verification_context(policy, start_node_id, &id_attributes)
            .key_resolver(&resolver)
            .verify(&xml)
            .map_err(|error| CommandError::Signature(error.to_string()))?
    };
    write_verification_diagnostics(invocation, &result, stdout)?;
    if aggregate_verification_status(&result) != DsigStatus::Valid {
        return Err(CommandError::InvalidSignature);
    }
    Ok(())
}

struct CertificateBudget {
    total_bytes: usize,
    maximum_bytes: usize,
}

#[derive(Clone, Default)]
struct ConfiguredCertificates {
    lookup: Vec<Vec<u8>>,
    trusted: Vec<Vec<u8>>,
}

impl ConfiguredCertificates {
    fn into_resolver_config(self) -> KeyResolverConfig {
        KeyResolverConfig {
            lookup_certs: self.lookup,
            trusted_certs: self.trusted,
            ..KeyResolverConfig::default()
        }
    }
}

fn load_configured_certificates(
    invocation: &Invocation,
    include_explicit_keys: bool,
    budget: &mut CertificateBudget,
) -> Result<ConfiguredCertificates, CommandError> {
    let mut certificates = ConfiguredCertificates::default();
    let lookup_names: &[&str] = if include_explicit_keys {
        &[
            "pubkey-cert-pem",
            "pubkey-cert-der",
            "untrusted-pem",
            "untrusted-der",
        ]
    } else {
        &["untrusted-pem", "untrusted-der"]
    };
    for name in lookup_names {
        for option in invocation.values(name) {
            let (certificate, source_len) = key_material::load_certificate_with_source_len(
                option.value.as_deref().unwrap_or_default(),
                certificate_encoding(option),
            )?;
            push_configured_certificate(&mut certificates.lookup, certificate, source_len, budget)?;
        }
    }
    for name in ["trusted-pem", "trusted-der"] {
        for option in invocation.values(name) {
            let (certificate, source_len) = key_material::load_certificate_with_source_len(
                option.value.as_deref().unwrap_or_default(),
                certificate_encoding(option),
            )?;
            push_configured_certificate(
                &mut certificates.trusted,
                certificate,
                source_len,
                budget,
            )?;
        }
    }
    Ok(certificates)
}

impl CertificateBudget {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            total_bytes: 0,
            maximum_bytes,
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), CommandError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum_bytes)
            .ok_or(CommandError::CertificateMaterialTooLarge {
                maximum: self.maximum_bytes,
            })?;
        Ok(())
    }
}

fn push_configured_certificate(
    certificates: &mut Vec<Vec<u8>>,
    certificate: Vec<u8>,
    source_bytes: usize,
    budget: &mut CertificateBudget,
) -> Result<(), CommandError> {
    budget.charge(source_bytes)?;
    if certificates.iter().any(|existing| existing == &certificate) {
        return Ok(());
    }
    certificates.push(certificate);
    Ok(())
}

fn write_verification_diagnostics(
    invocation: &Invocation,
    result: &VerifyResult,
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    let aggregate_status = aggregate_verification_status(result);
    if invocation.flag("print-debug") {
        let status = if aggregate_status == DsigStatus::Valid {
            "valid"
        } else {
            "invalid"
        };
        writeln!(stdout, "Status: {status}").map_err(stdout_error)?;
    }
    if invocation.flag("print-xml-debug") {
        let (status, failure_reason) = donor_dsig_status(aggregate_status);
        writeln!(
            stdout,
            "<VerificationContext status=\"{status}\" failureReason=\"{failure_reason}\">"
        )
        .map_err(stdout_error)?;
        write_reference_diagnostics(
            stdout,
            "SignedInfoReferences",
            &result.signed_info_references,
        )?;
        write_reference_diagnostics(stdout, "ManifestReferences", &result.manifest_references)?;
        writeln!(stdout, "</VerificationContext>").map_err(stdout_error)?;
    }
    Ok(())
}

fn aggregate_verification_status(result: &VerifyResult) -> DsigStatus {
    aggregate_statuses(
        result.status,
        result
            .manifest_references
            .iter()
            .map(|reference| reference.status),
    )
}

fn aggregate_statuses(
    core_status: DsigStatus,
    manifest_statuses: impl IntoIterator<Item = DsigStatus>,
) -> DsigStatus {
    if core_status != DsigStatus::Valid {
        return core_status;
    }
    manifest_statuses
        .into_iter()
        .find(|status| *status != DsigStatus::Valid)
        .unwrap_or(DsigStatus::Valid)
}

fn write_reference_diagnostics(
    stdout: &mut dyn Write,
    container: &str,
    references: &[ReferenceResult],
) -> Result<(), CommandError> {
    writeln!(stdout, "<{container}>").map_err(stdout_error)?;
    for reference in references {
        let (status, _) = donor_dsig_status(reference.status);
        writeln!(stdout, "<ReferenceVerificationContext status=\"{status}\">")
            .map_err(stdout_error)?;
        writeln!(
            stdout,
            "<URI>{}</URI>",
            quick_xml::escape::escape(&reference.uri)
        )
        .map_err(stdout_error)?;
        writeln!(stdout, "</ReferenceVerificationContext>").map_err(stdout_error)?;
    }
    writeln!(stdout, "</{container}>").map_err(stdout_error)
}

fn donor_dsig_status(status: DsigStatus) -> (&'static str, &'static str) {
    match status {
        DsigStatus::Valid => ("OK", "UNKNOWN"),
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { .. })
        | DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { .. })
        | DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { .. }) => {
            ("FAILED", "REFERENCE")
        }
        DsigStatus::Invalid(FailureReason::SignatureMismatch) => ("FAILED", "SIGNATURE"),
        DsigStatus::Invalid(FailureReason::KeyNotFound) => ("FAILED", "KEY-NOT-FOUND"),
        _ => ("ERROR", "UNKNOWN"),
    }
}

fn verification_context<'a>(
    policy: VerificationPolicy,
    start_node_id: Option<&'a str>,
    id_attributes: &'a [IdAttributeRegistration],
) -> VerifyContext<'a> {
    let context = VerifyContext::new()
        .policy(policy)
        .id_attributes(id_attributes);
    match start_node_id {
        Some(id) => context.start_node_id(id),
        None => context.first_document_signature(),
    }
}

enum ExplicitVerificationCandidate {
    Direct(VerificationKey),
    Certificate(KeyInfo),
}

struct CandidateVerificationResolver {
    candidates: Vec<ExplicitVerificationCandidate>,
    certificate_resolver: DefaultKeyResolver,
    has_trusted_certificates: bool,
}

impl CandidateVerificationResolver {
    fn new(
        candidates: Vec<ExplicitVerificationCandidate>,
        configured: ConfiguredCertificates,
    ) -> Self {
        let has_trusted_certificates = !configured.trusted.is_empty();
        Self {
            candidates,
            certificate_resolver: DefaultKeyResolver::new(configured.into_resolver_config()),
            has_trusted_certificates,
        }
    }
}

impl KeyResolver for CandidateVerificationResolver {
    fn resolve<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        self.resolve_with_policy_and_provider(
            key_info,
            algorithm,
            &VerificationPolicy::default(),
            default_provider(),
        )
    }

    fn resolve_with_policy_and_provider<'a>(
        &'a self,
        _key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &VerificationPolicy,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        let mut certificate_policy = policy.clone();
        if !self.has_trusted_certificates {
            // A caller-pinned certificate without a separate trust anchor is
            // a direct key source. Chain-dependent CRL checks therefore do
            // not apply to this candidate path.
            certificate_policy.key_trust.verify_x509_chains = false;
            certificate_policy.key_trust.check_crls = false;
        }
        let mut resolved = Vec::with_capacity(self.candidates.len());
        let mut last_error = None;
        for candidate in &self.candidates {
            let key = match candidate {
                ExplicitVerificationCandidate::Direct(key) => {
                    Some(Box::new(key.clone()) as Box<dyn VerifyingKey>)
                }
                ExplicitVerificationCandidate::Certificate(info) => {
                    match self.certificate_resolver.resolve_with_policy_and_provider(
                        Some(info),
                        algorithm,
                        &certificate_policy,
                        provider,
                    ) {
                        Ok(key) => key,
                        Err(error) => {
                            last_error = Some(error);
                            continue;
                        }
                    }
                }
            };
            if let Some(key) = key {
                match key.validate_policy(policy) {
                    Ok(()) => resolved.push(key),
                    Err(error) => last_error = Some(error),
                }
            }
        }
        if resolved.is_empty() {
            return match last_error {
                Some(error) => Err(error),
                None => Ok(None),
            };
        }
        Ok(Some(Box::new(CandidateVerifyingKey {
            candidates: resolved,
        })))
    }
}

struct CandidateVerifyingKey<'a> {
    candidates: Vec<Box<dyn VerifyingKey + 'a>>,
}

impl VerifyingKey for CandidateVerifyingKey<'_> {
    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        let mut saw_mismatch = false;
        let mut last_error = None;
        for candidate in &self.candidates {
            match candidate.validate_signature_value(algorithm, signature_value) {
                Ok(true) => return Ok(true),
                Ok(false) => saw_mismatch = true,
                Err(error) => last_error = Some(error),
            }
        }
        if saw_mismatch {
            Ok(false)
        } else {
            match last_error {
                Some(error) => Err(error),
                None => Ok(false),
            }
        }
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        let mut saw_mismatch = false;
        let mut last_error = None;
        for candidate in &self.candidates {
            match candidate.verify(algorithm, signed_data, signature_value) {
                Ok(true) => return Ok(true),
                Ok(false) => saw_mismatch = true,
                Err(error) => last_error = Some(error),
            }
        }
        if saw_mismatch {
            Ok(false)
        } else {
            match last_error {
                Some(error) => Err(error),
                None => Ok(false),
            }
        }
    }
}

fn load_explicit_certificate_key_info(
    certificate: &crate::OptionValue,
    budget: &mut CertificateBudget,
) -> Result<KeyInfo, CommandError> {
    let certificate_der = key_material::load_certificate(
        certificate.value.as_deref().unwrap_or_default(),
        certificate_encoding(certificate),
    )?;
    budget.charge(certificate_der.len())?;
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
    parse_key_info(document.root_element())
        .map_err(|error| CommandError::Signature(error.to_string()))
}

fn encrypt(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, ENCRYPT_OPTIONS)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    let has_binary_data = invocation.last_value("binary-data").is_some();
    let has_xml_data = invocation.last_value("xml-data").is_some();
    if has_binary_data == has_xml_data {
        return Err(CommandError::Usage(
            "encrypt requires exactly one of --binary-data or --xml-data".into(),
        ));
    }
    let policy = EncryptionPolicy::default();
    let maximum_document_bytes = policy.resources.max_xml_document_bytes;
    let maximum_plaintext_bytes = policy.resources.max_encryption_plaintext_bytes;
    let template = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let metadata = encryption_template(&template, start_node_id, &id_attributes, &policy)?;
    let algorithm = metadata.algorithm;
    let encrypted_type = metadata.encrypted_type;
    let explicit_xml_type = metadata.explicit_xml_type;
    let template_placement = metadata.placement;
    let mut builder = EncryptedDataBuilder::new(algorithm).policy(policy.clone());
    let aes_keys = invocation.values("aes-key").collect::<Vec<_>>();
    let public_keys = invocation
        .ordered_values(&[
            "pubkey-pem",
            "pubkey-der",
            "pubkey-cert-pem",
            "pubkey-cert-der",
        ])
        .map(|option| {
            let certificate = matches!(option.name.as_str(), "pubkey-cert-pem" | "pubkey-cert-der");
            (option, certificate)
        })
        .collect::<Vec<_>>();
    if !aes_keys.is_empty() && !public_keys.is_empty() {
        return Err(CommandError::Usage(
            "encrypt cannot combine explicit AES and RSA recipient keys".into(),
        ));
    }
    if !aes_keys.is_empty() {
        if metadata.has_encrypted_key_recipient {
            return Err(CommandError::Usage(
                "direct AES key cannot satisfy an EncryptedKey recipient in the template".into(),
            ));
        }
        let candidates = aes_keys
            .iter()
            .copied()
            .map(|option| (option, ()))
            .collect::<Vec<_>>();
        let requested_names = metadata
            .content_key_name
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let candidates = named_candidate_search(
            &candidates,
            &requested_names,
            invocation.flag("lax-key-search"),
            true,
            "AES key",
        )?;
        let mut selected = None;
        let mut last_error = None;
        for (option, ()) in candidates {
            match key_material::load_symmetric(
                option.value.as_deref().unwrap_or_default(),
                Some(algorithm.key_len()),
            ) {
                Ok(key) => {
                    selected = Some((option, key));
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let (option, key) = selected.ok_or_else(|| {
            last_error
                .map(CommandError::from)
                .unwrap_or_else(|| CommandError::Usage("no compatible AES key input".into()))
        })?;
        builder = builder.direct_key(key);
        if let Some(name) = option.parameter.as_deref() {
            builder = builder.direct_key_name(name);
        }
    } else if !public_keys.is_empty() {
        let template_recipients = if metadata.recipients.is_empty() {
            vec![EncryptionTemplateRecipient {
                key_name: None,
                oaep_parameters: None,
            }]
        } else {
            metadata.recipients
        };
        let lax_key_search = invocation.flag("lax-key-search");
        let mut available_public_keys = public_keys.clone();
        let mut loaded_public_keys = HashMap::new();
        let mut certificate_budget =
            CertificateBudget::new(policy.resources.max_external_resource_total_bytes);
        let mut selected_recipients = Vec::with_capacity(template_recipients.len());
        let recipient_metadata = recipient_key_metadata(
            &template,
            start_node_id,
            &id_attributes,
            &policy,
            template_recipients.len(),
        )?;
        for (template_recipient, metadata) in
            template_recipients.into_iter().zip(recipient_metadata)
        {
            let requested_names = template_recipient
                .key_name
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            let candidates = named_candidate_search(
                &available_public_keys,
                &requested_names,
                lax_key_search,
                true,
                "RSA recipient key",
            )?;
            let mut selected = None;
            let mut last_error: Option<CommandError> = None;
            for (option, certificate) in candidates {
                match cached_rsa_recipient_candidate(
                    &mut loaded_public_keys,
                    option,
                    certificate,
                    &policy,
                    &mut certificate_budget,
                )
                .and_then(|key| {
                    validate_recipient_key_metadata(metadata.as_ref(), &key)?;
                    Ok(key)
                }) {
                    Ok(key) => {
                        selected = Some((option, certificate, key.public_key));
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            let (selected_option, selected_certificate, public_key) =
                selected.ok_or_else(|| {
                    last_error.unwrap_or_else(|| {
                        CommandError::Usage("no compatible RSA recipient key input".into())
                    })
                })?;
            if lax_key_search {
                let selected_index = available_public_keys
                    .iter()
                    .position(|(option, certificate)| {
                        std::ptr::eq(*option, selected_option)
                            && *certificate == selected_certificate
                    })
                    .ok_or_else(|| {
                        CommandError::Encryption(
                            "selected recipient key is absent from the candidate set".into(),
                        )
                    })?;
                available_public_keys.remove(selected_index);
            }
            let key_name = template_recipient
                .key_name
                .or_else(|| selected_option.parameter.clone());
            selected_recipients.push((public_key, template_recipient.oaep_parameters, key_name));
        }
        for (public_key, parameters, key_name) in selected_recipients {
            let mut recipient = EncryptionRecipient::rsa_oaep(public_key);
            if let Some(parameters) = parameters {
                recipient = recipient.oaep_parameters(parameters);
            }
            if let Some(key_name) = key_name {
                recipient = recipient.key_name(key_name);
            }
            builder = builder.add_recipient(recipient);
        }
    } else {
        return Err(CommandError::Usage(
            "encrypt requires --aes-key, an RSA public key, or an RSA certificate".into(),
        ));
    }
    builder = builder.encryption_type(encrypted_type.clone());
    let result = if let Some(path) = invocation.last_value("binary-data") {
        if template_placement == EncryptionTemplatePlacement::Embedded {
            return Err(CommandError::Usage(
                "--binary-data requires a standalone EncryptedData template; embedded templates require --xml-data so decryption can replace XML".into(),
            ));
        }
        if explicit_xml_type {
            return Err(CommandError::Usage(
                "--binary-data cannot be used with an XML Element or Content template Type".into(),
            ));
        }
        let data = read_plaintext(path, maximum_plaintext_bytes)?;
        builder.encrypt_binary(&data)
    } else if let Some(path) = invocation.last_value("xml-data") {
        let data = read_xml_data(path, maximum_document_bytes)?;
        let plaintext = xml_data_plaintext(&data, &encrypted_type, &policy)?;
        builder.encrypt_xml(plaintext.as_ref())
    } else {
        return Err(CommandError::Usage(
            "encrypt requires --binary-data or --xml-data".into(),
        ));
    }
    .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let rendered = apply_encryption_template(
        &template,
        &result.encrypted_data_xml,
        start_node_id,
        &id_attributes,
        &policy,
    )?;
    write_result_then_stdout_diagnostics(invocation, rendered.as_bytes(), stdout, |stdout| {
        write_encryption_diagnostics(invocation, algorithm, stdout)
    })
}

fn xml_data_plaintext<'a>(
    xml: &'a str,
    encrypted_type: &EncryptedDataType,
    policy: &EncryptionPolicy,
) -> Result<Cow<'a, str>, CommandError> {
    // libxmlsec1 parses --xml-data into a document and passes its root node to
    // xmlSecEncCtxXmlEncrypt. Element serializes that node; Content serializes
    // only its children. The document declaration and boundary nodes therefore
    // never become encrypted replacement plaintext.
    let document = parse_encryption_document(xml, policy)?;
    let root = document.root_element();
    let element = &xml[root.range()];
    match encrypted_type {
        EncryptedDataType::Element => {
            ensure_plaintext_capacity(
                0,
                element.len(),
                policy.resources.max_encryption_plaintext_bytes,
            )?;
            Ok(Cow::Borrowed(element))
        }
        EncryptedDataType::Content => {
            let maximum = policy.resources.max_encryption_plaintext_bytes;
            let mut content = String::with_capacity(element.len().min(maximum));
            for child in root.children() {
                append_serialized_xml_child(&mut content, xml, child, maximum)?;
            }
            Ok(Cow::Owned(content))
        }
        EncryptedDataType::Other(_) => Err(CommandError::Encryption(
            "unsupported EncryptedData Type for XML data".into(),
        )),
    }
}

fn append_serialized_xml_child(
    output: &mut String,
    source: &str,
    node: roxmltree::Node<'_, '_>,
    maximum: usize,
) -> Result<(), CommandError> {
    if node.is_element() {
        return append_standalone_element(output, source, node, maximum);
    }
    // roxmltree's source range retains the lexical representation of text,
    // including entity references and complete CDATA delimiters. Copying that
    // range preserves text semantics without accidentally creating markup.
    push_plaintext(output, &source[node.range()], maximum)
}

fn write_encryption_diagnostics(
    invocation: &Invocation,
    algorithm: DataEncryptionAlgorithm,
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    if invocation.flag("print-debug") {
        writeln!(stdout, "== Data Encryption Context").map_err(stdout_error)?;
        writeln!(stdout, "Status: succeeded").map_err(stdout_error)?;
        writeln!(stdout, "Encryption Method: {}", algorithm.uri()).map_err(stdout_error)?;
    }
    if invocation.flag("print-xml-debug") {
        writeln!(
            stdout,
            "<DataEncryptionContext status=\"replaced\" failureReason=\"UNKNOWN\">"
        )
        .map_err(stdout_error)?;
        write_debug_transform(stdout, "EncryptionMethod", algorithm.uri())?;
        writeln!(stdout, "</DataEncryptionContext>").map_err(stdout_error)?;
    }
    Ok(())
}

fn write_debug_transform(
    stdout: &mut dyn Write,
    container: &str,
    uri: &str,
) -> Result<(), CommandError> {
    let name = uri.rsplit_once('#').map_or(uri, |(_, name)| name);
    writeln!(stdout, "<{container}>").map_err(stdout_error)?;
    writeln!(
        stdout,
        "<Transform name=\"{}\" href=\"{}\" />",
        quick_xml::escape::escape(name),
        quick_xml::escape::escape(uri)
    )
    .map_err(stdout_error)?;
    writeln!(stdout, "</{container}>").map_err(stdout_error)
}

#[derive(Clone, Debug)]
struct RecipientPublicKeyCandidate {
    public_key: RsaPublicKey,
    certificate_der: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum RecipientPublicKeySource {
    Public(key_material::PublicKeyEncoding),
    Certificate(key_material::CertificateEncoding),
}

fn load_rsa_recipient_candidate(
    path: &OsStr,
    source: RecipientPublicKeySource,
    policy: &EncryptionPolicy,
    certificate_budget: &mut CertificateBudget,
) -> Result<RecipientPublicKeyCandidate, CommandError> {
    let candidate = match source {
        RecipientPublicKeySource::Public(encoding) => RecipientPublicKeyCandidate {
            public_key: key_material::load_rsa_public(path, encoding)?,
            certificate_der: None,
        },
        RecipientPublicKeySource::Certificate(encoding) => {
            let (public_key, certificate_der) =
                key_material::load_rsa_certificate_public(path, encoding)?;
            certificate_budget.charge(certificate_der.len())?;
            RecipientPublicKeyCandidate {
                public_key,
                certificate_der: Some(certificate_der),
            }
        }
    };
    validate_rsa_recipient_key(&candidate.public_key, policy)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    Ok(candidate)
}

fn cached_rsa_recipient_candidate(
    cache: &mut HashMap<*const crate::OptionValue, Result<RecipientPublicKeyCandidate, String>>,
    option: &crate::OptionValue,
    certificate: bool,
    policy: &EncryptionPolicy,
    certificate_budget: &mut CertificateBudget,
) -> Result<RecipientPublicKeyCandidate, CommandError> {
    let identity = std::ptr::from_ref(option);
    if let Some(cached) = cache.get(&identity) {
        return cached.clone().map_err(CommandError::Encryption);
    }
    let source = if certificate {
        RecipientPublicKeySource::Certificate(certificate_encoding(option))
    } else {
        RecipientPublicKeySource::Public(public_key_encoding(option))
    };
    match load_rsa_recipient_candidate(
        option.value.as_deref().unwrap_or_default(),
        source,
        policy,
        certificate_budget,
    ) {
        Ok(candidate) => {
            cache.insert(identity, Ok(candidate.clone()));
            Ok(candidate)
        }
        Err(error) => {
            cache.insert(identity, Err(error.to_string()));
            Err(error)
        }
    }
}

#[derive(Clone)]
struct ParsedRecipientKeyMetadata(KeyInfo);

fn recipient_key_metadata(
    template: &str,
    start_node_id: Option<&str>,
    id_attributes: &[IdAttributeRegistration],
    policy: &EncryptionPolicy,
    expected_recipients: usize,
) -> Result<Vec<Option<ParsedRecipientKeyMetadata>>, CommandError> {
    let document = parse_encryption_document(template, policy)?;
    let encrypted_data = select_encrypted_data(&document, start_node_id, id_attributes)?;
    let encrypted_keys = direct_child_element(encrypted_data, XMLDSIG_NS, "KeyInfo")
        .into_iter()
        .flat_map(|key_info| key_info.children())
        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .collect::<Vec<_>>();
    if encrypted_keys.is_empty() {
        return Ok(vec![None; expected_recipients]);
    }
    if encrypted_keys.len() != expected_recipients {
        return Err(recipient_metadata_error(
            "selected RSA key count does not match template recipients",
        ));
    }

    encrypted_keys
        .into_iter()
        .map(|encrypted_key| {
            direct_child_element(encrypted_key, XMLDSIG_NS, "KeyInfo")
                .map(|node| parse_key_info(node).map(ParsedRecipientKeyMetadata))
                .transpose()
                .map_err(|error| CommandError::Encryption(error.to_string()))
        })
        .collect()
}

fn validate_recipient_key_metadata(
    metadata: Option<&ParsedRecipientKeyMetadata>,
    selected_key: &RecipientPublicKeyCandidate,
) -> Result<(), CommandError> {
    if let Some(metadata) = metadata {
        for source in &metadata.0.sources {
            let matches = match source {
                KeyInfoSource::KeyName(_) => continue,
                KeyInfoSource::KeyValue(KeyValueInfo::Rsa { modulus, exponent }) => {
                    rsa_components_match(&selected_key.public_key, modulus, exponent)
                }
                KeyInfoSource::X509Data(data) => {
                    if data.certificates.is_empty()
                        && data.subject_names.is_empty()
                        && data.issuer_serials.is_empty()
                        && data.skis.is_empty()
                        && data.digests.is_empty()
                    {
                        // An empty placeholder (or CRL-only source) makes no
                        // recipient identity claim and is safe to preserve.
                        continue;
                    }
                    let certificate_index = data
                        .certificate_chain
                        .first()
                        .copied()
                        .or_else(|| (!data.certificates.is_empty()).then_some(0));
                    if let Some(certificate_index) = certificate_index {
                        // ParsedRecipientKeyMetadata proves parse_key_info has
                        // already matched every selector category against this
                        // one embedded certificate chain.
                        let certificate =
                            data.certificates.get(certificate_index).ok_or_else(|| {
                                recipient_metadata_error(
                                    "X509Data certificate chain is inconsistent",
                                )
                            })?;
                        let (_, certificate) =
                            x509_parser::certificate::X509Certificate::from_der(certificate)
                                .map_err(|_| {
                                    recipient_metadata_error("X509Certificate is invalid")
                                })?;
                        let public_key =
                            RsaPublicKey::from_public_key_der(certificate.public_key().raw)
                                .map_err(|_| {
                                    recipient_metadata_error(
                                        "X509Certificate does not contain an RSA key",
                                    )
                                })?;
                        rsa_public_keys_match(&selected_key.public_key, &public_key)
                    } else {
                        let certificate =
                            selected_key.certificate_der.as_deref().ok_or_else(|| {
                                recipient_metadata_error(
                                    "X509Data selectors require a selected RSA certificate",
                                )
                            })?;
                        x509_certificate_matches_selectors(data, certificate, default_provider())
                            .map_err(|error| CommandError::Encryption(error.to_string()))?
                    }
                }
                KeyInfoSource::DerEncodedKeyValue(der) => {
                    let public_key = RsaPublicKey::from_public_key_der(der).map_err(|_| {
                        recipient_metadata_error("DEREncodedKeyValue is not an RSA public key")
                    })?;
                    rsa_public_keys_match(&selected_key.public_key, &public_key)
                }
                KeyInfoSource::KeyValue(_) | KeyInfoSource::RetrievalMethod { .. } => {
                    return Err(recipient_metadata_error(
                        "recipient key source cannot be matched to the selected RSA key",
                    ));
                }
                _ => {
                    return Err(recipient_metadata_error(
                        "recipient key source cannot be matched to the selected RSA key",
                    ));
                }
            };
            if !matches {
                return Err(recipient_metadata_error(
                    "recipient key metadata does not match the selected RSA key",
                ));
            }
        }
    }
    Ok(())
}

fn rsa_components_match(key: &RsaPublicKey, modulus: &[u8], exponent: &[u8]) -> bool {
    key.n().to_be_bytes_trimmed_vartime().as_ref() == trim_crypto_binary_zeroes(modulus)
        && key.e().to_be_bytes_trimmed_vartime().as_ref() == trim_crypto_binary_zeroes(exponent)
}

fn trim_crypto_binary_zeroes(value: &[u8]) -> &[u8] {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[first_nonzero..]
}

fn rsa_public_keys_match(left: &RsaPublicKey, right: &RsaPublicKey) -> bool {
    left.n() == right.n() && left.e() == right.e()
}

fn recipient_metadata_error(message: &str) -> CommandError {
    CommandError::Encryption(format!("recipient key metadata is inconsistent: {message}"))
}

fn template_oaep_parameters(
    method: &EncryptionMethod,
) -> Result<Option<RsaOaepParameters>, CommandError> {
    let transport = KeyTransportAlgorithm::from_uri(&method.algorithm)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let digest = oaep_digest_from_uri(
        method
            .oaep_digest
            .as_deref()
            .unwrap_or(OaepDigestAlgorithm::Sha1.uri()),
    )?;
    let mgf_digest = if transport == KeyTransportAlgorithm::RsaOaepMgf1p {
        OaepDigestAlgorithm::Sha1
    } else {
        oaep_mgf_from_uri(
            method
                .mgf_algorithm
                .as_deref()
                .unwrap_or(OaepDigestAlgorithm::Sha1.mgf_uri()),
        )?
    };
    Ok(Some(RsaOaepParameters {
        algorithm: transport,
        digest,
        mgf_digest,
        label: method.oaep_params.clone().unwrap_or_default(),
    }))
}

fn singleton_direct_child<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: &str,
    name: &str,
    cardinality_error: &str,
) -> Result<Option<Node<'a, 'input>>, CommandError> {
    let mut children = parent
        .children()
        .filter(|node| node.has_tag_name((namespace, name)));
    let child = children.next();
    if children.next().is_some() {
        return Err(CommandError::Encryption(cardinality_error.into()));
    }
    Ok(child)
}

fn direct_simple_text(node: Node<'_, '_>, field: &str) -> Result<String, CommandError> {
    if node.children().any(|child| child.is_element()) {
        return Err(CommandError::Encryption(format!(
            "{field} must not contain element children"
        )));
    }
    Ok(node
        .children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect())
}

fn oaep_digest_from_uri(uri: &str) -> Result<OaepDigestAlgorithm, CommandError> {
    OaepDigestAlgorithm::from_uri(uri)
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

fn apply_encryption_template(
    template: &str,
    generated: &str,
    start_node_id: Option<&str>,
    id_attributes: &[IdAttributeRegistration],
    policy: &EncryptionPolicy,
) -> Result<String, CommandError> {
    let template_document = parse_encryption_document(template, policy)?;
    let generated_document = parse_encryption_document(generated, policy)?;
    let template_data = select_encrypted_data(&template_document, start_node_id, id_attributes)?;
    let generated_data = generated_document.root_element();
    let template_cipher = required_cipher_value(template_data, "template EncryptedData")?;
    let generated_cipher = required_cipher_value(generated_data, "generated EncryptedData")?;
    let mut replacements = vec![(
        template_cipher.range(),
        standalone_cipher_value(generated_cipher),
    )];
    if template_data.attribute("Type").is_none()
        && let Some(generated_type) = generated_data.attribute("Type")
    {
        let opening_end = opening_tag_end(&template[template_data.range().start..])
            .map(|offset| template_data.range().start + offset)
            .ok_or_else(|| {
                CommandError::Encryption("template EncryptedData is malformed".into())
            })?;
        replacements.push((
            opening_end..opening_end,
            format!(" Type=\"{}\"", quick_xml::escape::escape(generated_type)),
        ));
    }

    let template_key_info = direct_child_element(template_data, XMLDSIG_NS, "KeyInfo");
    let generated_key_info = direct_child_element(generated_data, XMLDSIG_NS, "KeyInfo");
    match (template_key_info, generated_key_info) {
        (Some(template_key_info), Some(generated_key_info)) => {
            let template_keys = direct_encrypted_keys(template_key_info);
            let generated_keys = direct_encrypted_keys(generated_key_info);
            let template_values = encrypted_key_cipher_values(template_key_info, "template")?;
            let generated_values = encrypted_key_cipher_values(generated_key_info, "generated")?;
            let missing_generated_children = generated_key_info
                .children()
                .filter(|node| node.is_element() && !node.has_tag_name((XMLENC_NS, "EncryptedKey")))
                .filter(|generated_child| {
                    !template_key_info.children().any(|template_child| {
                        template_child.is_element()
                            && template_child.tag_name() == generated_child.tag_name()
                    })
                })
                .map(|node| standalone_element(generated, node))
                .collect::<Result<Vec<_>, _>>()?;
            if !template_key_info.children().any(|node| node.is_element()) {
                let generated_children = generated_key_info
                    .children()
                    .filter(|node| node.is_element())
                    .map(|node| standalone_element(generated, node))
                    .collect::<Result<Vec<_>, _>>()?;
                if !generated_children.is_empty() {
                    replacements.push(append_element_children_replacement(
                        template,
                        template_key_info,
                        &generated_children.concat(),
                    )?);
                }
            } else {
                let mut children_to_append = missing_generated_children;
                if template_values.is_empty() && !generated_values.is_empty() {
                    let generated_keys = generated_key_info
                        .children()
                        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
                        .map(|node| standalone_element(generated, node))
                        .collect::<Result<Vec<_>, _>>()?;
                    if generated_keys.len() != generated_values.len() {
                        return Err(CommandError::Encryption(
                            "generated KeyInfo does not contain one direct EncryptedKey per recipient"
                                .into(),
                        ));
                    }
                    children_to_append.extend(generated_keys);
                }
                if !children_to_append.is_empty() {
                    replacements.push(append_element_children_replacement(
                        template,
                        template_key_info,
                        &children_to_append.concat(),
                    )?);
                }
                if !template_values.is_empty() {
                    if template_values.len() != generated_values.len() {
                        return Err(CommandError::Encryption(
                            "template KeyInfo does not contain one CipherValue per generated recipient"
                                .into(),
                        ));
                    }
                    for (template_key, generated_key) in
                        template_keys.into_iter().zip(generated_keys)
                    {
                        if let Some(replacement) = merge_generated_recipient_key_name(
                            template,
                            template_key,
                            generated,
                            generated_key,
                        )? {
                            replacements.push(replacement);
                        }
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
            }
        }
        (None, Some(generated_key_info)) => {
            let cipher_data = direct_child_element(template_data, XMLENC_NS, "CipherData")
                .ok_or_else(|| CommandError::Encryption("template has no CipherData".into()))?;
            let key_info = standalone_element(generated, generated_key_info)?;
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
    if output.len() > policy.resources.max_xml_document_bytes {
        return Err(CommandError::Encryption(
            "encrypted template output exceeds XML document policy".into(),
        ));
    }
    parse_encryption_document(&output, policy)?;
    Ok(output)
}

fn append_element_children_replacement(
    source: &str,
    node: roxmltree::Node<'_, '_>,
    children: &str,
) -> Result<(std::ops::Range<usize>, String), CommandError> {
    let fragment = &source[node.range()];
    if fragment.trim_end().ends_with("/>") {
        let empty_end = fragment
            .rfind("/>")
            .ok_or_else(|| CommandError::Encryption("template KeyInfo is malformed".into()))?;
        let name_end = fragment[1..]
            .find(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '/' | '>'))
            .map(|offset| offset + 1)
            .ok_or_else(|| CommandError::Encryption("template KeyInfo is malformed".into()))?;
        let qualified_name = &fragment[1..name_end];
        return Ok((
            node.range(),
            format!("{}>{children}</{qualified_name}>", &fragment[..empty_end]),
        ));
    }
    let closing = fragment
        .rfind("</")
        .ok_or_else(|| CommandError::Encryption("template KeyInfo is malformed".into()))?;
    let insertion = node.range().start + closing;
    Ok((insertion..insertion, children.to_owned()))
}

fn merge_generated_recipient_key_name(
    template: &str,
    template_key: Node<'_, '_>,
    generated: &str,
    generated_key: Node<'_, '_>,
) -> Result<Option<(std::ops::Range<usize>, String)>, CommandError> {
    let Some(generated_key_info) = direct_child_element(generated_key, XMLDSIG_NS, "KeyInfo")
    else {
        return Ok(None);
    };
    let Some(generated_key_name) = direct_child_element(generated_key_info, XMLDSIG_NS, "KeyName")
    else {
        return Ok(None);
    };
    let key_name = standalone_element(generated, generated_key_name)?;

    if let Some(template_key_info) = direct_child_element(template_key, XMLDSIG_NS, "KeyInfo") {
        if direct_child_element(template_key_info, XMLDSIG_NS, "KeyName").is_some() {
            return Ok(None);
        }
        return append_element_children_replacement(template, template_key_info, &key_name)
            .map(Some);
    }

    let cipher_data =
        direct_child_element(template_key, XMLENC_NS, "CipherData").ok_or_else(|| {
            CommandError::Encryption("template EncryptedKey has no CipherData".into())
        })?;
    Ok(Some((
        cipher_data.range().start..cipher_data.range().start,
        format!("<KeyInfo xmlns=\"{XMLDSIG_NS}\">{key_name}</KeyInfo>"),
    )))
}

fn opening_tag_end(fragment: &str) -> Option<usize> {
    let mut quote = None;
    for (offset, ch) in fragment.char_indices() {
        match (quote, ch) {
            (None, '\'' | '"') => quote = Some(ch),
            (Some(delimiter), current) if delimiter == current => quote = None,
            (None, '>') => return Some(offset),
            _ => {}
        }
    }
    None
}

fn standalone_cipher_value(node: roxmltree::Node<'_, '_>) -> String {
    format!(
        "<CipherValue xmlns=\"http://www.w3.org/2001/04/xmlenc#\">{}</CipherValue>",
        node.text().unwrap_or_default()
    )
}

fn standalone_element(source: &str, node: roxmltree::Node<'_, '_>) -> Result<String, CommandError> {
    let mut output = String::new();
    append_standalone_element(&mut output, source, node, usize::MAX)?;
    Ok(output)
}

fn append_standalone_element(
    output: &mut String,
    source: &str,
    node: roxmltree::Node<'_, '_>,
    maximum: usize,
) -> Result<(), CommandError> {
    let fragment = &source[node.range()];
    let opening_end = opening_tag_end(fragment)
        .ok_or_else(|| CommandError::Encryption("element has no opening tag".into()))?;
    let opening = fragment[..opening_end].trim_end();
    let self_closing = opening.ends_with('/');
    let opening = opening.strip_suffix('/').unwrap_or(opening).trim_end();
    let qualified_name_end = opening.find(char::is_whitespace).unwrap_or(opening.len());
    let qualified_name = &opening[1..qualified_name_end];
    let attributes = &opening[qualified_name_end..];
    push_plaintext(output, "<", maximum)?;
    push_plaintext(output, qualified_name, maximum)?;
    push_plaintext(output, attributes, maximum)?;
    let owned_namespaces = owned_namespace_declarations(opening)?;
    for namespace in node.namespaces() {
        let declaration = namespace
            .name()
            .map_or("xmlns".to_owned(), |prefix| format!("xmlns:{prefix}"));
        let already_declared = owned_namespaces.contains(namespace.name().unwrap_or_default());
        if !already_declared {
            push_plaintext(output, " ", maximum)?;
            push_plaintext(output, &declaration, maximum)?;
            push_plaintext(output, "=\"", maximum)?;
            push_plaintext(output, &quick_xml::escape::escape(namespace.uri()), maximum)?;
            push_plaintext(output, "\"", maximum)?;
        }
    }
    if self_closing {
        push_plaintext(output, "/>", maximum)?;
    } else {
        let closing_start = fragment
            .rfind("</")
            .ok_or_else(|| CommandError::Encryption("element has no closing tag".into()))?;
        push_plaintext(output, ">", maximum)?;
        push_plaintext(output, &fragment[opening_end + 1..closing_start], maximum)?;
        push_plaintext(output, "</", maximum)?;
        push_plaintext(output, qualified_name, maximum)?;
        push_plaintext(output, ">", maximum)?;
    }
    Ok(())
}

fn push_plaintext(output: &mut String, fragment: &str, maximum: usize) -> Result<(), CommandError> {
    ensure_plaintext_capacity(output.len(), fragment.len(), maximum)?;
    output.push_str(fragment);
    Ok(())
}

fn ensure_plaintext_capacity(
    current: usize,
    additional: usize,
    maximum: usize,
) -> Result<(), CommandError> {
    current
        .checked_add(additional)
        .filter(|length| *length <= maximum)
        .map(|_| ())
        .ok_or(CommandError::PlaintextTooLarge { maximum })
}

fn owned_namespace_declarations(opening: &str) -> Result<HashSet<String>, CommandError> {
    let standalone = format!("{} />", opening.trim_end_matches('/'));
    let mut reader = quick_xml::Reader::from_str(&standalone);
    let event = reader
        .read_event()
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let element = match event {
        quick_xml::events::Event::Start(element) | quick_xml::events::Event::Empty(element) => {
            element
        }
        _ => {
            return Err(CommandError::Encryption(
                "generated KeyInfo child has no opening element".into(),
            ));
        }
    };
    element
        .attributes()
        .map(|attribute| {
            let attribute =
                attribute.map_err(|error| CommandError::Encryption(error.to_string()))?;
            let name = std::str::from_utf8(attribute.key.as_ref()).map_err(|_| {
                CommandError::Encryption("generated KeyInfo attribute name is not UTF-8".into())
            })?;
            Ok(match name {
                "xmlns" => Some(String::new()),
                _ => name.strip_prefix("xmlns:").map(str::to_owned),
            })
        })
        .filter_map(|result| result.transpose())
        .collect()
}

fn direct_child_element<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| child.has_tag_name((namespace, name)))
}

fn required_cipher_value<'a, 'input>(
    parent: roxmltree::Node<'a, 'input>,
    owner: &str,
) -> Result<roxmltree::Node<'a, 'input>, CommandError> {
    let cipher_data = singleton_direct_child(
        parent,
        XMLENC_NS,
        "CipherData",
        &format!("{owner} contains more than one direct CipherData"),
    )?
    .ok_or_else(|| CommandError::Encryption(format!("{owner} has no direct CipherData")))?;
    singleton_direct_child(
        cipher_data,
        XMLENC_NS,
        "CipherValue",
        &format!("{owner} CipherData contains more than one direct CipherValue"),
    )?
    .ok_or_else(|| CommandError::Encryption(format!("{owner} CipherData has no CipherValue")))
}

fn encrypted_key_cipher_values<'a, 'input>(
    key_info: roxmltree::Node<'a, 'input>,
    owner: &str,
) -> Result<Vec<roxmltree::Node<'a, 'input>>, CommandError> {
    direct_encrypted_keys(key_info)
        .into_iter()
        .enumerate()
        .map(|(index, encrypted_key)| {
            required_cipher_value(
                encrypted_key,
                &format!("{owner} EncryptedKey recipient {}", index + 1),
            )
        })
        .collect()
}

fn direct_encrypted_keys<'a, 'input>(
    key_info: roxmltree::Node<'a, 'input>,
) -> Vec<roxmltree::Node<'a, 'input>> {
    key_info
        .children()
        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .collect()
}

fn decrypt(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, DECRYPT_OPTIONS)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    if invocation.last_value("pwd").is_some() {
        return Err(CommandError::UnsupportedOption("pwd".into()));
    }
    let policy = DecryptionPolicy::default();
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let encrypted_data_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let document = parse_encryption_document(&xml, &policy)?;
    let encrypted_data = select_encrypted_data(&document, encrypted_data_id, &id_attributes)?;
    let standalone = encrypted_data == document.root_element();
    let content_key_name = encrypted_data_key_name(encrypted_data)?;
    let recipient_key_names = encrypted_key_recipient_names(encrypted_data)?;
    let aes_keys = invocation.values("aes-key").collect::<Vec<_>>();
    let private_keys = invocation
        .ordered_values(&["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"])
        .collect::<Vec<_>>();
    if !aes_keys.is_empty() && !private_keys.is_empty() {
        return Err(CommandError::Usage(
            "decrypt cannot combine explicit AES and RSA private keys".into(),
        ));
    }
    let bytes = if !aes_keys.is_empty() {
        let candidates = aes_keys
            .iter()
            .copied()
            .map(|option| (option, ()))
            .collect::<Vec<_>>();
        let requested_names = content_key_name.iter().cloned().collect::<Vec<_>>();
        let candidates = named_candidate_search(
            &candidates,
            &requested_names,
            invocation.flag("lax-key-search"),
            true,
            "AES key",
        )?;
        let lax_key_search = invocation.flag("lax-key-search");
        let mut keys = Vec::with_capacity(candidates.len());
        let mut last_error = None;
        for (option, ()) in candidates {
            match key_material::load_symmetric(option.value.as_deref().unwrap_or_default(), None) {
                Ok(key) => keys.push(key),
                Err(error) if lax_key_search => last_error = Some(CommandError::from(error)),
                Err(error) => return Err(error.into()),
            }
        }
        if keys.is_empty() {
            return Err(last_error
                .unwrap_or_else(|| CommandError::Usage("no compatible AES key input".into())));
        }
        decrypt_input(
            &CandidateSymmetricKeyDecryptor { keys },
            &xml,
            encrypted_data_id,
            standalone,
            policy,
            &id_attributes,
        )?
    } else if !private_keys.is_empty() {
        let selected = select_recipient_private_keys(
            &private_keys,
            &recipient_key_names,
            invocation.flag("lax-key-search"),
        )?;
        let mut keys = Vec::with_capacity(selected.len());
        let lax_key_search = invocation.flag("lax-key-search");
        let mut last_load_error = None;
        let mut certificate_budget =
            CertificateBudget::new(policy.resources.max_external_resource_total_bytes);
        for option in selected {
            let loaded = (|| {
                let (path, certificate_paths) =
                    split_key_and_certificates(option.value.as_deref().unwrap_or_default())?;
                let private_key = key_material::load_rsa_private(path, private_key_format(option))?;
                if !certificate_paths.is_empty() {
                    let encoding = if matches!(
                        private_key_format(option),
                        key_material::PrivateKeyFormat::Der
                            | key_material::PrivateKeyFormat::Pkcs8Der
                    ) {
                        key_material::CertificateEncoding::Der
                    } else {
                        key_material::CertificateEncoding::Pem
                    };
                    let certificates = load_certificate_companions(
                        &certificate_paths,
                        encoding,
                        &mut certificate_budget,
                    )?;
                    ensure_leaf_certificate_matches_rsa_key(&certificates[0], &private_key)?;
                }
                Ok::<_, CommandError>(RecipientPrivateKey {
                    inner: PrivateKeyDecryptor::new(private_key),
                    key_name: option.parameter.clone(),
                })
            })();
            match loaded {
                Ok(key) => keys.push(key),
                Err(error) if lax_key_search => last_load_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        if keys.is_empty() {
            return Err(last_load_error.unwrap_or_else(|| {
                CommandError::Usage("no compatible RSA private key input".into())
            }));
        }
        let resolver = NamedRecipientDecryptor {
            keys,
            lax_key_search,
            unnamed_single_key_fallback: private_keys.len() == 1
                && private_keys[0].parameter.is_none(),
        };
        decrypt_input(
            &resolver,
            &xml,
            encrypted_data_id,
            standalone,
            policy,
            &id_attributes,
        )?
    } else {
        return Err(CommandError::Usage(
            "decrypt requires --aes-key or an RSA private key".into(),
        ));
    };
    write_result_then_stdout_diagnostics(invocation, &bytes, stdout, |stdout| {
        write_decryption_diagnostics(invocation, encrypted_data, !standalone, stdout)
    })
}

fn write_decryption_diagnostics(
    invocation: &Invocation,
    encrypted_data: Node<'_, '_>,
    result_replaced: bool,
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    if !invocation.flag("print-debug") && !invocation.flag("print-xml-debug") {
        return Ok(());
    }
    let method = direct_child_element(encrypted_data, XMLENC_NS, "EncryptionMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .ok_or_else(|| CommandError::Encryption("template has no encryption algorithm".into()))?;
    let transform_name = method.rsplit_once('#').map_or(method, |(_, name)| name);
    debug_assert!(TRANSFORMS.contains(&transform_name));
    let status = if result_replaced {
        "replaced"
    } else {
        "not-replaced"
    };
    if invocation.flag("print-debug") {
        writeln!(stdout, "== Data Decryption Context").map_err(stdout_error)?;
        writeln!(stdout, "Status: succeeded").map_err(stdout_error)?;
        writeln!(stdout, "Result: {status}").map_err(stdout_error)?;
        writeln!(stdout, "Encryption Method: {method}").map_err(stdout_error)?;
    }
    if !invocation.flag("print-xml-debug") {
        return Ok(());
    }
    // Donor testEnc.sh routes plaintext through --output and parses stdout as
    // a separate xmlSecEncCtxDebugXmlDump-compatible diagnostics document.
    writeln!(
        stdout,
        "<DataDecryptionContext status=\"{status}\" failureReason=\"UNKNOWN\">"
    )
    .map_err(stdout_error)?;
    writeln!(stdout, "<Flags>00000000</Flags>").map_err(stdout_error)?;
    writeln!(stdout, "<Flags2>00000000</Flags2>").map_err(stdout_error)?;
    for (element, attribute) in [
        ("Id", "Id"),
        ("Type", "Type"),
        ("MimeType", "MimeType"),
        ("Encoding", "Encoding"),
    ] {
        let value = encrypted_data.attribute(attribute).unwrap_or("NULL");
        writeln!(
            stdout,
            "<{element}>{}</{element}>",
            quick_xml::escape::escape(value)
        )
        .map_err(stdout_error)?;
    }
    writeln!(stdout, "<Recipient>NULL</Recipient>").map_err(stdout_error)?;
    writeln!(stdout, "<CarriedKeyName>NULL</CarriedKeyName>").map_err(stdout_error)?;
    writeln!(stdout, "<EncryptionMethod>").map_err(stdout_error)?;
    writeln!(
        stdout,
        "<Transform name=\"{}\" href=\"{}\" />",
        quick_xml::escape::escape(transform_name),
        quick_xml::escape::escape(method)
    )
    .map_err(stdout_error)?;
    writeln!(stdout, "</EncryptionMethod>").map_err(stdout_error)?;
    writeln!(stdout, "</DataDecryptionContext>").map_err(stdout_error)
}

struct RecipientPrivateKey {
    inner: PrivateKeyDecryptor,
    key_name: Option<String>,
}

struct CandidateSymmetricKeyDecryptor {
    keys: Vec<Vec<u8>>,
}

impl DecryptionKeyResolver for CandidateSymmetricKeyDecryptor {
    fn resolve_key(
        &self,
        _provider: &dyn CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        self.keys.first().cloned().ok_or(XmlEncError::KeyNotFound)
    }

    fn resolve_key_candidates(
        &self,
        _provider: &dyn CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        maximum_candidates: usize,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        if encrypted_key.is_none() {
            if self.keys.len() > maximum_candidates {
                return Err(xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "decryption key candidates",
                    maximum: maximum_candidates,
                    actual: self.keys.len(),
                }
                .into());
            }
            Ok(self.keys.clone())
        } else {
            Err(XmlEncError::KeyNotFound)
        }
    }
}

struct NamedRecipientDecryptor {
    keys: Vec<RecipientPrivateKey>,
    lax_key_search: bool,
    unnamed_single_key_fallback: bool,
}

impl DecryptionKeyResolver for NamedRecipientDecryptor {
    fn resolve_key(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        let mut last_error = None;
        for key in &self.keys {
            if !self.lax_key_search
                && !self.unnamed_single_key_fallback
                && encrypted_key.and_then(|candidate| candidate.key_name.as_deref())
                    != key.key_name.as_deref()
            {
                continue;
            }
            match key.inner.resolve_key(provider, algorithm, encrypted_key) {
                Ok(key) => return Ok(key),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
    }
}

fn decrypt_input(
    resolver: &dyn DecryptionKeyResolver,
    xml: &str,
    encrypted_data_id: Option<&str>,
    standalone: bool,
    policy: DecryptionPolicy,
    id_attributes: &[IdAttributeRegistration],
) -> Result<Vec<u8>, CommandError> {
    let context = DecryptContext::new(resolver)
        .policy(policy)
        .id_attributes(id_attributes);
    if standalone {
        return context
            .decrypt(xml)
            .map(|content| match content {
                DecryptedContent::Xml(xml) => xml.into_bytes(),
                DecryptedContent::Bytes(bytes) => bytes,
            })
            .map_err(|error| CommandError::Encryption(error.to_string()));
    }
    context
        .decrypt_document_from_start_node(xml, encrypted_data_id)
        .map(String::into_bytes)
        .map_err(|error| CommandError::Encryption(error.to_string()))
}

struct EncryptionTemplateMetadata {
    algorithm: DataEncryptionAlgorithm,
    encrypted_type: EncryptedDataType,
    explicit_xml_type: bool,
    placement: EncryptionTemplatePlacement,
    has_encrypted_key_recipient: bool,
    content_key_name: Option<String>,
    recipients: Vec<EncryptionTemplateRecipient>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EncryptionTemplatePlacement {
    Standalone,
    Embedded,
}

struct EncryptionTemplateRecipient {
    key_name: Option<String>,
    oaep_parameters: Option<RsaOaepParameters>,
}

fn encryption_template(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[IdAttributeRegistration],
    policy: &EncryptionPolicy,
) -> Result<EncryptionTemplateMetadata, CommandError> {
    let document = parse_encryption_document(xml, policy)?;
    let encrypted_data = select_encrypted_data(&document, start_node_id, id_attributes)?;
    // Templates preserve every non-cipher field. Parse the selected node through
    // the reciprocal core path first so encryption cannot emit a document that
    // the same policy snapshot would reject during decryption.
    let parsed = parse_encrypted_data_template_node_with_policy(encrypted_data, policy)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let algorithm = DataEncryptionAlgorithm::from_uri(&parsed.encryption_method.algorithm)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let explicit_xml_type = matches!(
        parsed.encrypted_type,
        Some(EncryptedDataType::Element | EncryptedDataType::Content)
    );
    let encrypted_type = match parsed.encrypted_type {
        None | Some(EncryptedDataType::Element) => EncryptedDataType::Element,
        Some(EncryptedDataType::Content) => EncryptedDataType::Content,
        Some(EncryptedDataType::Other(other)) => EncryptedDataType::Other(other),
    };
    let recipients = parsed
        .encrypted_keys
        .into_iter()
        .map(|encrypted_key| {
            Ok(EncryptionTemplateRecipient {
                key_name: encrypted_key.key_name,
                oaep_parameters: template_oaep_parameters(&encrypted_key.encryption_method)?,
            })
        })
        .collect::<Result<Vec<_>, CommandError>>()?;
    Ok(EncryptionTemplateMetadata {
        algorithm,
        encrypted_type,
        explicit_xml_type,
        placement: if encrypted_data == document.root_element() {
            EncryptionTemplatePlacement::Standalone
        } else {
            EncryptionTemplatePlacement::Embedded
        },
        has_encrypted_key_recipient: !recipients.is_empty(),
        content_key_name: parsed.key_name,
        recipients,
    })
}

fn ensure_leaf_certificate_matches_rsa_key(
    certificate_der: &[u8],
    private_key: &rsa::RsaPrivateKey,
) -> Result<(), CommandError> {
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
        .map_err(|_| CommandError::Encryption("invalid X.509 certificate".into()))?;
    let public_key = RsaPublicKey::from(private_key)
        .to_public_key_der()
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    if certificate.public_key().raw != public_key.as_bytes() {
        return Err(CommandError::Encryption(
            "X.509 certificate public key does not match private key".into(),
        ));
    }
    Ok(())
}

fn encrypted_data_key_name(encrypted_data: Node<'_, '_>) -> Result<Option<String>, CommandError> {
    let Some(key_info) = singleton_direct_child(
        encrypted_data,
        XMLDSIG_NS,
        "KeyInfo",
        "EncryptedData contains more than one direct KeyInfo",
    )?
    else {
        return Ok(None);
    };
    optional_direct_child_text(
        key_info,
        XMLDSIG_NS,
        "KeyName",
        "KeyInfo contains more than one direct KeyName",
    )
}

fn optional_direct_child_text(
    parent: Node<'_, '_>,
    namespace: &str,
    name: &str,
    duplicate_error: &str,
) -> Result<Option<String>, CommandError> {
    let mut children = parent
        .children()
        .filter(|node| node.has_tag_name((namespace, name)));
    let value = children
        .next()
        .map(|node| direct_simple_text(node, name))
        .transpose()?;
    if children.next().is_some() {
        return Err(CommandError::Encryption(duplicate_error.into()));
    }
    Ok(value)
}

fn encrypted_key_recipient_names(
    encrypted_data: Node<'_, '_>,
) -> Result<Vec<Option<String>>, CommandError> {
    let key_info = singleton_direct_child(
        encrypted_data,
        XMLDSIG_NS,
        "KeyInfo",
        "EncryptedData contains more than one direct KeyInfo",
    )?;
    key_info
        .into_iter()
        .flat_map(|key_info| key_info.children())
        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .map(|encrypted_key| {
            let key_info = singleton_direct_child(
                encrypted_key,
                XMLDSIG_NS,
                "KeyInfo",
                "EncryptedKey contains more than one direct KeyInfo",
            )?;
            key_info
                .map(|key_info| {
                    optional_direct_child_text(
                        key_info,
                        XMLDSIG_NS,
                        "KeyName",
                        "EncryptedKey KeyInfo contains more than one direct KeyName",
                    )
                })
                .transpose()
                .map(Option::flatten)
        })
        .collect()
}

fn select_recipient_private_keys<'a>(
    candidates: &[&'a crate::OptionValue],
    recipient_names: &[Option<String>],
    lax_key_search: bool,
) -> Result<Vec<&'a crate::OptionValue>, CommandError> {
    if lax_key_search {
        return Ok(candidates.to_vec());
    }
    if let [candidate] = candidates
        && candidate.parameter.is_none()
    {
        return Ok(vec![*candidate]);
    }
    if recipient_names.is_empty() {
        let requested_names = Vec::new();
        let wrapped = candidates
            .iter()
            .copied()
            .map(|candidate| (candidate, ()))
            .collect::<Vec<_>>();
        return named_candidate_search(&wrapped, &requested_names, false, true, "RSA private key")
            .map(|selected| selected.into_iter().map(|(option, ())| option).collect());
    }

    let matching = candidates
        .iter()
        .copied()
        .filter(|candidate| {
            recipient_names
                .iter()
                .any(|requested| requested.as_deref() == candidate.parameter.as_deref())
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Err(CommandError::Usage(
            "template requests unknown KeyName for supplied RSA private key".into(),
        ));
    }
    let mut seen = HashSet::new();
    if matching
        .iter()
        .any(|candidate| !seen.insert(candidate.parameter.as_deref()))
    {
        return Err(CommandError::Usage(
            "multiple RSA private key inputs match the same template recipient identity".into(),
        ));
    }
    Ok(matching)
}

fn parse_encryption_document<'a>(
    xml: &'a str,
    policy: &EncryptionPolicy,
) -> Result<Document<'a>, CommandError> {
    policy
        .validate()
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let nodes_limit = u32::try_from(policy.resources.max_xml_nodes).map_err(|_| {
        CommandError::Encryption("XML node ceiling does not fit the parser limit".into())
    })?;
    Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: policy.xml.allow_internal_dtd,
            nodes_limit,
            entity_resolver: None,
        },
    )
    .map_err(|error| CommandError::Encryption(error.to_string()))
}

fn select_encrypted_data<'a>(
    document: &'a Document<'a>,
    start_node_id: Option<&str>,
    id_attributes: &[IdAttributeRegistration],
) -> Result<Node<'a, 'a>, CommandError> {
    let start = if let Some(id) = start_node_id {
        UriReferenceResolver::with_id_registrations(document, id_attributes)
            .node_for_id(id)
            .ok_or_else(|| {
                CommandError::Encryption(format!("selected node ID is missing or ambiguous: {id}"))
            })?
    } else {
        document.root()
    };
    let mut matches = start
        .descendants()
        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")));
    let selected = matches
        .next()
        .ok_or_else(|| CommandError::Encryption("document has no EncryptedData".into()))?;
    if matches.next().is_some() {
        return Err(CommandError::Encryption(
            "multiple matching EncryptedData elements".into(),
        ));
    }
    Ok(selected)
}

fn keys(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, KEYS_OPTIONS)?;
    let generated = invocation.values("gen-key").collect::<Vec<_>>();
    if generated.is_empty() {
        return Err(CommandError::Usage(
            "keys requires --gen-key:name algorithm".into(),
        ));
    }
    let mut entries = String::new();
    for generated in generated {
        let algorithm = option_value_text(generated)?;
        let size = capabilities::generated_key_len(algorithm)
            .ok_or(CommandError::CapabilityUnavailable)?;
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
    Document::parse(&document).map_err(|error| {
        CommandError::Usage(format!("generated key store is not valid XML: {error}"))
    })?;
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

fn validate_supported_selectors(
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
        "enabled-retrieval-method-uris",
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
    use std::{cell::Cell, ffi::OsString, rc::Rc};

    use super::*;

    fn invocation(arguments: &[&str]) -> Invocation {
        Invocation::parse(arguments.iter().map(OsString::from)).unwrap()
    }

    struct CountingVerificationKey {
        accepts: bool,
        calls: Rc<Cell<usize>>,
    }

    impl VerifyingKey for CountingVerificationKey {
        fn verify(
            &self,
            _algorithm: SignatureAlgorithm,
            _signed_data: &[u8],
            _signature_value: &[u8],
        ) -> Result<bool, DsigError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.accepts)
        }
    }

    #[test]
    fn candidate_verifier_retries_only_the_signature_primitive() {
        // The outer VerifyContext sees one verifier, so XML parsing, Reference
        // transforms and SignedInfo C14N are not repeated per candidate.
        let first_calls = Rc::new(Cell::new(0));
        let second_calls = Rc::new(Cell::new(0));
        let candidates = CandidateVerifyingKey {
            candidates: vec![
                Box::new(CountingVerificationKey {
                    accepts: false,
                    calls: Rc::clone(&first_calls),
                }),
                Box::new(CountingVerificationKey {
                    accepts: true,
                    calls: Rc::clone(&second_calls),
                }),
            ],
        };
        let xml = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
        ))
        .unwrap();

        let result = VerifyContext::new()
            .key(&candidates)
            .first_document_signature()
            .verify(&xml)
            .unwrap();
        assert_eq!(result.status, DsigStatus::Valid);
        assert_eq!(first_calls.get(), 1);
        assert_eq!(second_calls.get(), 1);
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
        let help = String::from_utf8(output).unwrap();
        assert!(help.starts_with("Usage: xmlsec1 verify"));
        assert!(help.contains("--pubkey-cert-pem"));
        assert!(!help.contains("--binary-data"));

        let mut command = Vec::new();
        execute(
            invocation(&["xmlsec1", "help-encrypt"]),
            &mut command,
            &mut Vec::new(),
        )
        .unwrap();
        let command = String::from_utf8(command).unwrap();
        assert!(command.contains("Usage: xmlsec1 encrypt"));
        assert!(command.contains("--binary-data"));
        assert!(!command.contains("Usage: xmlsec1 decrypt"));

        let error = execute(
            invocation(&["xmlsec1", "verify", "--lax-key-search", "input.xml"]),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(error, CommandError::UnsupportedOption(_)));
    }

    #[test]
    fn compatibility_verification_uses_libxmlsec_here_semantics() {
        // The CLI compatibility boundary must verify the same node set as the
        // donor when an XPath transform uses its non-standard here() binding.
        let policy = xmlsec_compatibility_verification_policy(&invocation(&[
            "xmlsec1",
            "verify",
            "input.xml",
        ]));
        assert_eq!(
            policy.xpath_here_semantics,
            xml_sec::xmldsig::XPathHereSemantics::XmlSecLegacy
        );
    }

    #[test]
    fn help_all_enumerates_the_registered_surface() {
        let mut output = Vec::new();
        execute(
            invocation(&["xmlsec1", "help-all"]),
            &mut output,
            &mut Vec::new(),
        )
        .unwrap();
        let help = String::from_utf8(output).unwrap();
        for command in Command::ALL {
            assert!(
                help.contains(command.canonical_name()),
                "missing command {}",
                command.canonical_name()
            );
            if command_contract(*command).is_some() {
                let mut command_output = Vec::new();
                command_help(*command, &mut command_output).unwrap();
                assert!(
                    String::from_utf8(command_output)
                        .unwrap()
                        .starts_with(&format!("Usage: xmlsec1 {}", command.canonical_name()))
                );
            }
        }
        assert!(!help.contains("sign-tmpl"));
        for option in OPTION_SPECS {
            assert!(
                help.contains(&format!("--{}", option.canonical)),
                "missing option --{}",
                option.canonical
            );
        }
        assert!(help.contains("--gen-key[:name] <value>"));
        assert!(help.contains("--insecure\n"));
    }

    #[test]
    fn injected_key_info_carries_alternate_prefix_bindings() {
        // Extracting a subtree must preserve namespace bindings inherited from
        // the generated EncryptedData root, regardless of the chosen prefixes.
        let template = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
        );
        let generated = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\" xmlns:n=\"http://www.w3.org/2009/xmlenc11#\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><s:KeyInfo><e:EncryptedKey><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><n:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/></e:EncryptionMethod><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
        );

        let rendered = apply_encryption_template(
            &template,
            &generated,
            None,
            &[],
            &EncryptionPolicy::default(),
        )
        .unwrap();
        let document = Document::parse(&rendered)
            .expect("injected KeyInfo prefixes must remain namespace-bound");
        assert!(
            document
                .descendants()
                .any(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        );
        assert!(
            document
                .descendants()
                .any(|node| node.has_tag_name(("http://www.w3.org/2009/xmlenc11#", "MGF")))
        );
    }

    #[test]
    fn generated_recipient_expands_an_empty_key_info_placeholder() {
        // An empty KeyInfo reserves the schema position but not an EncryptedKey
        // skeleton; generated recipient metadata must expand it in place.
        let template = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><s:KeyInfo/><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
        );
        let generated = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
        );

        let rendered = apply_encryption_template(
            &template,
            &generated,
            None,
            &[],
            &EncryptionPolicy::default(),
        )
        .expect("empty KeyInfo must accept a generated recipient");
        let document = Document::parse(&rendered).expect("merged output must parse");

        assert_eq!(
            document
                .descendants()
                .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
                .count(),
            1
        );
    }

    #[test]
    fn recipient_merge_keeps_parent_and_nested_insertions_disjoint() {
        // Outer key metadata, nested recipient identity, and ciphertext can all
        // be generated in one pass; their edits must not replace overlapping XML.
        let template = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><s:KeyInfo><e:EncryptedKey><s:KeyInfo/><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
        );
        let generated = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><s:KeyName>outer</s:KeyName><e:EncryptedKey><s:KeyInfo><s:KeyName>recipient</s:KeyName></s:KeyInfo><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
        );

        let rendered = apply_encryption_template(
            &template,
            &generated,
            None,
            &[],
            &EncryptionPolicy::default(),
        )
        .expect("all generated key metadata must merge without overlapping edits");
        let document = Document::parse(&rendered).expect("merged output must remain XML");
        let outer_key_info = document
            .descendants()
            .find(|node| {
                node.has_tag_name((XMLDSIG_NS, "KeyInfo"))
                    && node
                        .parent()
                        .is_some_and(|parent| parent.has_tag_name((XMLENC_NS, "EncryptedData")))
            })
            .expect("outer KeyInfo");
        assert_eq!(
            direct_child_element(outer_key_info, XMLDSIG_NS, "KeyName")
                .and_then(|node| node.text()),
            Some("outer")
        );
        let encrypted_key = direct_child_element(outer_key_info, XMLENC_NS, "EncryptedKey")
            .expect("generated recipient");
        let recipient_key_info =
            direct_child_element(encrypted_key, XMLDSIG_NS, "KeyInfo").expect("recipient KeyInfo");
        assert_eq!(
            direct_child_element(recipient_key_info, XMLDSIG_NS, "KeyName")
                .and_then(|node| node.text()),
            Some("recipient")
        );
        let values = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLENC_NS, "CipherValue")))
            .filter_map(|node| node.text())
            .collect::<Vec<_>>();
        assert_eq!(values, ["a2V5", "ZGF0YQ=="]);
    }

    #[test]
    fn merged_encryption_template_obeys_the_aggregate_node_ceiling() {
        // Template and generated output cross the trust boundary separately,
        // but the returned document must also fit the same operation policy.
        let extras = "<extra/>".repeat(24);
        let template = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\">{extras}<e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
        );
        let generated = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
        );
        let individual_node_ceiling = [template.as_str(), generated.as_str()]
            .into_iter()
            .map(|xml| Document::parse(xml).unwrap().descendants().count())
            .max()
            .unwrap();
        let policy = EncryptionPolicy {
            resources: xml_sec::policy::ResourcePolicy {
                max_xml_nodes: individual_node_ceiling,
                ..xml_sec::policy::ResourcePolicy::default()
            },
            ..EncryptionPolicy::default()
        };

        let error = apply_encryption_template(&template, &generated, None, &[], &policy)
            .expect_err("the aggregate merged document must be reparsed under policy");
        assert!(error.to_string().contains("nodes limit"), "{error}");
    }

    #[test]
    fn merged_encryption_template_checks_bytes_before_reparsing() {
        // Both inputs fit independently, but adding generated recipient data to
        // the padded template crosses the document ceiling before a merged DOM
        // may be allocated.
        let padding = "x".repeat(256);
        let template = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" padding=\"{padding}\"><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
        );
        let generated = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
        );
        let maximum = template.len().max(generated.len());
        let policy = EncryptionPolicy {
            resources: xml_sec::policy::ResourcePolicy {
                max_xml_document_bytes: maximum,
                ..xml_sec::policy::ResourcePolicy::default()
            },
            ..EncryptionPolicy::default()
        };

        let error = apply_encryption_template(&template, &generated, None, &[], &policy)
            .expect_err("merged output must be bounded before reparsing");
        assert!(
            matches!(&error, CommandError::Encryption(message) if message.contains("encrypted template output exceeds XML document policy")),
            "{error}"
        );
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
    fn encryption_template_inspection_enforces_the_xml_node_ceiling() {
        // CLI metadata discovery runs before the core builder, so it must reject
        // over-budget templates instead of constructing an unrestricted DOM.
        let mut xml = format!(
            "<EncryptedData xmlns=\"{XMLENC_NS}\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><CipherData><CipherValue/></CipherData>"
        );
        for _ in 0..100_000 {
            xml.push_str("<Extension/>");
        }
        xml.push_str("</EncryptedData>");

        let error = match encryption_template(&xml, None, &[], &EncryptionPolicy::default()) {
            Ok(_) => panic!("over-budget template must fail"),
            Err(error) => error,
        };
        assert!(
            matches!(&error, CommandError::Encryption(message) if message.contains("nodes limit")),
            "expected the parser node ceiling, got: {error}"
        );
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

    #[test]
    fn configured_certificates_are_deduplicated_and_aggregate_bounded() {
        // Repeated CLI options must not multiply retained DER, while distinct
        // trust material must be rejected before crossing the compiled total.
        let mut certificates = Vec::new();
        let mut budget = CertificateBudget::new(5);
        push_configured_certificate(&mut certificates, vec![1, 2], 2, &mut budget).unwrap();
        push_configured_certificate(&mut certificates, vec![1, 2], 2, &mut budget).unwrap();
        assert_eq!(certificates, [vec![1, 2]]);
        assert_eq!(budget.total_bytes, 4);

        assert!(matches!(
            push_configured_certificate(&mut certificates, vec![3, 4], 2, &mut budget),
            Err(CommandError::CertificateMaterialTooLarge { maximum: 5 })
        ));
        assert_eq!(certificates, [vec![1, 2]]);
        assert_eq!(budget.total_bytes, 4);

        assert!(matches!(
            budget.charge(2),
            Err(CommandError::CertificateMaterialTooLarge { maximum: 5 })
        ));
        assert_eq!(budget.total_bytes, 4);
    }

    #[test]
    fn duplicate_configured_certificate_sources_consume_aggregate_budget() {
        // Deduplicating retained DER must not make repeated external file reads
        // free: every explicitly supplied source consumes invocation work.
        let certificate = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let source_len = fs::read(&certificate).unwrap().len();
        let invocation = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("verify"),
            OsString::from("--trusted-pem"),
            certificate.as_os_str().to_owned(),
            OsString::from("--trusted-pem"),
            certificate.as_os_str().to_owned(),
            OsString::from("signed.xml"),
        ])
        .unwrap();
        let mut budget = CertificateBudget::new(source_len);

        assert!(matches!(
            load_configured_certificates(&invocation, false, &mut budget),
            Err(CommandError::CertificateMaterialTooLarge { maximum }) if maximum == source_len
        ));
    }

    #[test]
    fn recipient_certificate_loader_charges_the_invocation_budget() {
        // Recipient certificates are external inputs even when used only to
        // extract an RSA wrapping key, so they share the operation-wide budget.
        let certificate = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let mut budget = CertificateBudget::new(1);

        let error = load_rsa_recipient_candidate(
            certificate.as_os_str(),
            RecipientPublicKeySource::Certificate(key_material::CertificateEncoding::Pem),
            &EncryptionPolicy::default(),
            &mut budget,
        )
        .expect_err("certificate DER must exceed the one-byte aggregate budget");

        assert!(matches!(
            error,
            CommandError::CertificateMaterialTooLarge { maximum: 1 }
        ));
    }

    #[test]
    fn recipient_certificate_cache_reuses_one_budget_charge() {
        // Repeated recipient selection may reuse one CLI option, but external
        // certificate bytes belong to the invocation and are charged once.
        let certificate = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let der = key_material::load_certificate(
            certificate.as_os_str(),
            key_material::CertificateEncoding::Pem,
        )
        .unwrap();
        let invocation = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("encrypt"),
            OsString::from("--pubkey-cert-pem"),
            certificate.as_os_str().to_owned(),
            OsString::from("--binary-data"),
            OsString::from("payload.bin"),
            OsString::from("template.xml"),
        ])
        .unwrap();
        let option = invocation.values("pubkey-cert-pem").next().unwrap();
        let mut cache = HashMap::new();
        let mut budget = CertificateBudget::new(der.len());

        cached_rsa_recipient_candidate(
            &mut cache,
            option,
            true,
            &EncryptionPolicy::default(),
            &mut budget,
        )
        .unwrap();
        cached_rsa_recipient_candidate(
            &mut cache,
            option,
            true,
            &EncryptionPolicy::default(),
            &mut budget,
        )
        .expect("cached selection must not charge the certificate twice");
    }

    #[test]
    fn xml_content_serialization_enforces_the_plaintext_limit_while_rendering() {
        // Inherited namespaces can expand every serialized child. The Content
        // path must stop at the operation budget rather than constructing the
        // complete expanded plaintext before the builder checks its length.
        let xml = r#"<root xmlns:a="urn:one" xmlns:b="urn:two"><a:item/><b:item/></root>"#;
        let policy = EncryptionPolicy {
            resources: xml_sec::policy::ResourcePolicy {
                max_encryption_plaintext_bytes: 32,
                ..xml_sec::policy::ResourcePolicy::default()
            },
            ..EncryptionPolicy::default()
        };

        assert!(matches!(
            xml_data_plaintext(xml, &EncryptedDataType::Content, &policy),
            Err(CommandError::PlaintextTooLarge { maximum: 32 })
        ));
    }

    #[test]
    fn verification_diagnostics_aggregate_manifest_failures() {
        // libxmlsec1 reports the operation as failed when a processed Manifest
        // reference fails, even though the core SignatureValue remains valid.
        let aggregate = aggregate_statuses(
            DsigStatus::Valid,
            [DsigStatus::Invalid(
                FailureReason::ReferenceDigestMismatch { ref_index: 0 },
            )],
        );

        assert_eq!(donor_dsig_status(aggregate), ("FAILED", "REFERENCE"));
    }
}
