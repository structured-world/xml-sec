use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use rsa::{
    RsaPublicKey,
    pkcs8::{DecodePublicKey as _, EncodePublicKey as _},
    traits::PublicKeyParts as _,
};
use x509_parser::prelude::FromDer as _;
use xml_sec::xml_input as xml_sec_xml_input;
use xml_sec::{
    IdAttributeRegistration, XmlBackend,
    key_manager::{self, KeyInventory, SymmetricKeyKind},
    policy::{
        DecryptionPolicy, EcdsaSignatureValueEncoding, EncryptionPolicy, HmacPolicy,
        ManifestProcessing, ResourcePolicy, SameDocumentIdSemantics, SigningPolicy,
        TransformPolicy, UriPolicy, VerificationPolicy, XmlInputPolicy,
    },
    provider::{CryptoProvider, default_provider},
    xmldsig::{
        DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus, FailureReason, HmacSigningKey,
        HmacVerificationKey, InspectedKeyCandidateBudget, KeyInfo, KeyInfoSource, KeyInfoWriter,
        KeyResolver, KeyResolverConfig, KeyValueInfo, ReferenceResult, SignContext,
        SignatureAlgorithm, SignatureTemplateSelection, SigningKey, SigningPublicKeyInfo,
        UriTypeSet, VerificationKey, VerifyContext, VerifyResult, VerifyingKey,
        X509CertificateKeyInfoWriter, XPathHereSemantics, parse_key_info,
        uri::UriReferenceResolver, validate_signing_key, x509_certificate_matches_selectors,
    },
    xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DecryptionKeyResolver,
        EncryptedDataBuilder, EncryptedDataType, EncryptedKey, EncryptionMethod,
        EncryptionRecipient, KekDecryptor, KeyCandidateBudget, KeyTransportAlgorithm,
        KeyWrapAlgorithm, OaepDigestAlgorithm, PrivateKeyDecryptor, RsaOaepParameters, XmlEncError,
        parse_encrypted_data_template_node_with_policy_and_backend, validate_rsa_recipient_key,
    },
};
use xml_sec::{
    XmlDomDocument as Document, XmlDomNode as Node, XmlDomParsingOptions as ParsingOptions,
};
use xml_sec_xml_input::lexical::{escape_attribute, escape_text};

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
    "help",
];
const SIGN_OPTIONS: &[&str] = &[
    "xml-backend",
    "print-debug",
    "print-xml-debug",
    "output",
    "ignore-manifests",
    "privkey-pem",
    "privkey-der",
    "pkcs8-pem",
    "pkcs8-der",
    "pkcs12",
    "hmac-key",
    "keys-file",
    "pwd",
    "lax-key-search",
    "node-id",
    "node-name",
    "node-xpath",
    "id-attr",
    "add-id-attr",
    "enable-visa3d-hack",
    "enable-asn1-signatures-hack",
];
const VERIFY_OPTIONS: &[&str] = &[
    "xml-backend",
    "print-debug",
    "print-xml-debug",
    "pubkey-pem",
    "pubkey-der",
    "pubkey-cert-pem",
    "pubkey-cert-der",
    "hmac-key",
    "keys-file",
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
    "enable-visa3d-hack",
    "enable-asn1-signatures-hack",
];
const ENCRYPT_OPTIONS: &[&str] = &[
    #[cfg(feature = "legacy-algorithms")]
    "des-key",
    "xml-backend",
    "print-debug",
    "print-xml-debug",
    "output",
    "binary-data",
    "xml-data",
    "aes-key",
    "keys-file",
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
    #[cfg(feature = "legacy-algorithms")]
    "des-key",
    "xml-backend",
    "print-debug",
    "print-xml-debug",
    "output",
    "aes-key",
    "keys-file",
    "privkey-pem",
    "privkey-der",
    "pkcs8-pem",
    "pkcs8-der",
    "pkcs12",
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
    #[error("option --{option} is recognized but is not applicable to the {command} command")]
    InapplicableOption { option: String, command: Command },
    #[error("unsupported crypto provider: {0}")]
    UnsupportedProvider(String),
    #[error("unsupported XML backend: {0}; expected xmloxide, roxmltree, or differential")]
    UnsupportedXmlBackend(String),
    #[error("XML backend {0} is not compiled into this binary")]
    UnavailableXmlBackend(String),
    #[error("I/O error for {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("input XML exceeds policy limit of {maximum} bytes")]
    InputTooLarge { maximum: usize },
    #[error("invalid XML byte encoding: {0}")]
    InvalidXmlEncoding(String),
    #[error("encryption plaintext exceeds policy limit of {maximum} bytes")]
    PlaintextTooLarge { maximum: usize },
    #[error("configured external key/certificate material exceeds policy limit of {maximum} bytes")]
    ExternalMaterialTooLarge { maximum: usize },
    #[error(transparent)]
    Key(#[from] key_material::KeyMaterialError),
    #[error(transparent)]
    KeyStore(#[from] key_manager::KeyStoreError),
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
        Command::Version => writeln!(
            stdout,
            "xmlsec1 1.3.13 ({})",
            selected_provider(&invocation)?.name()
        )
        .map_err(stdout_error),
        Command::ListTransforms => {
            validate_options(&invocation, &[])?;
            let provider = selected_provider(&invocation)?;
            capabilities::list_available(
                "transform klasses",
                TRANSFORMS,
                |name| capabilities::transform_available(name, provider),
                stdout,
            )
            .map_err(stdout_error)
        }
        Command::CheckTransforms => {
            validate_options(&invocation, &[])?;
            let provider = selected_provider(&invocation)?;
            if capabilities::all_requested_available_where(
                TRANSFORMS,
                &invocation.positional,
                |name| capabilities::transform_available(name, provider),
            ) {
                Ok(())
            } else {
                Err(CommandError::CapabilityUnavailable)
            }
        }
        Command::ListKeyData => {
            validate_options(&invocation, &[])?;
            let provider = selected_provider(&invocation)?;
            capabilities::list_available(
                "key data klasses",
                KEY_DATA,
                |name| capabilities::key_data_available(name, provider),
                stdout,
            )
            .map_err(stdout_error)
        }
        Command::CheckKeyData => {
            validate_options(&invocation, &[])?;
            let provider = selected_provider(&invocation)?;
            if capabilities::all_requested_available_where(
                KEY_DATA,
                &invocation.positional,
                |name| capabilities::key_data_available(name, provider),
            ) {
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
    selected_provider(invocation)?;
    Ok(())
}

fn selected_provider(invocation: &Invocation) -> Result<&'static dyn CryptoProvider, CommandError> {
    match option_text(invocation, "crypto")?.unwrap_or("default") {
        "rustcrypto" | "default" => Ok(default_provider()),
        #[cfg(feature = "aws-lc-fips")]
        "aws-lc-fips" => Ok(&xml_sec::provider::AwsLcFipsProvider),
        name => Err(CommandError::UnsupportedProvider(name.to_owned())),
    }
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

fn selected_xml_backend(invocation: &Invocation) -> Result<XmlBackend, CommandError> {
    let Some(name) = option_text(invocation, "xml-backend")? else {
        return Ok(XmlBackend::default());
    };
    let backend = match name {
        "xmloxide" => XmlBackend::Xmloxide,
        "roxmltree" => XmlBackend::Roxmltree,
        "differential" => XmlBackend::Differential,
        _ => return Err(CommandError::UnsupportedXmlBackend(name.to_owned())),
    };
    if backend.is_available() {
        Ok(backend)
    } else {
        Err(CommandError::UnavailableXmlBackend(name.to_owned()))
    }
}

fn validate_options(invocation: &Invocation, command_options: &[&str]) -> Result<(), CommandError> {
    // Parsing establishes that every option name is known. Command validation
    // must therefore report a recognized-but-inapplicable option semantically,
    // naming both the option and command; never collapse this case into a
    // generic syntax, usage, or unknown-option error.
    for name in invocation.options.keys() {
        if !GENERIC_OPTIONS.contains(&name.as_str()) && !command_options.contains(&name.as_str()) {
            return Err(CommandError::InapplicableOption {
                option: name.clone(),
                command: invocation.command,
            });
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
    xml_sec::encoding::decode_xml_octets(&bytes, maximum)
        .map(Cow::into_owned)
        .map_err(map_xml_decode_error)
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
    let bytes = read_bounded_file(path, maximum, |maximum| CommandError::InputTooLarge {
        maximum,
    })?;
    xml_sec::encoding::decode_xml_octets(&bytes, maximum)
        .map(Cow::into_owned)
        .map_err(map_xml_decode_error)
}

fn map_xml_decode_error(error: xml_sec::encoding::XmlEncodingError) -> CommandError {
    match error {
        xml_sec::encoding::XmlEncodingError::DecodedLimit { maximum, .. } => {
            CommandError::InputTooLarge { maximum }
        }
        error => CommandError::InvalidXmlEncoding(error.to_string()),
    }
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

fn load_xml_key_stores<P: xml_sec::document::XmlDocumentPolicy>(
    invocation: &Invocation,
    policy: &P,
    backend: XmlBackend,
    budget: &mut ExternalMaterialBudget,
) -> Result<KeyInventory, CommandError> {
    let mut importer =
        key_manager::XmlKeyStoreImporter::with_live_material(policy, backend, budget.total_bytes)?;
    for option in invocation.values("keys-file") {
        let path = Path::new(option.value.as_deref().unwrap_or_default());
        let bytes = read_key_material_with_budget(path, budget)?;
        importer.import(&bytes)?;
    }
    Ok(importer.finish())
}

fn select_store_candidates<'a, T>(
    entries: impl Iterator<Item = &'a T>,
    requested_names: &[String],
    lax: bool,
    max_candidates: usize,
    name: impl Fn(&T) -> &str,
) -> Result<Vec<&'a T>, CommandError> {
    // Policy caps candidates per stage, not the sum of selection and crypto
    // attempts. Bound this scan independently before materializing matches.
    let mut named = Vec::new();
    let mut fallback = Vec::new();
    for (inspected, entry) in entries.enumerate() {
        if inspected == max_candidates {
            return Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "key candidates",
                    maximum: max_candidates,
                    actual: inspected.saturating_add(1),
                },
            )));
        }
        if requested_names.is_empty()
            || requested_names
                .iter()
                .any(|requested| requested == name(entry))
        {
            named.push(entry);
        } else if lax {
            fallback.push(entry);
        }
    }
    if !lax && named.len() > 1 {
        return Err(CommandError::Usage(
            "multiple matching keys in --keys-file".into(),
        ));
    }
    if lax {
        named.extend(fallback);
    }
    if named.is_empty() {
        return Err(CommandError::Usage("no matching key in --keys-file".into()));
    }
    Ok(named)
}

fn sign(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, SIGN_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    let password = invocation.password_bytes();
    // This binary is an explicit libxmlsec1 compatibility boundary. Its sign
    // and verify commands must bind XPath here() identically for round trips.
    let mut policy = xmlsec_compatibility_signing_policy(invocation);
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let signature = key_material::signing_signature_metadata(
        &xml,
        start_node_id,
        &id_attributes,
        &policy,
        xml_backend,
        selected_provider(invocation)?,
    )?;
    let has_key_store = invocation.values("keys-file").next().is_some();
    if matches!(signature.algorithm, SignatureAlgorithm::RsaPss(_)) {
        // The CLI explicitly permits all implemented PSS parameter combinations;
        // the finite URI inventory cannot enumerate every exact salt/hash tuple.
        policy
            .signature_algorithms
            .as_mut()
            .expect("CLI algorithm allowlist")
            .insert(signature.algorithm);
    }
    if has_key_store
        && invocation
            .ordered_values(&[
                "hmac-key",
                "privkey-pem",
                "privkey-der",
                "pkcs8-pem",
                "pkcs8-der",
                "pkcs12",
            ])
            .next()
            .is_some()
    {
        return Err(CommandError::Usage(
            "sign cannot combine --keys-file with explicit key options".into(),
        ));
    }
    let selected = if has_key_store {
        if signature.key_names.is_empty() && !invocation.flag("lax-key-search") {
            return Err(CommandError::Usage(
                "sign with --keys-file requires a template KeyName unless --lax-key-search is set"
                    .into(),
            ));
        }
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        let store = load_xml_key_stores(invocation, &policy, xml_backend, &mut budget)?;
        let lax_candidates = invocation.flag("lax-key-search");
        let candidates = if signature.algorithm.hmac_output_bits().is_some() {
            select_store_candidates(
                store.symmetric_keys().iter().filter(|entry| {
                    entry.kind == SymmetricKeyKind::Hmac
                        && entry.usages.allows(key_manager::KeyUsage::Sign)
                }),
                &signature.key_names,
                lax_candidates,
                policy.resources.max_key_candidates,
                |entry| &entry.name,
            )?
            .into_iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>()
        } else {
            select_store_candidates(
                store
                    .private_keys()
                    .iter()
                    .filter(|entry| entry.usages.allows(key_manager::KeyUsage::Sign)),
                &signature.key_names,
                lax_candidates,
                policy.resources.max_key_candidates,
                |entry| &entry.name,
            )?
            .into_iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>()
        };
        select_store_signing_key(
            &store,
            candidates,
            signature.algorithm,
            signature.key_info.as_ref(),
            &policy,
            lax_candidates,
            selected_provider(invocation)?,
        )?
    } else {
        select_signing_key(
            invocation,
            &signature.key_names,
            signature.algorithm,
            signature.key_info.as_ref(),
            &policy,
            password,
        )?
    };
    let mut context = SignContext::new(selected.key.as_ref())
        .provider(selected_provider(invocation)?)
        .policy(policy)
        .xml_backend(xml_backend)
        .signature_template_selection(SignatureTemplateSelection::FirstDescendant);
    if let Some(id) = start_node_id {
        context = context.start_node_id(id);
    }
    context = context.id_attributes(&id_attributes);
    if let Some(writer) = &selected.certificate_writer
        && signature.key_info.is_some()
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

fn xmlsec_compatibility_signing_policy(invocation: &Invocation) -> SigningPolicy {
    // The native CLI is an explicit compatibility boundary. These complete
    // allowlists opt its sign command into every implemented libxmlsec1 method,
    // including legacy SHA-1, without weakening the core library defaults.
    let mut policy = SigningPolicy {
        signature_algorithms: Some(HashSet::from(SignatureAlgorithm::ALL)),
        digest_algorithms: Some(HashSet::from(DigestAlgorithm::ALL)),
        manifest_processing: if invocation.flag("ignore-manifests") {
            ManifestProcessing::Ignore
        } else {
            ManifestProcessing::Process
        },
        transforms: TransformPolicy {
            xpath_here_semantics: XMLSEC_COMPATIBILITY_HERE_SEMANTICS,
            same_document_id_semantics: same_document_id_semantics(invocation),
            ..TransformPolicy::default()
        },
        hmac: HmacPolicy {
            minimum_key_bits: 40,
            minimum_output_bits: 40,
        },
        ecdsa_signature_value_encoding: ecdsa_signature_value_encoding(invocation),
        ..SigningPolicy::default()
    };
    policy.dsa_keys.minimum_modulus_bits = 1024;
    policy
}

fn write_signing_diagnostics(
    invocation: &Invocation,
    algorithm: SignatureAlgorithm,
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    write_operation_diagnostics(
        invocation,
        stdout,
        algorithm.uri(),
        DiagnosticFormat {
            text_context: "Signature Context",
            text_method: "Signature Method",
            xml_context: "SignatureContext",
            xml_status: "SUCCEEDED",
            xml_method: "SignatureMethod",
        },
    )
}

struct SigningKeyCandidate {
    key: Box<dyn SigningKey>,
    certificate_writer: Option<X509CertificateKeyInfoWriter>,
    leaf_certificate_der: Option<Vec<u8>>,
}

fn select_store_signing_key<'a>(
    store: &KeyInventory,
    candidates: impl IntoIterator<Item = &'a str>,
    algorithm: SignatureAlgorithm,
    key_info: Option<&KeyInfo>,
    policy: &SigningPolicy,
    lax: bool,
    provider: &dyn CryptoProvider,
) -> Result<SigningKeyCandidate, CommandError> {
    let mut last_error = None;
    let mut lookup_budget = key_manager::SigningLookupBudget::default();
    for name in candidates {
        let attempt = store
            .signing_key_with_provider_and_budget(
                name,
                algorithm,
                policy,
                provider,
                &mut lookup_budget,
            )
            .map_err(CommandError::from)
            .and_then(|key| {
                let candidate = SigningKeyCandidate {
                    key,
                    certificate_writer: None,
                    leaf_certificate_der: None,
                };
                validate_signing_key_info(key_info, &candidate, provider)?;
                Ok(candidate)
            });
        match attempt {
            Ok(candidate) => return Ok(candidate),
            Err(error) if lax && lax_candidate_error_is_recoverable(&error) => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| CommandError::Usage("no compatible signing key".into())))
}

fn select_signing_key(
    invocation: &Invocation,
    requested_names: &[String],
    algorithm: SignatureAlgorithm,
    key_info: Option<&KeyInfo>,
    policy: &SigningPolicy,
    password: Option<&[u8]>,
) -> Result<SigningKeyCandidate, CommandError> {
    let hmac = algorithm.hmac_output_bits().is_some();
    let key_options: &[&str] = if hmac {
        &["hmac-key"]
    } else {
        &[
            "privkey-pem",
            "privkey-der",
            "pkcs8-pem",
            "pkcs8-der",
            "pkcs12",
        ]
    };
    let key_kind = if hmac { "HMAC key" } else { "private key" };
    let keys = invocation
        .ordered_values(key_options)
        .map(|key| (key, ()))
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return Err(CommandError::Usage(if hmac {
            "HMAC signing requires --hmac-key".into()
        } else {
            "sign requires --privkey-pem, --pkcs8-pem/der, or --pkcs12".into()
        }));
    }
    let candidates = named_candidate_search(
        &keys,
        requested_names,
        invocation.flag("lax-key-search"),
        false,
        key_kind,
    )?;
    KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
        .consume(candidates.len())
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    let lax_key_search = invocation.flag("lax-key-search");
    let mut last_error: Option<CommandError> = None;
    let mut material_budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    for (option, ()) in candidates {
        let attempt = prepare_signing_key_candidate(
            option,
            algorithm,
            policy,
            password,
            &mut material_budget,
            selected_provider(invocation)?,
        )
        .and_then(|candidate| {
            validate_signing_key_info(key_info, &candidate, selected_provider(invocation)?)?;
            Ok(candidate)
        });
        match attempt {
            Ok(candidate) => return Ok(candidate),
            Err(error) if lax_key_search && lax_candidate_error_is_recoverable(&error) => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(CommandError::Usage(format!(
        "no {key_kind} input supports {}",
        algorithm.uri()
    )))
}

fn prepare_signing_key_candidate(
    option: &crate::OptionValue,
    algorithm: SignatureAlgorithm,
    policy: &SigningPolicy,
    password: Option<&[u8]>,
    material_budget: &mut ExternalMaterialBudget,
    provider: &dyn CryptoProvider,
) -> Result<SigningKeyCandidate, CommandError> {
    provider
        .require_capability(xml_sec::provider::ProviderCapability::Sign(algorithm))
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    material_budget.with_key_import(&policy.resources, |budget, inventory, resources| {
        prepare_signing_key_candidate_inner(
            option,
            algorithm,
            policy,
            password,
            SigningKeyImport {
                material_budget: budget,
                inventory,
                resources,
            },
            provider,
        )
    })
}

struct SigningKeyImport<'a> {
    material_budget: &'a mut ExternalMaterialBudget,
    inventory: &'a mut KeyInventory,
    resources: &'a xml_sec::policy::ResourcePolicy,
}

fn prepare_signing_key_candidate_inner(
    option: &crate::OptionValue,
    algorithm: SignatureAlgorithm,
    policy: &SigningPolicy,
    password: Option<&[u8]>,
    import: SigningKeyImport<'_>,
    provider: &dyn CryptoProvider,
) -> Result<SigningKeyCandidate, CommandError> {
    let SigningKeyImport {
        material_budget,
        inventory,
        resources,
    } = import;
    if algorithm.hmac_output_bits().is_some() {
        let path = option.value.as_deref().unwrap_or_default();
        let key_bytes = key_material::read(path)?;
        material_budget.charge(key_bytes.len())?;
        let key = HmacSigningKey::new(key_bytes)
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        validate_signing_key(&key, algorithm, policy)
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        return Ok(SigningKeyCandidate {
            key: Box::new(key),
            certificate_writer: None,
            leaf_certificate_der: None,
        });
    }
    if option.name == "pkcs12" {
        let path = Path::new(option.value.as_deref().unwrap_or_default());
        let bytes = read_key_material_with_budget(path, material_budget)?;
        let password = password
            .and_then(|value| std::str::from_utf8(value).ok())
            .ok_or(key_manager::KeyStoreError::ProtectedContainer)?;
        let name = option.parameter.clone().unwrap_or_else(|| "pkcs12".into());
        inventory.add_pkcs12(name.clone(), &bytes, password, resources)?;
        let key = inventory.signing_key_with_provider(&name, algorithm, policy, provider)?;
        let imported = inventory
            .private_keys()
            .first()
            .ok_or_else(|| CommandError::Usage("PKCS#12 contains no usable private key".into()))?;
        let certificate_writer = imported
            .matching_certificate_chain()
            .map(X509CertificateKeyInfoWriter::from_der_chain)
            .transpose()
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        if let Some(writer) = &certificate_writer {
            writer
                .write_key_info(key.as_ref())
                .map_err(|error| CommandError::Signature(error.to_string()))?;
        }
        return Ok(SigningKeyCandidate {
            key,
            certificate_writer,
            leaf_certificate_der: imported
                .matching_certificate_chain()
                .and_then(|chain| chain.first())
                .cloned(),
        });
    }
    let (path, certificate_paths) =
        split_key_and_certificates(option.value.as_deref().unwrap_or_default())?;
    let key_bytes = key_material::read(path)?;
    material_budget.charge(key_bytes.len())?;
    let format = private_key_format(option);
    let key = if provider.name() != "rustcrypto"
        || key_material::is_encrypted_pkcs8_container(&key_bytes, format)
    {
        // All protected PKCS#8 aliases share the inventory's pre-decryption KDF gate;
        // selecting a CLI spelling must never change import policy enforcement.
        let name = option.parameter.as_deref().unwrap_or("explicit");
        import_explicit_private_key(
            inventory,
            &key_bytes,
            key_material::PrivateKeyImport {
                path: Path::new(path),
                name,
                format,
                password,
                usages: key_manager::KeyUsages::SIGN,
                resources,
            },
            material_budget,
        )?;
        inventory.signing_key_with_provider(name, algorithm, policy, provider)?
    } else {
        key_material::decode_signing_key(Path::new(path), &key_bytes, format, algorithm, password)?
    };
    validate_signing_key(key.as_ref(), algorithm, policy)
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    let (certificate_writer, leaf_certificate_der) = if certificate_paths.is_empty() {
        (None, None)
    } else {
        let certificates = load_certificate_companions(
            &certificate_paths,
            if matches!(option.name.as_str(), "privkey-der" | "pkcs8-der") {
                key_material::CertificateEncoding::Der
            } else {
                key_material::CertificateEncoding::Pem
            },
            material_budget,
        )?;
        let writer = X509CertificateKeyInfoWriter::from_der_chain(&certificates)
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        // Companion validation belongs to candidate preparation even when the
        // template has no KeyInfo output slot: the option is one key identity.
        writer
            .write_key_info(key.as_ref())
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        (Some(writer), certificates.first().cloned())
    };
    Ok(SigningKeyCandidate {
        key,
        certificate_writer,
        leaf_certificate_der,
    })
}

fn validate_signing_key_info(
    key_info: Option<&KeyInfo>,
    selected: &SigningKeyCandidate,
    provider: &dyn CryptoProvider,
) -> Result<(), CommandError> {
    let Some(key_info) = key_info else {
        return Ok(());
    };
    let public = selected
        .key
        .public_key_info()
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    for source in &key_info.sources {
        let matches = match source {
            KeyInfoSource::KeyName(_) => continue,
            KeyInfoSource::KeyValue(KeyValueInfo::Rsa { modulus, exponent }) => matches!(
                &public,
                SigningPublicKeyInfo::Rsa { modulus: expected_modulus, exponent: expected_exponent, .. }
                    if expected_modulus == modulus && expected_exponent == exponent
            ),
            KeyInfoSource::KeyValue(KeyValueInfo::Dsa { p, q, g, y }) => matches!(
                &public,
                SigningPublicKeyInfo::Dsa {
                    p: expected_p,
                    q: expected_q,
                    g: expected_g,
                    y: expected_y,
                    ..
                } if p.as_deref().is_none_or(|value| value == expected_p)
                    && q.as_deref().is_none_or(|value| value == expected_q)
                    && g.as_deref().is_none_or(|value| value == expected_g)
                    && y == expected_y
            ),
            KeyInfoSource::KeyValue(KeyValueInfo::Ec {
                curve_oid,
                public_key,
            }) => matches!(
                &public,
                SigningPublicKeyInfo::Ec { curve_oid: expected_curve, public_key: expected_key, .. }
                    if *expected_curve == curve_oid && expected_key == public_key
            ),
            KeyInfoSource::DerEncodedKeyValue(der) => public.spki_der() == Some(der),
            KeyInfoSource::X509Data(data) => {
                let has_identity = !data.certificates.is_empty()
                    || !data.subject_names.is_empty()
                    || !data.issuer_serials.is_empty()
                    || !data.skis.is_empty()
                    || !data.digests.is_empty();
                if !has_identity {
                    continue;
                }
                if let Some(index) = data
                    .certificate_chain
                    .first()
                    .copied()
                    .or_else(|| (!data.certificates.is_empty()).then_some(0))
                {
                    let certificate = data.certificates.get(index).ok_or_else(|| {
                        signing_key_info_error("X509Data certificate chain is inconsistent")
                    })?;
                    let (_, certificate) =
                        x509_parser::certificate::X509Certificate::from_der(certificate)
                            .map_err(|_| signing_key_info_error("X509Certificate is invalid"))?;
                    Some(certificate.public_key().raw) == public.spki_der()
                } else {
                    let certificate =
                        selected.leaf_certificate_der.as_deref().ok_or_else(|| {
                            signing_key_info_error(
                                "X509Data selectors require a signing certificate companion",
                            )
                        })?;
                    x509_certificate_matches_selectors(data, certificate, provider)
                        .map_err(|error| CommandError::Signature(error.to_string()))?
                }
            }
            _ => {
                return Err(signing_key_info_error(
                    "preserved KeyInfo identity cannot be matched to the selected signing key",
                ));
            }
        };
        if !matches {
            return Err(signing_key_info_error(
                "preserved KeyInfo does not match the selected signing key",
            ));
        }
    }
    Ok(())
}

fn signing_key_info_error(message: &str) -> CommandError {
    CommandError::Signature(message.into())
}

fn load_certificate_companions(
    paths: &[&OsStr],
    encoding: key_material::CertificateEncoding,
    budget: &mut ExternalMaterialBudget,
) -> Result<Vec<Vec<u8>>, CommandError> {
    paths
        .iter()
        .map(|path| load_certificate_with_budget(path, encoding, budget))
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
        digest_algorithms: Some(HashSet::from(DigestAlgorithm::ALL)),
        // The compatibility executable explicitly permits every compiled XML
        // signature method, including experimental PQ methods. Library defaults
        // remain restrictive; provider capability still gates execution.
        signature_algorithms: Some(HashSet::from(SignatureAlgorithm::ALL)),
        manifest_processing: if invocation.flag("ignore-manifests") {
            ManifestProcessing::Ignore
        } else {
            ManifestProcessing::Process
        },
        uris: UriPolicy {
            references: UriTypeSet::ALL,
            retrieval_methods: UriTypeSet::ALL,
            // CLI metadata selection has no request-scoped external resource
            // resolver, so advertise only the URI classes it can execute.
            key_info_references: UriTypeSet::SAME_DOCUMENT,
        },
        transforms: TransformPolicy {
            xpath_here_semantics: XMLSEC_COMPATIBILITY_HERE_SEMANTICS,
            same_document_id_semantics: same_document_id_semantics(invocation),
            ..TransformPolicy::default()
        },
        ecdsa_signature_value_encoding: ecdsa_signature_value_encoding(invocation),
        ..VerificationPolicy::default()
    };
    policy.key_trust.allowed_legacy_signature_algorithms = HashSet::from([
        SignatureAlgorithm::RsaSha1,
        SignatureAlgorithm::RsaPssSha1,
        SignatureAlgorithm::DsaSha1,
        SignatureAlgorithm::HmacSha1,
        SignatureAlgorithm::EcdsaSha1,
    ]);
    // A compatibility boundary opts into provider-supported certificate/CRL
    // methods independently of XML methods. This includes every valid PSS
    // salt length without constructing an artificial finite parameter list.
    policy.key_trust.certificate_signature_algorithms =
        Some(xml_sec::policy::CertificateSignatureAlgorithms::AllSupported);
    policy.key_trust.dsa_keys.minimum_modulus_bits = 1024;
    policy.hmac = HmacPolicy {
        minimum_key_bits: 40,
        minimum_output_bits: 40,
    };
    // X509Data is controlled by the signed document and therefore cannot
    // establish its own trust. Only an explicit insecure opt-out disables
    // path validation for resolver-selected certificates. libxmlsec1 makes
    // that opt-out authoritative over --verify-crls as well: CRLs are part of
    // path validation and cannot remain enabled after trust checks are bypassed.
    let insecure = invocation.flag("insecure");
    policy.key_trust.verify_x509_chains = !insecure;
    policy.key_trust.mode = if insecure {
        xml_sec::policy::VerificationTrustMode::CryptographicOnly
    } else {
        xml_sec::policy::VerificationTrustMode::RequireTrustedKey
    };
    policy.key_trust.check_crls = invocation.flag("verify-crls") && !insecure;
    // libxmlsec1's OpenSSL backend does not consume
    // XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS; only its GnuTLS/NSS
    // adapters relax backend-specific certificate checks. RustCrypto likewise
    // has no provider security-level switch: every implemented certificate
    // signature algorithm is already available to path validation. Reading the
    // flag here documents that the compatibility no-op is deliberate.
    let _skip_backend_strict_checks = invocation.flag("X509-skip-strict-checks");
    policy
}

fn same_document_id_semantics(invocation: &Invocation) -> SameDocumentIdSemantics {
    if invocation.flag("enable-visa3d-hack") {
        SameDocumentIdSemantics::XmlSecVisa3d
    } else {
        SameDocumentIdSemantics::XmlSecBarename
    }
}

fn ecdsa_signature_value_encoding(invocation: &Invocation) -> EcdsaSignatureValueEncoding {
    if invocation.flag("enable-asn1-signatures-hack") {
        EcdsaSignatureValueEncoding::XmlSecAsn1Der
    } else {
        EcdsaSignatureValueEncoding::XmlDsig
    }
}

fn verify(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, VERIFY_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    reject_unimplemented_verification_policy(invocation)?;
    let explicit_keys = invocation
        .ordered_values(&[
            "pubkey-pem",
            "pubkey-der",
            "pubkey-cert-pem",
            "pubkey-cert-der",
            "hmac-key",
        ])
        .map(|option| {
            let certificate = matches!(option.name.as_str(), "pubkey-cert-pem" | "pubkey-cert-der");
            (option, certificate)
        })
        .collect::<Vec<_>>();
    // With an explicit public key there is no key-manager search to relax.
    // Reject the flag on resolver-backed paths until its semantics exist.
    let lax_key_search = invocation.flag("lax-key-search");
    let has_key_store = invocation.values("keys-file").next().is_some();
    if has_key_store && !explicit_keys.is_empty() {
        return Err(CommandError::Usage(
            "verify cannot combine --keys-file with explicit key options".into(),
        ));
    }
    if lax_key_search && explicit_keys.is_empty() && !has_key_store {
        return Err(CommandError::UnsupportedOption("lax-key-search".into()));
    }
    let mut policy = xmlsec_compatibility_verification_policy(invocation);
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let key_name_resolution = if lax_key_search
        || (explicit_keys.is_empty() && !has_key_store)
        || matches!(explicit_keys.as_slice(), [(key, _)] if key.parameter.is_none())
    {
        key_material::VerificationKeyNameResolution::IgnoreDocumentKeyInfo
    } else {
        key_material::VerificationKeyNameResolution::ResolveDocumentKeyInfo
    };
    let signature = key_material::verification_signature_metadata(
        &xml,
        start_node_id,
        &id_attributes,
        &policy,
        key_name_resolution,
        xml_backend,
        selected_provider(invocation)?,
    )?;
    let algorithm = signature.algorithm;
    if matches!(algorithm, SignatureAlgorithm::RsaPss(_)) {
        policy
            .signature_algorithms
            .as_mut()
            .expect("CLI algorithm allowlist")
            .insert(algorithm);
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(algorithm);
    }
    let selected_keys = if explicit_keys.is_empty() {
        Vec::new()
    } else {
        named_candidate_search(
            &explicit_keys,
            &signature.key_names,
            lax_key_search,
            true,
            "verification key",
        )?
    };
    validate_verification_candidate_count(selected_keys.len(), &policy)
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    let mut certificate_budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    let configured_certificates = load_configured_certificates(
        invocation,
        selected_keys.is_empty(),
        &mut certificate_budget,
    )?;
    let stored_keys =
        load_xml_key_stores(invocation, &policy, xml_backend, &mut certificate_budget)?;
    let result = if !selected_keys.is_empty() {
        let mut candidates = Vec::with_capacity(selected_keys.len());
        let mut last_load_error = None;
        for (option, certificate) in selected_keys {
            let candidate = if option.name == "hmac-key" {
                (|| {
                    let path = Path::new(option.value.as_deref().unwrap_or_default());
                    let bytes = key_material::read(path)?;
                    certificate_budget.charge(bytes.len())?;
                    HmacVerificationKey::new(bytes)
                        .map(ExplicitVerificationCandidate::Hmac)
                        .map_err(|error| CommandError::Signature(error.to_string()))
                })()
            } else if certificate {
                load_explicit_certificate_key_info(option, &mut certificate_budget)
                    .map(ExplicitVerificationCandidate::Certificate)
            } else {
                (|| {
                    let path = Path::new(option.value.as_deref().unwrap_or_default());
                    let bytes = key_material::read(path)?;
                    certificate_budget.charge(bytes.len())?;
                    key_material::decode_verification_key(
                        path,
                        &bytes,
                        public_key_encoding(option),
                        algorithm,
                    )
                    .map_err(CommandError::from)
                    .map(ExplicitVerificationCandidate::Direct)
                })()
            };
            match candidate {
                Ok(candidate) => candidates.push(candidate),
                Err(error) if lax_key_search && lax_candidate_error_is_recoverable(&error) => {
                    last_load_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        if candidates.is_empty() {
            return Err(last_load_error.unwrap_or(CommandError::InvalidSignature));
        }
        let resolver = CandidateVerificationResolver::new(
            candidates,
            configured_certificates,
            lax_key_search,
            policy.key_trust.check_crls,
        );
        verification_context(policy, start_node_id, &id_attributes, xml_backend)
            .provider(selected_provider(invocation)?)
            .key_resolver(&resolver)
            .verify(&xml)
            .map_err(|error| CommandError::Signature(error.to_string()))?
    } else if has_key_store && algorithm.hmac_output_bits().is_some() {
        let selected = select_store_candidates(
            stored_keys.symmetric_keys().iter().filter(|entry| {
                entry.kind == SymmetricKeyKind::Hmac
                    && entry.usages.allows(key_manager::KeyUsage::Verify)
            }),
            &signature.key_names,
            lax_key_search,
            policy.resources.max_key_candidates,
            |entry| &entry.name,
        )?;
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(selected.len())
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        let candidates = selected
            .into_iter()
            .map(|entry| {
                HmacVerificationKey::new(entry.bytes.to_vec())
                    .map(ExplicitVerificationCandidate::Hmac)
                    .map_err(|error| CommandError::Signature(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let resolver = CandidateVerificationResolver::new(
            candidates,
            configured_certificates,
            lax_key_search,
            policy.key_trust.check_crls,
        );
        verification_context(policy, start_node_id, &id_attributes, xml_backend)
            .provider(selected_provider(invocation)?)
            .key_resolver(&resolver)
            .verify(&xml)
            .map_err(|error| CommandError::Signature(error.to_string()))?
    } else if has_key_store {
        let selected = select_store_candidates(
            stored_keys
                .public_keys()
                .iter()
                .filter(|entry| entry.usages.allows(key_manager::KeyUsage::Verify)),
            &signature.key_names,
            lax_key_search,
            policy.resources.max_key_candidates,
            |entry| &entry.name,
        )?;
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(selected.len())
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        let resolver = CandidateVerificationResolver::new(
            selected
                .into_iter()
                .map(|entry| ExplicitVerificationCandidate::Certificate(entry.key_info.clone()))
                .collect(),
            configured_certificates,
            lax_key_search,
            policy.key_trust.check_crls,
        );
        verification_context(policy, start_node_id, &id_attributes, xml_backend)
            .provider(selected_provider(invocation)?)
            .key_resolver(&resolver)
            .verify(&xml)
            .map_err(|error| CommandError::Signature(error.to_string()))?
    } else {
        let config = configured_certificates.into_resolver_config();
        let resolver = DefaultKeyResolver::new(config);
        verification_context(policy, start_node_id, &id_attributes, xml_backend)
            .provider(selected_provider(invocation)?)
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

struct ExternalMaterialBudget {
    total_bytes: usize,
    maximum_bytes: usize,
    kdf_work: usize,
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
    budget: &mut ExternalMaterialBudget,
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
            let certificate = load_certificate_with_budget(
                option.value.as_deref().unwrap_or_default(),
                certificate_encoding(option),
                budget,
            )?;
            push_configured_certificate(&mut certificates.lookup, certificate);
        }
    }
    for name in ["trusted-pem", "trusted-der"] {
        for option in invocation.values(name) {
            let certificate = load_certificate_with_budget(
                option.value.as_deref().unwrap_or_default(),
                certificate_encoding(option),
                budget,
            )?;
            push_configured_certificate(&mut certificates.trusted, certificate);
        }
    }
    Ok(certificates)
}

impl ExternalMaterialBudget {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            total_bytes: 0,
            maximum_bytes,
            kdf_work: 0,
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), CommandError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum_bytes)
            .ok_or(CommandError::ExternalMaterialTooLarge {
                maximum: self.maximum_bytes,
            })?;
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.maximum_bytes - self.total_bytes
    }

    fn with_key_import<T>(
        &mut self,
        resources: &xml_sec::policy::ResourcePolicy,
        import: impl FnOnce(
            &mut Self,
            &mut KeyInventory,
            &xml_sec::policy::ResourcePolicy,
        ) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        if self.kdf_work > resources.max_key_import_kdf_work {
            return Err(key_manager::KeyStoreError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: "key import KDF work",
                    maximum: resources.max_key_import_kdf_work,
                },
            )
            .into());
        }
        let mut remaining = resources.clone();
        remaining.max_key_import_kdf_work -= self.kdf_work;
        let mut inventory = KeyInventory::default();
        let result = import(self, &mut inventory, &remaining);
        // Retain actual work on every result, but release the temporary encoded
        // inventory when its native key has been extracted. No key copies linger.
        self.kdf_work += inventory.key_import_kdf_work();
        result
    }
}

fn import_explicit_private_key(
    inventory: &mut KeyInventory,
    bytes: &[u8],
    import: key_material::PrivateKeyImport<'_>,
    budget: &ExternalMaterialBudget,
) -> Result<(), CommandError> {
    // Container normalization is provider-independent. Already charged material
    // stays live; the importer may use only the remaining operation workspace.
    debug_assert!(budget.total_bytes >= bytes.len());
    let mut remaining = import.resources.clone();
    remaining.max_external_resource_total_bytes = remaining
        .max_external_resource_total_bytes
        .min(budget.maximum_bytes)
        .checked_sub(budget.total_bytes - bytes.len())
        .ok_or(CommandError::ExternalMaterialTooLarge {
            maximum: budget.maximum_bytes,
        })?;
    key_material::import_private_key(
        inventory,
        bytes,
        key_material::PrivateKeyImport {
            resources: &remaining,
            ..import
        },
    )
    .map_err(|error| match error {
        key_material::KeyMaterialError::KeyStore(error) => CommandError::KeyStore(error),
        error => CommandError::Key(error),
    })?;
    Ok(())
}

fn read_key_material_with_budget(
    path: &Path,
    budget: &mut ExternalMaterialBudget,
) -> Result<Vec<u8>, CommandError> {
    let remaining = budget.remaining();
    let bytes = key_material::read_with_limit(path, remaining).map_err(|error| {
        if remaining < key_material::KEY_MATERIAL_BYTE_CEILING
            && matches!(
                error,
                key_material::KeyMaterialError::KeyMaterialTooLarge { .. }
            )
        {
            CommandError::ExternalMaterialTooLarge {
                maximum: budget.maximum_bytes,
            }
        } else {
            error.into()
        }
    })?;
    budget.charge(bytes.len())?;
    Ok(bytes)
}

fn lax_candidate_error_is_recoverable(error: &CommandError) -> bool {
    // Lax lookup may skip an unusable candidate, not an invocation-wide
    // resource failure or a failed protected-container authentication.
    !matches!(
        error,
        CommandError::ExternalMaterialTooLarge { .. }
            | CommandError::KeyStore(key_manager::KeyStoreError::ProtectedContainer)
            | CommandError::KeyStore(key_manager::KeyStoreError::Policy(_))
            | CommandError::Key(key_material::KeyMaterialError::ProtectedContainer)
            | CommandError::Key(key_material::KeyMaterialError::PrivateKeyComponents(_))
            | CommandError::Key(key_material::KeyMaterialError::Policy(_))
    )
}

fn push_configured_certificate(certificates: &mut Vec<Vec<u8>>, certificate: Vec<u8>) {
    if certificates.iter().any(|existing| existing == &certificate) {
        return;
    }
    certificates.push(certificate);
}

fn load_certificate_with_budget(
    path: &OsStr,
    encoding: key_material::CertificateEncoding,
    budget: &mut ExternalMaterialBudget,
) -> Result<Vec<u8>, CommandError> {
    let bytes = key_material::read(path)?;
    budget.charge(bytes.len())?;
    key_material::decode_certificate(Path::new(path), &bytes, encoding).map_err(CommandError::from)
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
        writeln!(stdout, "<URI>{}</URI>", escape_text(&reference.uri)).map_err(stdout_error)?;
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
    xml_backend: XmlBackend,
) -> VerifyContext<'a> {
    let context = VerifyContext::new()
        .policy(policy)
        .xml_backend(xml_backend)
        .id_attributes(id_attributes);
    match start_node_id {
        Some(id) => context.start_node_id(id),
        None => context.first_document_signature(),
    }
}

enum ExplicitVerificationCandidate {
    Direct(VerificationKey),
    Hmac(HmacVerificationKey),
    Certificate(KeyInfo),
}

struct CandidateVerificationResolver {
    candidates: Vec<ExplicitVerificationCandidate>,
    certificate_resolver: DefaultKeyResolver,
    has_trusted_certificates: bool,
    lax_key_search: bool,
    consume_document_crls: bool,
}

impl CandidateVerificationResolver {
    fn new(
        candidates: Vec<ExplicitVerificationCandidate>,
        configured: ConfiguredCertificates,
        lax_key_search: bool,
        consume_document_crls: bool,
    ) -> Self {
        let has_trusted_certificates = !configured.trusted.is_empty();
        Self {
            candidates,
            certificate_resolver: DefaultKeyResolver::new(configured.into_resolver_config()),
            has_trusted_certificates,
            lax_key_search,
            consume_document_crls,
        }
    }
}

fn validate_verification_candidate_count(
    actual: usize,
    policy: &VerificationPolicy,
) -> Result<(), DsigError> {
    if actual > policy.key_trust.max_x509_candidate_paths {
        return Err(DsigError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "verification key candidates",
                maximum: policy.key_trust.max_x509_candidate_paths,
                actual,
            },
        ));
    }
    Ok(())
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
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &VerificationPolicy,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        validate_verification_candidate_count(self.candidates.len(), policy)?;
        policy.validate()?;
        let mut candidate_budget = InspectedKeyCandidateBudget::new(policy);
        let document_crls = key_info
            .into_iter()
            .flat_map(|info| &info.sources)
            .filter_map(|source| match source {
                KeyInfoSource::X509Data(info) => Some(info.crls.as_slice()),
                _ => None,
            })
            .flatten();
        let has_document_crls = document_crls.clone().next().is_some();
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
                    candidate_budget.charge()?;
                    Some(Box::new(key.clone()) as Box<dyn VerifyingKey>)
                }
                ExplicitVerificationCandidate::Hmac(key) => {
                    candidate_budget.charge()?;
                    Some(Box::new(key.clone()) as Box<dyn VerifyingKey>)
                }
                ExplicitVerificationCandidate::Certificate(info) => {
                    let mut candidate = Cow::Borrowed(info);
                    if has_document_crls
                        && let Some(index) = info
                            .sources
                            .iter()
                            .position(|source| matches!(source, KeyInfoSource::X509Data(_)))
                        && let KeyInfoSource::X509Data(x509) =
                            &mut candidate.to_mut().sources[index]
                    {
                        // The explicit certificate remains the sole identity
                        // source. Only revocation evidence crosses from the
                        // untrusted document KeyInfo into its candidate path.
                        x509.crls.extend(document_crls.clone().cloned());
                    }
                    match self.certificate_resolver.resolve_with_candidate_budget(
                        Some(candidate.as_ref()),
                        algorithm,
                        &certificate_policy,
                        provider,
                        &mut candidate_budget,
                    ) {
                        Ok(key) => key.map(xml_sec::xmldsig::ResolvedVerificationKey::into_key),
                        Err(error)
                            if self.lax_key_search && !matches!(error, DsigError::Policy(_)) =>
                        {
                            last_error = Some(error);
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
            };
            if let Some(key) = key {
                match key.validate_policy(policy) {
                    Ok(()) => resolved.push(key),
                    Err(error) if self.lax_key_search && !matches!(error, DsigError::Policy(_)) => {
                        last_error = Some(error)
                    }
                    Err(error) => return Err(error),
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

    fn consumes_document_key_info(&self) -> bool {
        // Explicit certificate candidates ignore document-controlled identity
        // hints, but they still consume embedded CRLs as revocation evidence.
        self.consume_document_crls
            && self
                .candidates
                .iter()
                .any(|candidate| matches!(candidate, ExplicitVerificationCandidate::Certificate(_)))
    }

    fn resolve_for_verification<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &VerificationPolicy,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<xml_sec::xmldsig::ResolvedVerificationKey<'a>>, DsigError> {
        // These candidates are explicitly supplied by the caller, never selected
        // from document-controlled identity hints. PKI checks above still apply.
        self.resolve_with_policy_and_provider(key_info, algorithm, policy, provider)
            .map(|key| key.map(xml_sec::xmldsig::ResolvedVerificationKey::CallerTrusted))
    }
}

struct CandidateVerifyingKey<'a> {
    candidates: Vec<Box<dyn VerifyingKey + 'a>>,
}

impl CandidateVerifyingKey<'_> {
    fn first_accepting(
        &self,
        mut attempt: impl FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
    ) -> Result<bool, DsigError> {
        let mut saw_mismatch = false;
        let mut last_error = None;
        for candidate in &self.candidates {
            match attempt(candidate.as_ref()) {
                Ok(true) => return Ok(true),
                Ok(false) => saw_mismatch = true,
                Err(error) => last_error = Some(error),
            }
        }
        if saw_mismatch {
            Ok(false)
        } else {
            last_error.map_or(Ok(false), Err)
        }
    }
}

impl VerifyingKey for CandidateVerifyingKey<'_> {
    fn verify_candidate_keys(
        &self,
        verify: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
    ) -> Result<Option<bool>, DsigError> {
        self.first_accepting(verify).map(Some)
    }
    fn verify_with_context(
        &self,
        algorithm: SignatureAlgorithm,
        context: &xml_sec::xmldsig::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        // Candidate selection must preserve RFC 8032 section 5 domain
        // separation; the context is authenticated SignatureMethod data.
        // https://www.rfc-editor.org/rfc/rfc8032#section-5
        self.first_accepting(|candidate| {
            candidate.verify_with_context(algorithm, context, signed_data, signature_value)
        })
    }

    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.first_accepting(|candidate| {
            candidate.validate_signature_value(algorithm, signature_value)
        })
    }

    fn validate_signature_value_with_policy(
        &self,
        policy: &VerificationPolicy,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.first_accepting(|candidate| {
            candidate.validate_signature_value_with_policy(policy, algorithm, signature_value)
        })
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.first_accepting(|candidate| candidate.verify(algorithm, signed_data, signature_value))
    }

    fn verify_with_policy(
        &self,
        policy: &VerificationPolicy,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.first_accepting(|candidate| {
            candidate.verify_with_policy(policy, algorithm, signed_data, signature_value)
        })
    }
}

fn load_explicit_certificate_key_info(
    certificate: &crate::OptionValue,
    budget: &mut ExternalMaterialBudget,
) -> Result<KeyInfo, CommandError> {
    let certificate_der = load_certificate_with_budget(
        certificate.value.as_deref().unwrap_or_default(),
        certificate_encoding(certificate),
        budget,
    )?;
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
    let provider = selected_provider(invocation)?;
    validate_options(invocation, ENCRYPT_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    let has_binary_data = invocation.last_value("binary-data").is_some();
    let has_xml_data = invocation.last_value("xml-data").is_some();
    if has_binary_data == has_xml_data {
        return Err(CommandError::Usage(
            "encrypt requires exactly one of --binary-data or --xml-data".into(),
        ));
    }
    let policy = xmlsec_compatibility_encryption_policy();
    let maximum_document_bytes = policy.resources.max_xml_document_bytes;
    let maximum_plaintext_bytes = policy.resources.max_encryption_plaintext_bytes;
    let template = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let metadata = encryption_template(
        &template,
        start_node_id,
        &id_attributes,
        &policy,
        xml_backend,
    )?;
    let algorithm = metadata.algorithm;
    let encrypted_type = metadata.encrypted_type;
    let explicit_xml_type = metadata.explicit_xml_type;
    let template_placement = metadata.placement;
    let mut builder = EncryptedDataBuilder::new(algorithm)
        .provider(match provider.name() {
            "rustcrypto" => std::sync::Arc::new(xml_sec::provider::RustCryptoProvider),
            #[cfg(feature = "aws-lc-fips")]
            "aws-lc-fips" => std::sync::Arc::new(xml_sec::provider::AwsLcFipsProvider),
            name => return Err(CommandError::UnsupportedProvider(name.to_owned())),
        })
        .policy(policy.clone())
        .xml_backend(xml_backend);
    let aes_keys = invocation
        .ordered_values(&["aes-key", "des-key"])
        .collect::<Vec<_>>();
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
    let has_key_store = invocation.values("keys-file").next().is_some();
    if has_key_store && (!aes_keys.is_empty() || !public_keys.is_empty()) {
        return Err(CommandError::Usage(
            "encrypt cannot combine --keys-file with explicit key options".into(),
        ));
    }
    if !aes_keys.is_empty() && !public_keys.is_empty() {
        return Err(CommandError::Usage(
            "encrypt cannot combine explicit AES and RSA recipient keys".into(),
        ));
    }
    if metadata
        .recipients
        .iter()
        .any(|recipient| recipient.wrap.is_some())
    {
        builder = configure_wrapping_recipients(
            builder,
            &metadata.recipients,
            invocation,
            &aes_keys,
            &policy,
            xml_backend,
        )?;
    } else if !aes_keys.is_empty() {
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
            "symmetric key",
        )?;
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(candidates.len())
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let mut material_budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        let mut selected = None;
        let mut last_error = None;
        for (option, ()) in candidates {
            if !symmetric_kind_accepts(symmetric_option_kind(&option.name), algorithm) {
                last_error = Some(CommandError::Usage(
                    "symmetric key type does not match the content encryption algorithm".into(),
                ));
                continue;
            }
            match load_symmetric_with_budget(
                option.value.as_deref().unwrap_or_default(),
                Some(algorithm.key_len()),
                &mut material_budget,
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
                .unwrap_or_else(|| CommandError::Usage("no compatible symmetric key input".into()))
        })?;
        builder = builder.direct_key(key);
        if let Some(name) = option.parameter.as_deref() {
            builder = builder.direct_key_name(name);
        }
    } else if has_key_store && !metadata.has_encrypted_key_recipient {
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        let store = load_xml_key_stores(invocation, &policy, xml_backend, &mut budget)?;
        let requested_names = metadata
            .content_key_name
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let candidates = select_store_candidates(
            store.symmetric_keys().iter().filter(|entry| {
                symmetric_kind_accepts(entry.kind, algorithm)
                    && entry.usages.allows(key_manager::KeyUsage::Encrypt)
            }),
            &requested_names,
            invocation.flag("lax-key-search"),
            policy.resources.max_key_candidates,
            |entry| &entry.name,
        )?;
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(candidates.len())
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let selected = candidates
            .into_iter()
            .find(|entry| entry.bytes.len() == algorithm.key_len())
            .ok_or_else(|| {
                CommandError::Usage("no compatible symmetric key in --keys-file".into())
            })?;
        let key =
            key_material::decode_symmetric(selected.bytes.to_vec(), Some(algorithm.key_len()))?;
        builder = builder.direct_key(key).direct_key_name(&selected.name);
    } else if has_key_store {
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        let store = load_xml_key_stores(invocation, &policy, xml_backend, &mut budget)?;
        let template_recipients = if metadata.recipients.is_empty() {
            vec![EncryptionTemplateRecipient {
                key_name: None,
                transport: None,
                wrap: None,
                oaep_parameters: None,
            }]
        } else {
            metadata.recipients
        };
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(template_recipients.len())
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let recipient_metadata = recipient_key_metadata(
            &template,
            start_node_id,
            &id_attributes,
            &policy,
            template_recipients.len(),
            xml_backend,
            selected_provider(invocation)?,
        )?;
        let mut store_candidate_budget =
            KeyCandidateBudget::with_limit(policy.resources.max_key_candidates);
        let mut available_public_keys_by_name = HashMap::new();
        let mut only_public_key = None;
        let mut public_key_count = 0;
        for entry in store
            .public_keys()
            .iter()
            .filter(|entry| entry.usages.allows(key_manager::KeyUsage::Encrypt))
        {
            public_key_count += 1;
            only_public_key = Some(entry);
            available_public_keys_by_name.insert(
                entry.name.as_str(),
                AvailableStoreRecipient {
                    entry,
                    reservations: 0,
                    loaded: None,
                },
            );
        }
        let lax = invocation.flag("lax-key-search");
        let mut reserved_slots = Vec::new();
        if lax {
            reserved_slots.reserve(template_recipients.len());
            // A stale name contradicted by recipient metadata is not an exact
            // match. Cache decoded candidates so reservation checks do not
            // repeat RSA decoding during assignment; names remain borrowed.
            for (recipient, metadata) in template_recipients.iter().zip(&recipient_metadata) {
                let mut reserved = false;
                if let Some(name) = recipient.key_name.as_deref()
                    && let Some(available) = available_public_keys_by_name.get_mut(name)
                {
                    if metadata.as_ref().is_some_and(|metadata| {
                        metadata
                            .0
                            .sources
                            .iter()
                            .any(|source| !matches!(source, KeyInfoSource::KeyName(_)))
                    }) {
                        if available.loaded.is_none() {
                            store_candidate_budget
                                .consume(1)
                                .map_err(|error| CommandError::Encryption(error.to_string()))?;
                            match load_stored_recipient_candidate(available.entry, &policy) {
                                Ok(candidate) => available.loaded = Some(candidate),
                                Err(
                                    error @ CommandError::KeyStore(
                                        key_manager::KeyStoreError::Policy(_),
                                    ),
                                ) => return Err(error),
                                Err(_) => {}
                            }
                        }
                        reserved = available.loaded.as_ref().is_some_and(|candidate| {
                            validate_recipient_key_metadata(metadata.as_ref(), candidate, provider)
                                .is_ok()
                        });
                    } else {
                        reserved = true;
                    }
                    if reserved {
                        available.reservations += 1;
                    }
                }
                reserved_slots.push(reserved);
            }
        }
        for (slot, (recipient, metadata)) in template_recipients
            .into_iter()
            .zip(recipient_metadata)
            .enumerate()
        {
            if lax
                && reserved_slots[slot]
                && let Some(name) = recipient.key_name.as_deref()
                && let Some(available) = available_public_keys_by_name.get_mut(name)
            {
                available.reservations -= 1;
            }
            let exact = match recipient.key_name.as_deref() {
                Some(name) => available_public_keys_by_name
                    .get(name)
                    .map(|available| available.entry),
                None if public_key_count == 1 => only_public_key.and_then(|entry| {
                    available_public_keys_by_name
                        .get(entry.name.as_str())
                        .filter(|available| !lax || available.reservations == 0)
                        .map(|available| available.entry)
                }),
                None if !lax && public_key_count > 1 => {
                    return Err(CommandError::Usage(
                        "multiple matching keys in --keys-file".into(),
                    ));
                }
                None => None,
            };
            if exact.is_none() && !lax {
                return Err(CommandError::Usage("no matching key in --keys-file".into()));
            }
            let fallbacks = store.public_keys().iter().filter(|entry| {
                lax && entry.usages.allows(key_manager::KeyUsage::Encrypt)
                    && !exact.is_some_and(|selected| std::ptr::eq(selected, *entry))
            });
            let mut selected = None;
            let mut last_error = None;
            for entry in exact.into_iter().chain(fallbacks) {
                if !exact.is_some_and(|selected| std::ptr::eq(selected, entry))
                    && available_public_keys_by_name
                        .get(entry.name.as_str())
                        .is_none_or(|available| available.reservations != 0)
                {
                    continue;
                }
                let cached = available_public_keys_by_name
                    .get_mut(entry.name.as_str())
                    .and_then(|available| available.loaded.take());
                // Reservation already charged decoding for a retained candidate.
                // Charge new inspections before work, not movement out of the cache.
                let candidate = match cached {
                    Some(candidate) => Ok(candidate),
                    None => {
                        store_candidate_budget
                            .consume(1)
                            .map_err(|error| CommandError::Encryption(error.to_string()))?;
                        load_stored_recipient_candidate(entry, &policy)
                    }
                }
                .and_then(|candidate| {
                    // This exact slot was checked against immutable metadata
                    // before reservation. Do not repeat its conversions.
                    if !(lax
                        && reserved_slots[slot]
                        && exact.is_some_and(|selected| std::ptr::eq(selected, entry)))
                    {
                        validate_recipient_key_metadata(
                            metadata.as_ref(),
                            &candidate,
                            selected_provider(invocation)?,
                        )?;
                    }
                    Ok(candidate)
                });
                match candidate {
                    Ok(candidate) => {
                        selected = Some((entry, candidate));
                        break;
                    }
                    Err(error @ CommandError::KeyStore(key_manager::KeyStoreError::Policy(_))) => {
                        return Err(error);
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            let (entry, candidate) = selected.ok_or_else(|| {
                last_error.unwrap_or_else(|| {
                    CommandError::Usage("no compatible RSA key in --keys-file".into())
                })
            })?;
            // Lax recipient search assigns each available entry once, as the
            // explicit-key path does. Keep store order for subsequent fallbacks.
            if lax {
                available_public_keys_by_name.remove(entry.name.as_str());
            }
            let mut configured =
                configured_template_recipient(candidate.public_key, recipient.transport)
                    .key_name(&entry.name);
            if let Some(parameters) = recipient.oaep_parameters {
                configured = configured.oaep_parameters(parameters);
            }
            builder = builder.add_recipient(configured);
        }
    } else if !public_keys.is_empty() {
        let template_recipients = if metadata.recipients.is_empty() {
            vec![EncryptionTemplateRecipient {
                key_name: None,
                transport: None,
                wrap: None,
                oaep_parameters: None,
            }]
        } else {
            metadata.recipients
        };
        let lax_key_search = invocation.flag("lax-key-search");
        let mut available_public_keys = public_keys.clone();
        if lax_key_search {
            KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
                .consume(available_public_keys.len())
                .map_err(|error| CommandError::Encryption(error.to_string()))?;
        }
        let mut loaded_public_keys = HashMap::new();
        let mut certificate_budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        let mut selected_recipients = Vec::with_capacity(template_recipients.len());
        let recipient_metadata = recipient_key_metadata(
            &template,
            start_node_id,
            &id_attributes,
            &policy,
            template_recipients.len(),
            xml_backend,
            selected_provider(invocation)?,
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
                    validate_recipient_key_metadata(
                        metadata.as_ref(),
                        &key,
                        selected_provider(invocation)?,
                    )?;
                    Ok(key)
                }) {
                    Ok(key) => {
                        selected = Some((option, certificate, key.public_key));
                        break;
                    }
                    Err(error @ CommandError::ExternalMaterialTooLarge { .. }) => {
                        return Err(error);
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
            selected_recipients.push((
                public_key,
                template_recipient.transport,
                template_recipient.oaep_parameters,
                key_name,
            ));
        }
        for (public_key, transport, parameters, key_name) in selected_recipients {
            let mut recipient = configured_template_recipient(public_key, transport);
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
        let plaintext = xml_data_plaintext(&data, &encrypted_type, &policy, xml_backend)?;
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
        xml_backend,
    )?;
    write_result_then_stdout_diagnostics(invocation, rendered.as_bytes(), stdout, |stdout| {
        write_encryption_diagnostics(invocation, algorithm, stdout)
    })
}

fn load_symmetric_with_budget(
    path: &OsStr,
    expected: Option<usize>,
    budget: &mut ExternalMaterialBudget,
) -> Result<Vec<u8>, CommandError> {
    let bytes = key_material::read_symmetric(path, expected)?;
    budget.charge(bytes.len())?;
    key_material::decode_symmetric(bytes, expected).map_err(CommandError::from)
}

fn xml_data_plaintext<'a>(
    xml: &'a str,
    encrypted_type: &EncryptedDataType,
    policy: &EncryptionPolicy,
    xml_backend: XmlBackend,
) -> Result<Cow<'a, str>, CommandError> {
    // libxmlsec1 parses --xml-data into a document and passes its root node to
    // xmlSecEncCtxXmlEncrypt. Element serializes that node; Content serializes
    // only its children. The document declaration and boundary nodes therefore
    // never become encrypted replacement plaintext.
    let document = parse_encryption_document(xml, &policy.xml, &policy.resources, xml_backend)?;
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
    node: Node<'_, '_>,
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
    write_operation_diagnostics(
        invocation,
        stdout,
        algorithm.uri(),
        DiagnosticFormat {
            text_context: "Data Encryption Context",
            text_method: "Encryption Method",
            xml_context: "DataEncryptionContext",
            xml_status: "replaced",
            xml_method: "EncryptionMethod",
        },
    )
}

#[derive(Clone, Copy)]
struct DiagnosticFormat {
    text_context: &'static str,
    text_method: &'static str,
    xml_context: &'static str,
    xml_status: &'static str,
    xml_method: &'static str,
}

fn write_operation_diagnostics(
    invocation: &Invocation,
    stdout: &mut dyn Write,
    algorithm_uri: &str,
    format: DiagnosticFormat,
) -> Result<(), CommandError> {
    if invocation.flag("print-debug") {
        writeln!(stdout, "== {}", format.text_context).map_err(stdout_error)?;
        writeln!(stdout, "Status: succeeded").map_err(stdout_error)?;
        writeln!(stdout, "{}: {}", format.text_method, algorithm_uri).map_err(stdout_error)?;
    }
    if invocation.flag("print-xml-debug") {
        writeln!(
            stdout,
            "<{} status=\"{}\" failureReason=\"UNKNOWN\">",
            format.xml_context, format.xml_status
        )
        .map_err(stdout_error)?;
        write_debug_transform(stdout, format.xml_method, algorithm_uri)?;
        writeln!(stdout, "</{}>", format.xml_context).map_err(stdout_error)?;
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
        escape_attribute(name),
        escape_attribute(uri)
    )
    .map_err(stdout_error)?;
    writeln!(stdout, "</{container}>").map_err(stdout_error)
}

#[derive(Clone, Debug)]
struct RecipientPublicKeyCandidate {
    public_key: RsaPublicKey,
    certificate_der: Option<Vec<u8>>,
}

struct AvailableStoreRecipient<'a> {
    entry: &'a key_manager::StoredPublicKey,
    reservations: usize,
    loaded: Option<RecipientPublicKeyCandidate>,
}

fn load_stored_recipient_candidate(
    entry: &key_manager::StoredPublicKey,
    policy: &EncryptionPolicy,
) -> Result<RecipientPublicKeyCandidate, CommandError> {
    let public_key = entry.rsa_encryption_key(policy)?;
    validate_rsa_recipient_key(&public_key, policy)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    Ok(RecipientPublicKeyCandidate {
        public_key,
        certificate_der: None,
    })
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
    certificate_budget: &mut ExternalMaterialBudget,
) -> Result<RecipientPublicKeyCandidate, CommandError> {
    let candidate = match source {
        RecipientPublicKeySource::Public(encoding) => RecipientPublicKeyCandidate {
            public_key: {
                let bytes = key_material::read(path)?;
                certificate_budget.charge(bytes.len())?;
                key_material::decode_rsa_public(Path::new(path), &bytes, encoding)?
            },
            certificate_der: None,
        },
        RecipientPublicKeySource::Certificate(encoding) => {
            let bytes = key_material::read(path)?;
            certificate_budget.charge(bytes.len())?;
            let (public_key, certificate_der) =
                key_material::decode_rsa_certificate_public(Path::new(path), &bytes, encoding)?;
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
    certificate_budget: &mut ExternalMaterialBudget,
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
    xml_backend: XmlBackend,
    provider: &dyn CryptoProvider,
) -> Result<Vec<Option<ParsedRecipientKeyMetadata>>, CommandError> {
    let document =
        parse_encryption_document(template, &policy.xml, &policy.resources, xml_backend)?;
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

    let mut parsing = xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&policy.resources)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    encrypted_keys
        .into_iter()
        .map(|encrypted_key| {
            direct_child_element(encrypted_key, XMLDSIG_NS, "KeyInfo")
                .map(|node| {
                    parsing
                        .parse_with_provider(node, provider)
                        .map(ParsedRecipientKeyMetadata)
                })
                .transpose()
                .map_err(|error| CommandError::Encryption(error.to_string()))
        })
        .collect()
}

fn validate_recipient_key_metadata(
    metadata: Option<&ParsedRecipientKeyMetadata>,
    selected_key: &RecipientPublicKeyCandidate,
    provider: &dyn CryptoProvider,
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
                        x509_certificate_matches_selectors(data, certificate, provider)
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
    #[cfg(feature = "legacy-algorithms")]
    if transport == KeyTransportAlgorithm::RsaPkcs1v15 {
        return Ok(None);
    }
    let digest = oaep_digest_from_uri(
        method
            .oaep_digest
            .as_deref()
            .unwrap_or(OaepDigestAlgorithm::Sha1.uri()),
    )?;
    // Both OAEP URIs default an absent MGF child to MGF1-SHA1. libxmlsec1
    // also accepts an explicit XMLEnc 1.1 MGF child under the legacy URI, so
    // template execution must consume the same metadata it preserves.
    let mgf_digest = oaep_mgf_from_uri(
        method
            .mgf_algorithm
            .as_deref()
            .unwrap_or(OaepDigestAlgorithm::Sha1.mgf_uri()),
    )?;
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

fn same_direct_simple_text(
    left: Node<'_, '_>,
    right: Node<'_, '_>,
    field: &str,
) -> Result<bool, CommandError> {
    if left.children().any(|child| child.is_element())
        || right.children().any(|child| child.is_element())
    {
        return Err(CommandError::Encryption(format!(
            "{field} must not contain element children"
        )));
    }
    let left_bytes = left
        .children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .flat_map(str::bytes);
    let right_bytes = right
        .children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .flat_map(str::bytes);
    Ok(left_bytes.eq(right_bytes))
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
    xml_backend: XmlBackend,
) -> Result<String, CommandError> {
    let template_document =
        parse_encryption_document(template, &policy.xml, &policy.resources, xml_backend)?;
    let generated_document =
        parse_encryption_document(generated, &policy.xml, &policy.resources, xml_backend)?;
    let template_data = select_encrypted_data(&template_document, start_node_id, id_attributes)?;
    let generated_data = generated_document.root_element();
    let template_cipher = required_cipher_value(template_data, "template EncryptedData")?;
    let generated_cipher = required_cipher_value(generated_data, "generated EncryptedData")?;
    let mut replacements = vec![replace_element_text(
        template,
        template_cipher,
        generated_cipher.text().unwrap_or_default(),
    )?];
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
            format!(" Type=\"{}\"", escape_attribute(generated_type)),
        ));
    }

    let template_key_info = direct_child_element(template_data, XMLDSIG_NS, "KeyInfo");
    let generated_key_info = direct_child_element(generated_data, XMLDSIG_NS, "KeyInfo");
    match (template_key_info, generated_key_info) {
        (Some(template_key_info), Some(generated_key_info)) => {
            if let (Some(template_name), Some(generated_name)) = (
                direct_child_element(template_key_info, XMLDSIG_NS, "KeyName"),
                direct_child_element(generated_key_info, XMLDSIG_NS, "KeyName"),
            ) && !same_direct_simple_text(template_name, generated_name, "KeyName")?
            {
                replacements.push(replace_element_text(
                    template,
                    template_name,
                    &escape_text(generated_name.text().unwrap_or_default()),
                )?);
            }
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
                    for (template_value, generated_value) in
                        template_values.into_iter().zip(generated_values)
                    {
                        replacements.push(replace_element_text(
                            template,
                            template_value,
                            generated_value.text().unwrap_or_default(),
                        )?);
                    }
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
    parse_encryption_document(&output, &policy.xml, &policy.resources, xml_backend)?;
    Ok(output)
}

fn append_element_children_replacement(
    source: &str,
    node: Node<'_, '_>,
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
        if let Some(template_key_name) =
            direct_child_element(template_key_info, XMLDSIG_NS, "KeyName")
        {
            if same_direct_simple_text(template_key_name, generated_key_name, "KeyName")? {
                return Ok(None);
            }
            return Ok(Some((template_key_name.range(), key_name)));
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

fn replace_element_text(
    source: &str,
    node: Node<'_, '_>,
    text: &str,
) -> Result<(std::ops::Range<usize>, String), CommandError> {
    let range = node.range();
    let fragment = &source[range.clone()];
    let opening_end = opening_tag_end(fragment)
        .ok_or_else(|| CommandError::Encryption("template CipherValue is malformed".into()))?;
    if fragment[..opening_end].trim_end().ends_with('/') {
        let slash = fragment[..opening_end]
            .rfind('/')
            .ok_or_else(|| CommandError::Encryption("template CipherValue is malformed".into()))?;
        let name_end = fragment[1..]
            .find(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '/' | '>'))
            .map(|offset| offset + 1)
            .ok_or_else(|| CommandError::Encryption("template CipherValue is malformed".into()))?;
        let qualified_name = &fragment[1..name_end];
        return Ok((
            range.start + slash..range.start + opening_end + 1,
            format!(">{text}</{qualified_name}>"),
        ));
    }
    let closing = fragment
        .rfind("</")
        .ok_or_else(|| CommandError::Encryption("template CipherValue is malformed".into()))?;
    Ok((
        range.start + opening_end + 1..range.start + closing,
        text.into(),
    ))
}

fn standalone_element(source: &str, node: Node<'_, '_>) -> Result<String, CommandError> {
    let mut output = String::new();
    append_standalone_element(&mut output, source, node, usize::MAX)?;
    Ok(output)
}

fn append_standalone_element(
    output: &mut String,
    source: &str,
    node: Node<'_, '_>,
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
            push_plaintext(output, &escape_attribute(namespace.uri()), maximum)?;
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

fn owned_namespace_declarations(
    opening: &str,
) -> Result<xml_sec_xml_input::lexical::DeclaredNamespacePrefixes, CommandError> {
    xml_sec_xml_input::lexical::declared_namespace_prefixes(opening)
        .map_err(|error| CommandError::Encryption(error.to_string()))
}

fn direct_child_element<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|child| child.has_tag_name((namespace, name)))
}

fn required_cipher_value<'a, 'input>(
    parent: Node<'a, 'input>,
    owner: &str,
) -> Result<Node<'a, 'input>, CommandError> {
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
    key_info: Node<'a, 'input>,
    owner: &str,
) -> Result<Vec<Node<'a, 'input>>, CommandError> {
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

fn direct_encrypted_keys<'a, 'input>(key_info: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    key_info
        .children()
        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .collect()
}

fn decrypt(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, DECRYPT_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    let password = invocation.password_bytes();
    let policy = xmlsec_compatibility_decryption_policy();
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let encrypted_data_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let document = parse_encryption_document(&xml, &policy.xml, &policy.resources, xml_backend)?;
    let encrypted_data = select_encrypted_data(&document, encrypted_data_id, &id_attributes)?;
    let standalone = encrypted_data == document.root_element();
    let content_key_name = encrypted_data_key_name(encrypted_data)?;
    let recipient_key_names = encrypted_key_recipient_names(encrypted_data)?;
    let has_wrap_recipients = encrypted_data
        .children()
        .filter(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .flat_map(|node| node.children())
        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .any(|node| {
            node.children()
                .filter(|child| child.has_tag_name((XMLENC_NS, "EncryptionMethod")))
                .any(|method| {
                    method
                        .attribute("Algorithm")
                        .is_some_and(|uri| KeyWrapAlgorithm::from_uri(uri).is_ok())
                })
        });
    let requested_symmetric_names = content_key_name
        .iter()
        .chain(
            recipient_key_names
                .iter()
                .flatten()
                .filter(|_| has_wrap_recipients),
        )
        .cloned()
        .collect::<Vec<_>>();
    let aes_keys = invocation
        .ordered_values(&["aes-key", "des-key"])
        .collect::<Vec<_>>();
    let private_keys = invocation
        .ordered_values(&[
            "privkey-pem",
            "privkey-der",
            "pkcs8-pem",
            "pkcs8-der",
            "pkcs12",
        ])
        .collect::<Vec<_>>();
    let has_key_store = invocation.values("keys-file").next().is_some();
    if has_key_store && (!aes_keys.is_empty() || !private_keys.is_empty()) {
        return Err(CommandError::Usage(
            "decrypt cannot combine --keys-file with explicit key options".into(),
        ));
    }
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
        let candidates = named_candidate_search(
            &candidates,
            &requested_symmetric_names,
            invocation.flag("lax-key-search"),
            true,
            "symmetric key",
        )?;
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(candidates.len())
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let lax_key_search = invocation.flag("lax-key-search");
        let mut keys = Vec::with_capacity(candidates.len());
        let mut last_error = None;
        for (option, ()) in candidates {
            match key_material::load_symmetric(option.value.as_deref().unwrap_or_default(), None) {
                Ok(key) => keys.push(SymmetricCandidate {
                    kind: symmetric_option_kind(&option.name),
                    bytes: Cow::Owned(key),
                    name: option.parameter.as_deref().map(Cow::Borrowed),
                }),
                Err(error) if lax_key_search => last_error = Some(CommandError::from(error)),
                Err(error) => return Err(error.into()),
            }
        }
        if keys.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                CommandError::Usage("no compatible symmetric key input".into())
            }));
        }
        decrypt_input(
            &CandidateSymmetricKeyDecryptor {
                keys,
                lax_key_search,
                content_key_name: content_key_name.as_deref(),
                wrapping_only: has_wrap_recipients && content_key_name.is_none(),
            },
            &xml,
            encrypted_data_id,
            standalone,
            policy,
            &id_attributes,
            CommandBackends {
                xml: xml_backend,
                crypto: selected_provider(invocation)?,
            },
        )?
    } else if has_key_store {
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        let store = load_xml_key_stores(invocation, &policy, xml_backend, &mut budget)?;
        if !recipient_key_names.is_empty()
            && !store.symmetric_keys().iter().any(|entry| {
                entry.kind.is_encryption_key()
                    && entry.usages.allows(key_manager::KeyUsage::Decrypt)
            })
        {
            // XMLDSig 1.1 section 4.5.2.2 defines RSAKeyValue as Modulus and
            // Exponent, not a private-key container:
            // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-RSAKeyValue
            return Err(CommandError::Usage(
                "--keys-file does not supply RSA recipient private keys for decrypt: RSAKeyValue imports are public-only; use --privkey-pem, --privkey-der, or --pkcs12".into(),
            ));
        }
        let selected = select_store_candidates(
            store.symmetric_keys().iter().filter(|entry| {
                entry.kind.is_encryption_key()
                    && entry.usages.allows(key_manager::KeyUsage::Decrypt)
            }),
            &requested_symmetric_names,
            invocation.flag("lax-key-search"),
            policy.resources.max_key_candidates,
            |entry| &entry.name,
        )?;
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(selected.len())
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let resolver = CandidateSymmetricKeyDecryptor {
            keys: selected
                .into_iter()
                .map(|entry| SymmetricCandidate {
                    kind: entry.kind,
                    bytes: Cow::Borrowed(entry.bytes.as_slice()),
                    name: Some(Cow::Borrowed(entry.name.as_str())),
                })
                .collect(),
            lax_key_search: invocation.flag("lax-key-search"),
            content_key_name: content_key_name.as_deref(),
            wrapping_only: has_wrap_recipients && content_key_name.is_none(),
        };
        decrypt_input(
            &resolver,
            &xml,
            encrypted_data_id,
            standalone,
            policy,
            &id_attributes,
            CommandBackends {
                xml: xml_backend,
                crypto: selected_provider(invocation)?,
            },
        )?
    } else if !private_keys.is_empty() {
        let selected = select_recipient_private_keys(
            &private_keys,
            &recipient_key_names,
            invocation.flag("lax-key-search"),
        )?;
        KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
            .consume(selected.len())
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let mut keys = Vec::with_capacity(selected.len());
        let lax_key_search = invocation.flag("lax-key-search");
        let mut last_load_error = None;
        let mut certificate_budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        for option in selected {
            let loaded = certificate_budget.with_key_import(
                &policy.resources,
                |certificate_budget, inventory, resources| {
                    if option.name == "pkcs12" {
                        let path = Path::new(option.value.as_deref().unwrap_or_default());
                        let bytes = read_key_material_with_budget(path, certificate_budget)?;
                        let password = password
                            .and_then(|value| std::str::from_utf8(value).ok())
                            .ok_or(key_manager::KeyStoreError::ProtectedContainer)?;
                        let name = option.parameter.clone().unwrap_or_else(|| "pkcs12".into());
                        inventory.add_pkcs12(name.clone(), &bytes, password, resources)?;
                        let imported = inventory.private_keys().first().ok_or_else(|| {
                            CommandError::Usage("PKCS#12 contains no usable private key".into())
                        })?;
                        if selected_provider(invocation)?.name() != "rustcrypto" {
                            let key = selected_provider(invocation)?
                                .import_recovery_key(&imported.pkcs8_der)
                                .map_err(|error| CommandError::Encryption(error.to_string()))?;
                            return Ok(RecipientPrivateKey {
                                inner: PrivateKeyDecryptor::provider_key(key),
                                key_name: option.parameter.clone(),
                            });
                        }
                        let private_key = key_material::decode_rsa_private_with_password(
                            path,
                            &imported.pkcs8_der,
                            key_material::PrivateKeyFormat::Pkcs8Der,
                            None,
                            &policy.resources,
                        )?;
                        return Ok(RecipientPrivateKey {
                            inner: PrivateKeyDecryptor::new(private_key),
                            key_name: option.parameter.clone(),
                        });
                    }
                    let (path, certificate_paths) =
                        split_key_and_certificates(option.value.as_deref().unwrap_or_default())?;
                    let bytes = read_key_material_with_budget(Path::new(path), certificate_budget)?;
                    if selected_provider(invocation)?.name() != "rustcrypto" {
                        let format = private_key_format(option);
                        import_explicit_private_key(
                            inventory,
                            &bytes,
                            key_material::PrivateKeyImport {
                                path: Path::new(path),
                                name: "explicit",
                                format,
                                password,
                                usages: key_manager::KeyUsages::DECRYPT,
                                resources,
                            },
                            certificate_budget,
                        )?;
                        let imported = inventory.private_keys().last().ok_or_else(|| {
                            CommandError::Usage("no RSA private key imported".into())
                        })?;
                        let key = selected_provider(invocation)?
                            .import_recovery_key(&imported.pkcs8_der)
                            .map_err(|error| CommandError::Encryption(error.to_string()))?;
                        if !certificate_paths.is_empty() {
                            let encoding = if matches!(
                                format,
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
                                certificate_budget,
                            )?;
                            let spki = key.public_spki().ok_or_else(|| {
                                CommandError::Encryption(
                                    "recovery key exposes no public identity".into(),
                                )
                            })?;
                            ensure_leaf_certificate_matches_spki(&certificates[0], spki)?;
                        }
                        return Ok(RecipientPrivateKey {
                            inner: PrivateKeyDecryptor::provider_key(key),
                            key_name: option.parameter.clone(),
                        });
                    }
                    let private_key = key_material::decode_rsa_private_with_inventory(
                        Path::new(path),
                        &bytes,
                        private_key_format(option),
                        password,
                        resources,
                        inventory,
                    )?;
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
                            certificate_budget,
                        )?;
                        ensure_leaf_certificate_matches_rsa_key(&certificates[0], &private_key)?;
                    }
                    Ok::<_, CommandError>(RecipientPrivateKey {
                        inner: PrivateKeyDecryptor::new(private_key),
                        key_name: option.parameter.clone(),
                    })
                },
            );
            match loaded {
                Ok(key) => keys.push(key),
                Err(error) if lax_key_search && lax_candidate_error_is_recoverable(&error) => {
                    last_load_error = Some(error);
                }
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
            CommandBackends {
                xml: xml_backend,
                crypto: selected_provider(invocation)?,
            },
        )?
    } else {
        return Err(CommandError::Usage(
            "decrypt requires --aes-key, an RSA private key, or --pkcs12".into(),
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
        writeln!(stdout, "<{element}>{}</{element}>", escape_text(value)).map_err(stdout_error)?;
    }
    writeln!(stdout, "<Recipient>NULL</Recipient>").map_err(stdout_error)?;
    writeln!(stdout, "<CarriedKeyName>NULL</CarriedKeyName>").map_err(stdout_error)?;
    writeln!(stdout, "<EncryptionMethod>").map_err(stdout_error)?;
    writeln!(
        stdout,
        "<Transform name=\"{}\" href=\"{}\" />",
        escape_attribute(transform_name),
        escape_attribute(method)
    )
    .map_err(stdout_error)?;
    writeln!(stdout, "</EncryptionMethod>").map_err(stdout_error)?;
    writeln!(stdout, "</DataDecryptionContext>").map_err(stdout_error)
}

struct RecipientPrivateKey {
    inner: PrivateKeyDecryptor,
    key_name: Option<String>,
}

struct SymmetricCandidate<'a> {
    kind: SymmetricKeyKind,
    bytes: Cow<'a, [u8]>,
    name: Option<Cow<'a, str>>,
}

struct CandidateSymmetricKeyDecryptor<'a> {
    keys: Vec<SymmetricCandidate<'a>>,
    lax_key_search: bool,
    content_key_name: Option<&'a str>,
    wrapping_only: bool,
}

impl CandidateSymmetricKeyDecryptor<'_> {
    fn direct_candidate(
        &self,
        kind: SymmetricKeyKind,
        name: Option<&str>,
        algorithm: DataEncryptionAlgorithm,
    ) -> bool {
        !self.wrapping_only
            && symmetric_kind_accepts(kind, algorithm)
            && (self.lax_key_search
                || name.is_none()
                || self.content_key_name.is_none()
                || name == self.content_key_name)
    }
}

fn symmetric_option_kind(name: &str) -> key_manager::SymmetricKeyKind {
    if name == "des-key" {
        key_manager::SymmetricKeyKind::Des
    } else {
        key_manager::SymmetricKeyKind::Aes
    }
}

fn symmetric_kind_accepts(
    kind: key_manager::SymmetricKeyKind,
    algorithm: DataEncryptionAlgorithm,
) -> bool {
    kind == algorithm.key_kind()
}

impl DecryptionKeyResolver for CandidateSymmetricKeyDecryptor<'_> {
    fn resolve_key(
        &self,
        _provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        self.keys
            .iter()
            .find(|key| self.direct_candidate(key.kind, key.name.as_deref(), algorithm))
            .map(|key| key.bytes.as_ref().to_vec())
            .ok_or(XmlEncError::KeyNotFound)
    }

    fn resolve_key_candidates(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        if encrypted_key.is_some() {
            return Err(XmlEncError::KeyNotFound);
        }
        self.resolve_key_candidates_with_policy(
            provider,
            algorithm,
            None,
            &DecryptionPolicy::default(),
            budget,
        )
    }

    fn resolve_key_candidates_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        self.resolve_content_keys_with_policy(provider, algorithm, encrypted_key, policy, budget)?
            .into_iter()
            .map(|key| key.into_key().map_err(XmlEncError::from))
            .collect()
    }

    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        let Some(recipient) = encrypted_key else {
            let mut keys = Vec::new();
            for key in &self.keys {
                if !self.direct_candidate(key.kind, key.name.as_deref(), algorithm) {
                    continue;
                }
                budget.consume(1)?;
                keys.push(xml_sec::provider::RecoveredContentKey::confirmed(
                    key.bytes.to_vec(),
                ));
            }
            return if keys.is_empty() {
                Err(XmlEncError::KeyNotFound)
            } else {
                Ok(keys)
            };
        };
        let wrap = KeyWrapAlgorithm::from_uri(&recipient.encryption_method.algorithm)?;
        let mut keys = Vec::new();
        let mut last_error = XmlEncError::KeyNotFound;
        for key in &self.keys {
            if key.kind != wrap.key_kind() {
                continue;
            }
            if !self.lax_key_search
                && recipient.key_name.as_deref() != key.name.as_deref()
                && !(recipient.key_name.is_none() && self.keys.len() == 1)
            {
                continue;
            }
            match KekDecryptor::borrowed_with_kind(&key.bytes, key.kind)
                .resolve_content_keys_with_policy(
                    provider,
                    algorithm,
                    Some(recipient),
                    policy,
                    budget,
                ) {
                Ok(mut recovered) => keys.append(&mut recovered),
                Err(error @ XmlEncError::Policy(_)) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        if keys.is_empty() {
            Err(last_error)
        } else {
            Ok(keys)
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
        let Some(encrypted_key) = encrypted_key else {
            return Err(XmlEncError::KeyNotFound);
        };
        let mut last_error = None;
        for key in self.applicable_keys(encrypted_key) {
            match key
                .inner
                .resolve_key(provider, algorithm, Some(encrypted_key))
            {
                Ok(key) => return Ok(key),
                Err(error @ XmlEncError::Policy(_)) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
    }

    fn resolve_key_candidates(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        self.resolve_key_candidates_with_policy(
            provider,
            algorithm,
            encrypted_key,
            &DecryptionPolicy::default(),
            budget,
        )
    }

    fn resolve_key_candidates_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        self.resolve_content_keys_with_policy(provider, algorithm, encrypted_key, policy, budget)?
            .into_iter()
            .map(|key| key.into_key().map_err(XmlEncError::Provider))
            .collect()
    }

    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        let Some(encrypted_key) = encrypted_key else {
            return Err(XmlEncError::KeyNotFound);
        };
        let mut resolved = Vec::new();
        let mut last_error = None;
        for key in self.applicable_keys(encrypted_key) {
            budget.consume(1)?;
            match key.inner.resolve_key_with_policy(
                provider,
                algorithm,
                Some(encrypted_key),
                policy,
            ) {
                Ok(key) => resolved.push(key),
                Err(error @ XmlEncError::Policy(_)) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        if resolved.is_empty() {
            return Err(last_error.unwrap_or(XmlEncError::KeyNotFound));
        }
        Ok(resolved)
    }
}

impl NamedRecipientDecryptor {
    fn applicable_keys<'a>(
        &'a self,
        encrypted_key: &'a EncryptedKey,
    ) -> impl Iterator<Item = &'a RecipientPrivateKey> {
        self.keys.iter().filter(|key| {
            self.lax_key_search
                || self.unnamed_single_key_fallback
                || encrypted_key.key_name.as_deref() == key.key_name.as_deref()
        })
    }
}

struct CommandBackends<'a> {
    xml: XmlBackend,
    crypto: &'a dyn CryptoProvider,
}

fn decrypt_input(
    resolver: &dyn DecryptionKeyResolver,
    xml: &str,
    encrypted_data_id: Option<&str>,
    standalone: bool,
    policy: DecryptionPolicy,
    id_attributes: &[IdAttributeRegistration],
    backends: CommandBackends<'_>,
) -> Result<Vec<u8>, CommandError> {
    let context = DecryptContext::new(resolver)
        .provider(backends.crypto)
        .policy(policy)
        .xml_backend(backends.xml)
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
        .decrypt_first_document_from_start_node(xml, encrypted_data_id)
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

fn xmlsec_compatibility_encryption_policy() -> EncryptionPolicy {
    // The compatibility executable is an explicit profile boundary, as for
    // XMLDSig. Library defaults remain restrictive, and provider capability
    // still gates every requested primitive independently of this allowlist.
    EncryptionPolicy {
        #[cfg(feature = "legacy-algorithms")]
        data_algorithms: Some(
            [
                DataEncryptionAlgorithm::TripleDesCbc,
                DataEncryptionAlgorithm::Aes192Cbc,
                DataEncryptionAlgorithm::Aes192Gcm,
                DataEncryptionAlgorithm::Aes128Cbc,
                DataEncryptionAlgorithm::Aes256Cbc,
                DataEncryptionAlgorithm::Aes128Gcm,
                DataEncryptionAlgorithm::Aes256Gcm,
            ]
            .into(),
        ),
        #[cfg(feature = "legacy-algorithms")]
        key_transport_algorithms: Some(
            [
                KeyTransportAlgorithm::RsaPkcs1v15,
                KeyTransportAlgorithm::RsaOaepMgf1p,
                KeyTransportAlgorithm::RsaOaep11,
            ]
            .into(),
        ),
        #[cfg(feature = "legacy-algorithms")]
        key_wrap_algorithms: Some(
            [
                xml_sec::xmlenc::KeyWrapAlgorithm::TripleDes,
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw192,
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw128,
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw256,
            ]
            .into(),
        ),
        ..EncryptionPolicy::default()
    }
}

fn configure_wrapping_recipients(
    mut builder: EncryptedDataBuilder,
    recipients: &[EncryptionTemplateRecipient],
    invocation: &Invocation,
    explicit: &[&crate::OptionValue],
    policy: &EncryptionPolicy,
    backend: XmlBackend,
) -> Result<EncryptedDataBuilder, CommandError> {
    if recipients.iter().any(|recipient| recipient.wrap.is_none()) {
        return Err(CommandError::Usage(
            "encrypt cannot mix symmetric KEK and RSA recipients in one invocation".into(),
        ));
    }
    let mut material =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    let store = if invocation.values("keys-file").next().is_some() {
        Some(load_xml_key_stores(
            invocation,
            policy,
            backend,
            &mut material,
        )?)
    } else {
        None
    };
    let mut budget = KeyCandidateBudget::with_limit(policy.resources.max_key_candidates);
    let mut decoded = HashMap::<usize, zeroize::Zeroizing<Vec<u8>>>::new();
    for recipient in recipients {
        let wrap = recipient.wrap.expect("all recipient methods checked above");
        let requested = recipient.key_name.iter().cloned().collect::<Vec<_>>();
        let (name, key) = if let Some(store) = &store {
            let candidates = select_store_candidates(
                store.symmetric_keys().iter().filter(|entry| {
                    entry.kind == wrap.key_kind()
                        && entry.usages.allows(key_manager::KeyUsage::Encrypt)
                }),
                &requested,
                invocation.flag("lax-key-search"),
                policy.resources.max_key_candidates,
                |entry| &entry.name,
            )?;
            budget
                .consume(candidates.len())
                .map_err(|error| CommandError::Encryption(error.to_string()))?;
            let selected = candidates
                .into_iter()
                .find(|entry| entry.bytes.len() == wrap.key_len())
                .ok_or_else(|| {
                    CommandError::Usage("no compatible wrapping key in --keys-file".into())
                })?;
            (Some(selected.name.clone()), selected.bytes.to_vec())
        } else {
            let candidates = explicit
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, option)| symmetric_option_kind(&option.name) == wrap.key_kind())
                .map(|(index, option)| (option, index))
                .collect::<Vec<_>>();
            let candidates = named_candidate_search(
                &candidates,
                &requested,
                invocation.flag("lax-key-search"),
                true,
                "wrapping key",
            )?;
            budget
                .consume(candidates.len())
                .map_err(|error| CommandError::Encryption(error.to_string()))?;
            let mut selected = None;
            let mut last_error = None;
            for (option, index) in candidates {
                if let Some(key) = decoded.get(&index) {
                    if key.len() == wrap.key_len() {
                        selected = Some((option.parameter.clone(), key.to_vec()));
                        break;
                    }
                    last_error = Some(CommandError::Usage(
                        "wrapping key length does not match the template method".into(),
                    ));
                    continue;
                }
                match load_symmetric_with_budget(
                    option.value.as_deref().unwrap_or_default(),
                    Some(wrap.key_len()),
                    &mut material,
                ) {
                    Ok(key) => {
                        // Recipient builders retain their own key bytes. Cache
                        // only batched inputs to avoid repeated filesystem I/O;
                        // single-recipient operations have no cache allocation.
                        if recipients.len() > 1 {
                            decoded.insert(index, zeroize::Zeroizing::new(key.clone()));
                        }
                        selected = Some((option.parameter.clone(), key));
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            selected.ok_or_else(|| {
                last_error.unwrap_or_else(|| {
                    CommandError::Usage("no compatible wrapping key input".into())
                })
            })?
        };
        let mut configured = EncryptionRecipient::aes_key_wrap(key, wrap);
        if let Some(name) = name {
            configured = configured.key_name(name);
        }
        builder = builder.add_recipient(configured);
    }
    Ok(builder)
}

fn xmlsec_compatibility_decryption_policy() -> DecryptionPolicy {
    let compatibility = xmlsec_compatibility_encryption_policy();
    DecryptionPolicy {
        data_algorithms: compatibility.data_algorithms,
        key_transport_algorithms: compatibility.key_transport_algorithms,
        key_wrap_algorithms: compatibility.key_wrap_algorithms,
        ..DecryptionPolicy::default()
    }
}

fn configured_template_recipient(
    public_key: RsaPublicKey,
    transport: Option<KeyTransportAlgorithm>,
) -> EncryptionRecipient {
    #[cfg(feature = "legacy-algorithms")]
    if transport == Some(KeyTransportAlgorithm::RsaPkcs1v15) {
        return EncryptionRecipient::rsa_pkcs1v15(public_key);
    }
    #[cfg(not(feature = "legacy-algorithms"))]
    let _ = transport;
    EncryptionRecipient::rsa_oaep(public_key)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EncryptionTemplatePlacement {
    Standalone,
    Embedded,
}

struct EncryptionTemplateRecipient {
    key_name: Option<String>,
    transport: Option<KeyTransportAlgorithm>,
    wrap: Option<KeyWrapAlgorithm>,
    oaep_parameters: Option<RsaOaepParameters>,
}

fn encryption_template(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[IdAttributeRegistration],
    policy: &EncryptionPolicy,
    xml_backend: XmlBackend,
) -> Result<EncryptionTemplateMetadata, CommandError> {
    let document = parse_encryption_document(xml, &policy.xml, &policy.resources, xml_backend)?;
    let encrypted_data = select_encrypted_data(&document, start_node_id, id_attributes)?;
    // Templates preserve every non-cipher field. Parse the selected node through
    // the reciprocal core path first so encryption cannot emit a document that
    // the same policy snapshot would reject during decryption.
    let parsed = parse_encrypted_data_template_node_with_policy_and_backend(
        encrypted_data,
        policy,
        xml_backend,
    )
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
            let wrap = KeyWrapAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm).ok();
            Ok(EncryptionTemplateRecipient {
                key_name: encrypted_key.key_name,
                transport: if wrap.is_some() {
                    None
                } else {
                    Some(
                        KeyTransportAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm)
                            .map_err(|error| CommandError::Encryption(error.to_string()))?,
                    )
                },
                wrap,
                oaep_parameters: if wrap.is_some() {
                    None
                } else {
                    template_oaep_parameters(&encrypted_key.encryption_method)?
                },
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
    let public_key = RsaPublicKey::from(private_key)
        .to_public_key_der()
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    ensure_leaf_certificate_matches_spki(certificate_der, public_key.as_bytes())
}

fn ensure_leaf_certificate_matches_spki(
    certificate_der: &[u8],
    public_spki: &[u8],
) -> Result<(), CommandError> {
    let (rest, certificate) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
        .map_err(|_| CommandError::Encryption("invalid X.509 certificate".into()))?;
    if !rest.is_empty() {
        return Err(CommandError::Encryption("invalid X.509 certificate".into()));
    }
    // RFC 5280 §4.1.2.7: SPKI includes AlgorithmIdentifier and its parameters,
    // not just key bits. The companion must match this complete key identity.
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7
    if certificate.public_key().raw != public_spki {
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
    xml_policy: &XmlInputPolicy,
    resources: &ResourcePolicy,
    xml_backend: XmlBackend,
) -> Result<Document<'a>, CommandError> {
    resources
        .validate()
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let nodes_limit = u32::try_from(resources.max_xml_nodes).map_err(|_| {
        CommandError::Encryption("XML node ceiling does not fit the parser limit".into())
    })?;
    Document::parse_with_options_and_backend(
        xml,
        ParsingOptions {
            allow_dtd: xml_policy.allow_internal_dtd,
            nodes_limit,
        },
        xml_backend,
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
    start
        .descendants()
        .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
        .ok_or_else(|| CommandError::Encryption("document has no EncryptedData".into()))
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
        selected_provider(invocation)?
            .fill_random(&mut key)
            .map_err(|error| CommandError::Encryption(error.to_string()))?;
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
        let key_name = generated
            .parameter
            .as_deref()
            .map_or_else(String::new, |name| {
                format!("<KeyName>{}</KeyName>\n", escape_text(name))
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

    use base64::Engine as _;

    use super::*;

    fn invocation(arguments: &[&str]) -> Invocation {
        Invocation::parse(arguments.iter().map(OsString::from)).unwrap()
    }

    #[test]
    fn recipient_metadata_shares_operation_candidate_preflight() {
        // Nested recipients must not each receive a fresh policy allowance;
        // the third candidate is denied before its malformed payload is decoded.
        let recipient = |value: &str| {
            format!(
                "<EncryptedKey><ds:KeyInfo><ds:KeyValue>{value}</ds:KeyValue></ds:KeyInfo></EncryptedKey>"
            )
        };
        let template = |last: &str| {
            format!(
                "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyInfo>{}{}{}</ds:KeyInfo></EncryptedData>",
                recipient("<Unknown/>"),
                recipient("<Unknown/>"),
                recipient(last),
            )
        };
        let mut policy = EncryptionPolicy::default();
        policy.resources.max_key_candidates = 2;
        let error = recipient_key_metadata(
            &template(""),
            None,
            &[],
            &policy,
            3,
            XmlBackend::default(),
            default_provider(),
        )
        .err()
        .expect("aggregate candidate limit");
        assert_eq!(
            error.to_string(),
            "XML encryption operation failed: XMLDSig policy violation: key candidates exceeds policy maximum 2: got 3"
        );
        policy.resources.max_key_candidates = 3;
        assert!(
            recipient_key_metadata(
                &template("<Unknown/>"),
                None,
                &[],
                &policy,
                3,
                XmlBackend::default(),
                default_provider(),
            )
            .is_ok()
        );
    }

    #[test]
    fn temporary_private_imports_keep_kdf_work_after_failure() {
        use der::Encode as _;
        use rsa::pkcs8::{
            EncryptedPrivateKeyInfoRef,
            pkcs5::{EncryptionScheme, pbes2},
        };
        // A failed decrypt spent work even though its temporary inventory held
        // no key. A second PEM/DER candidate must see only the remainder.
        let envelope = EncryptedPrivateKeyInfoRef {
            encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
                kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
                    salt: pbes2::Salt::new(b"12345678").unwrap(),
                    iteration_count: 2,
                    key_length: None,
                    prf: pbes2::Pbkdf2Prf::HmacWithSha256,
                }),
                encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
            }),
            encrypted_data: der::asn1::OctetStringRef::new(&[0; 64]).unwrap(),
        };
        let der = envelope.to_der().unwrap();
        let pem = pem::encode(&pem::Pem::new("ENCRYPTED PRIVATE KEY", der.clone()));
        let resources = xml_sec::policy::ResourcePolicy {
            max_key_import_kdf_work: 5,
            ..Default::default()
        };
        for (bytes, format) in [
            (der.as_slice(), key_material::PrivateKeyFormat::Pkcs8Der),
            (pem.as_bytes(), key_material::PrivateKeyFormat::Pkcs8Pem),
        ] {
            let mut budget =
                ExternalMaterialBudget::new(resources.max_external_resource_total_bytes);
            let import = |_: &mut ExternalMaterialBudget,
                          inventory: &mut KeyInventory,
                          remaining: &xml_sec::policy::ResourcePolicy| {
                key_material::decode_rsa_private_with_inventory(
                    Path::new("key"),
                    bytes,
                    format,
                    Some(b"wrong"),
                    remaining,
                    inventory,
                )
                .map_err(CommandError::from)
            };
            assert!(matches!(
                budget.with_key_import(&resources, import),
                Err(CommandError::Key(
                    key_material::KeyMaterialError::ProtectedContainer
                ))
            ));
            assert_eq!(budget.kdf_work, 3);
            assert!(matches!(
                budget.with_key_import(&resources, import),
                Err(CommandError::Key(key_material::KeyMaterialError::Policy(_)))
            ));
            assert_eq!(budget.kdf_work, 3, "denial must precede the second KDF");
        }
    }

    #[test]
    fn temporary_pkcs12_imports_keep_aggregate_work() {
        // Lax candidates use temporary inventories without resetting operation work.
        let bytes =
            include_bytes!("../../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let resources = xml_sec::policy::ResourcePolicy {
            max_key_import_kdf_work: 10_000,
            ..Default::default()
        };
        let mut budget = ExternalMaterialBudget::new(resources.max_external_resource_total_bytes);
        let import = |_: &mut ExternalMaterialBudget,
                      inventory: &mut KeyInventory,
                      remaining: &xml_sec::policy::ResourcePolicy| {
            inventory
                .add_pkcs12("key".into(), bytes, "secret", remaining)
                .map_err(CommandError::from)
        };
        budget.with_key_import(&resources, import).unwrap();
        assert!(budget.kdf_work > 0);
        assert!(matches!(
            budget.with_key_import(&resources, import),
            Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                _
            )))
        ));
    }

    #[test]
    fn key_store_import_includes_prior_external_material() {
        // Certificate buffers stay live while keys.xml and its decoded key coexist.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("keys.xml");
        let xml = "<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyInfo><ds:KeyName>a</ds:KeyName><ds:KeyValue><HMACKeyValue>AA==</HMACKeyValue></ds:KeyValue></ds:KeyInfo></Keys>";
        fs::write(&path, xml).unwrap();
        let invocation = invocation(&[
            "xmlsec1",
            "verify",
            "--keys-file",
            path.to_str().unwrap(),
            "input.xml",
        ]);
        let mut policy = xml_sec::policy::VerificationPolicy::default();
        policy.resources.max_external_resource_total_bytes = xml.len() + 100;
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        budget.charge(99).unwrap();
        assert!(matches!(
            load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget),
            Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                _
            )))
        ));
        let mut exact =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        exact.charge(97).unwrap();
        assert_eq!(
            load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut exact)
                .unwrap()
                .entry_count(),
            1
        );
    }

    #[test]
    fn repeated_key_files_share_candidate_and_parser_budgets() {
        // The third entry must fail the operation budget before its malformed
        // key is decoded; XML parser work must not reset between files either.
        let temp = tempfile::tempdir().expect("test directory");
        let first = temp.path().join("first.xml");
        let second = temp.path().join("second.xml");
        let entry = |name: &str, value: &str| {
            format!(
                "<ds:KeyInfo><ds:KeyName>{name}</ds:KeyName><ds:KeyValue><HMACKeyValue>{value}</HMACKeyValue></ds:KeyValue></ds:KeyInfo>"
            )
        };
        let store = |entries: String| {
            format!(
                "<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{entries}</Keys>"
            )
        };
        let a = store(entry("a", "AA=="));
        fs::write(&first, &a).expect("first store");
        fs::write(&second, store(entry("b", "AA==") + &entry("c", "!"))).expect("second store");
        let invocation = invocation(&[
            "xmlsec1",
            "sign",
            "--keys-file",
            first.to_str().unwrap(),
            "--keys-file",
            second.to_str().unwrap(),
            "template.xml",
        ]);
        let mut policy = xml_sec::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 2;
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        assert!(matches!(
            load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget),
            Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: "key candidates",
                    maximum: 2
                }
            )))
        ));
        fs::write(&second, store(entry("b", "AA=="))).expect("valid second store");
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        assert_eq!(
            load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget)
                .expect("exact candidate boundary")
                .entry_count(),
            2
        );
        // Enough for either document individually, not both decoding/parsing passes.
        policy.resources.max_xml_parse_work_bytes = a.len() * 3;
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        assert!(matches!(
            load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget),
            Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "cumulative XML parse-work bytes",
                    ..
                }
            )))
        ));
    }

    #[test]
    fn explicit_pkcs8_signing_enforces_import_kdf_limits() {
        // Explicit PEM/DER options, including generic private-key aliases, must
        // reject KDF policy violations before password-dependent decryption.
        use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
        use rsa::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
        let rsa = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .unwrap();
        let plain = rsa.to_pkcs8_der().unwrap();
        let encrypted = rsa::pkcs8::PrivateKeyInfoRef::try_from(plain.as_bytes())
            .unwrap()
            .encrypt_with_rng(&mut ChaCha20Rng::seed_from_u64(42), b"correct")
            .unwrap();
        let pem = encrypted
            .to_pem("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF)
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        for option_name in ["pkcs8-pem", "pkcs8-der", "privkey-pem", "privkey-der"] {
            let path = temp.path().join(option_name);
            fs::write(
                &path,
                if option_name.ends_with("pem") {
                    pem.as_bytes()
                } else {
                    encrypted.as_bytes()
                },
            )
            .unwrap();
            let parsed = Invocation::parse([
                OsString::from("xmlsec1"),
                OsString::from("sign"),
                OsString::from(format!("--{option_name}")),
                path.into_os_string(),
                OsString::from("template.xml"),
            ])
            .unwrap();
            for memory_limit in [false, true] {
                let mut policy = SigningPolicy::default();
                if memory_limit {
                    policy.resources.max_key_import_kdf_memory_bytes = 1;
                } else {
                    policy.resources.max_key_import_kdf_work = 1;
                }
                let mut budget =
                    ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
                let result = prepare_signing_key_candidate(
                    parsed.values(option_name).next().unwrap(),
                    SignatureAlgorithm::RsaSha256,
                    &policy,
                    Some(b"wrong"),
                    &mut budget,
                    default_provider(),
                );
                assert!(
                    matches!(
                        result,
                        Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                            _
                        )))
                    ),
                    "{option_name}, memory limit {memory_limit}"
                );
            }
        }
    }

    #[test]
    fn lax_key_search_stops_on_password_and_policy_failures() {
        // Candidate search may skip incompatible keys, never terminal
        // authentication or operation-wide policy failures.
        assert!(!lax_candidate_error_is_recoverable(&CommandError::Key(
            key_material::KeyMaterialError::ProtectedContainer,
        )));
        assert!(!lax_candidate_error_is_recoverable(&CommandError::Key(
            key_material::KeyMaterialError::PrivateKeyComponents(
                key_manager::KeyStoreError::Selection("RSA modulus exceeds safety limit"),
            ),
        )));
        assert!(!lax_candidate_error_is_recoverable(
            &CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "external resource bytes",
                    maximum: 1,
                    actual: 2,
                },
            ),)
        ));
        assert!(!lax_candidate_error_is_recoverable(&CommandError::Key(
            key_material::KeyMaterialError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "external resource bytes",
                    maximum: 1,
                    actual: 2,
                },
            ),
        )));
    }

    #[test]
    fn compatibility_signing_policy_includes_every_implemented_algorithm() {
        // An explicit allowlist replaces, rather than extends, secure defaults.
        // Keep the CLI compatibility boundary complete when algorithms evolve.
        let policy = xmlsec_compatibility_signing_policy(&invocation(&["xmlsec1", "sign"]));
        assert_eq!(
            policy.signature_algorithms,
            Some(HashSet::from([
                #[cfg(feature = "legacy-algorithms")]
                SignatureAlgorithm::RsaMd5,
                #[cfg(feature = "legacy-algorithms")]
                SignatureAlgorithm::RsaRipemd160,
                #[cfg(feature = "legacy-algorithms")]
                SignatureAlgorithm::HmacMd5,
                #[cfg(feature = "legacy-algorithms")]
                SignatureAlgorithm::HmacRipemd160,
                #[cfg(feature = "legacy-algorithms")]
                SignatureAlgorithm::EcdsaRipemd160,
                SignatureAlgorithm::DsaSha1,
                SignatureAlgorithm::DsaSha256,
                SignatureAlgorithm::HmacSha1,
                SignatureAlgorithm::HmacSha224,
                SignatureAlgorithm::HmacSha256,
                SignatureAlgorithm::HmacSha384,
                SignatureAlgorithm::HmacSha512,
                SignatureAlgorithm::RsaSha1,
                SignatureAlgorithm::RsaSha224,
                SignatureAlgorithm::RsaSha256,
                SignatureAlgorithm::RsaSha384,
                SignatureAlgorithm::RsaSha512,
                SignatureAlgorithm::RsaPssSha1,
                SignatureAlgorithm::RsaPssSha224,
                SignatureAlgorithm::RsaPssSha256,
                SignatureAlgorithm::RsaPssSha384,
                SignatureAlgorithm::RsaPssSha512,
                SignatureAlgorithm::RsaPssSha3_224,
                SignatureAlgorithm::RsaPssSha3_256,
                SignatureAlgorithm::RsaPssSha3_384,
                SignatureAlgorithm::RsaPssSha3_512,
                SignatureAlgorithm::RsaPss(xml_sec::xmldsig::RsaPssParameters::DEFAULT),
                SignatureAlgorithm::EcdsaSha1,
                SignatureAlgorithm::EcdsaSha224,
                SignatureAlgorithm::EcdsaSha256,
                SignatureAlgorithm::EcdsaSha384,
                SignatureAlgorithm::EcdsaSha512,
                SignatureAlgorithm::EcdsaSha3_224,
                SignatureAlgorithm::EcdsaSha3_256,
                SignatureAlgorithm::EcdsaSha3_384,
                SignatureAlgorithm::EcdsaSha3_512,
                SignatureAlgorithm::Ed25519,
                SignatureAlgorithm::Ed25519Ctx,
                SignatureAlgorithm::Ed25519Ph,
                SignatureAlgorithm::Ed448,
                SignatureAlgorithm::Ed448Ph,
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::MlDsa44),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::MlDsa65),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::MlDsa87),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_128s),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_128f),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_192s),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_192f),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_256s),
                SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_256f),
            ]))
        );
        assert_eq!(
            policy.digest_algorithms,
            Some(HashSet::from([
                #[cfg(feature = "legacy-algorithms")]
                DigestAlgorithm::Md5,
                #[cfg(feature = "legacy-algorithms")]
                DigestAlgorithm::Ripemd160,
                DigestAlgorithm::Sha1,
                DigestAlgorithm::Sha224,
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
                DigestAlgorithm::Sha3_224,
                DigestAlgorithm::Sha3_256,
                DigestAlgorithm::Sha3_384,
                DigestAlgorithm::Sha3_512,
            ]))
        );
        assert_eq!(policy.dsa_keys.minimum_modulus_bits, 1024);
    }

    fn testdata(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tools/xmlsec1/testdata")
            .join(name)
    }

    #[test]
    fn named_store_encryption_falls_back_only_when_lax() {
        // An absent named key may fall back in lax mode, but an exact match wins.
        let names = ["fallback", "exact"];
        let requested = vec!["exact".to_string()];
        assert_eq!(
            select_store_candidates(names.iter(), &requested, true, 2, |name| name).unwrap()[0],
            &"exact"
        );
        let absent = vec!["absent".to_string()];
        assert!(select_store_candidates(names.iter(), &absent, false, 2, |name| name).is_err());
        assert_eq!(
            select_store_candidates(names.iter(), &absent, true, 2, |name| name).unwrap()[0],
            &"fallback"
        );
    }

    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn direct_candidates_do_not_cross_aes_and_triple_des_families() {
        // Equal 24-byte lengths must not turn an AES key into a TDEA key.
        let resolver = CandidateSymmetricKeyDecryptor {
            keys: vec![SymmetricCandidate {
                kind: key_manager::SymmetricKeyKind::Aes,
                bytes: Cow::Borrowed(&[1; 24]),
                name: None,
            }],
            lax_key_search: false,
            content_key_name: None,
            wrapping_only: false,
        };
        assert!(matches!(
            resolver.resolve_key(
                &xml_sec::provider::RustCryptoProvider,
                DataEncryptionAlgorithm::TripleDesCbc,
                None
            ),
            Err(XmlEncError::KeyNotFound)
        ));
        assert!(
            resolver
                .resolve_key(
                    &xml_sec::provider::RustCryptoProvider,
                    DataEncryptionAlgorithm::Aes192Cbc,
                    None
                )
                .is_ok()
        );
    }

    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn cli_optional_content_round_trips_and_rejects_wrong_key_type() {
        // Exercise the actual command boundary, including named key selection
        // and explicit compatibility policy; equal AES/TDEA widths cannot alias.
        let directory = tempfile::tempdir().expect("temporary CLI files");
        let template = directory.path().join("template.xml");
        let input = directory.path().join("input.bin");
        let key = directory.path().join("key.bin");
        let encrypted = directory.path().join("encrypted.xml");
        fs::write(&input, b"legacy CLI plaintext").expect("plaintext file");
        fs::write(&key, [0x31; 24]).expect("key file");
        for algorithm in [
            DataEncryptionAlgorithm::TripleDesCbc,
            DataEncryptionAlgorithm::Aes192Cbc,
            DataEncryptionAlgorithm::Aes192Gcm,
        ] {
            fs::write(&template, format!("<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\"><EncryptionMethod Algorithm=\"{}\"/><CipherData><CipherValue/></CipherData></EncryptedData>", algorithm.uri())).expect("template file");
            let option = if algorithm == DataEncryptionAlgorithm::TripleDesCbc {
                "--deskey"
            } else {
                "--aeskey"
            };
            let args = [
                "xmlsec1",
                "encrypt",
                option,
                key.to_str().unwrap(),
                "--binary-data",
                input.to_str().unwrap(),
                template.to_str().unwrap(),
            ];
            let mut output = Vec::new();
            execute(invocation(&args), &mut output, &mut Vec::new()).expect("CLI encryption");
            fs::write(&encrypted, output).expect("encrypted file");
            let args = [
                "xmlsec1",
                "decrypt",
                option,
                key.to_str().unwrap(),
                encrypted.to_str().unwrap(),
            ];
            let mut plaintext = Vec::new();
            execute(invocation(&args), &mut plaintext, &mut Vec::new()).expect("CLI decryption");
            assert_eq!(plaintext, b"legacy CLI plaintext");
            let wrong_option = if option == "--deskey" {
                "--aeskey"
            } else {
                "--deskey"
            };
            let args = [
                "xmlsec1",
                "decrypt",
                wrong_option,
                key.to_str().unwrap(),
                encrypted.to_str().unwrap(),
            ];
            assert!(execute(invocation(&args), &mut Vec::new(), &mut Vec::new()).is_err());
        }
    }

    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn cli_rsa15_template_selects_parameterless_transport() {
        // Test command wiring, not just the library builder: a template's
        // RSA-1.5 method must survive staging without acquiring OAEP children.
        let directory = tempfile::tempdir().expect("CLI files");
        let template = directory.path().join("template.xml");
        let input = directory.path().join("input.bin");
        let encrypted = directory.path().join("encrypted.xml");
        fs::write(&input, b"RSA15 CLI plaintext").expect("plaintext");
        fs::write(&template, "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>").expect("template");
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let public = root.join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
        let private = root.join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
        let args = [
            "xmlsec1",
            "encrypt",
            "--pubkey-pem",
            public.to_str().unwrap(),
            "--binary-data",
            input.to_str().unwrap(),
            template.to_str().unwrap(),
        ];
        let mut output = Vec::new();
        execute(invocation(&args), &mut output, &mut Vec::new()).expect("CLI RSA-1.5 encrypt");
        assert!(!String::from_utf8_lossy(&output).contains("OAEPparams"));
        assert!(!String::from_utf8_lossy(&output).contains("DigestMethod"));
        fs::write(&encrypted, output).expect("ciphertext");
        let args = [
            "xmlsec1",
            "decrypt",
            "--privkey-pem",
            private.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ];
        let mut output = Vec::new();
        execute(invocation(&args), &mut output, &mut Vec::new()).expect("CLI RSA-1.5 decrypt");
        assert_eq!(output, b"RSA15 CLI plaintext");
    }

    #[test]
    fn store_selection_bounds_inspected_candidates() {
        // A name filter cannot make scanning an oversized candidate pool free.
        let names = ["first", "second"];
        let requested = vec!["second".to_owned()];
        assert!(matches!(
            select_store_candidates(names.iter(), &requested, false, 1, |name| name),
            Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "key candidates",
                    maximum: 1,
                    actual: 2,
                }
            )))
        ));
        assert_eq!(
            select_store_candidates(names.iter(), &requested, false, 2, |name| name).unwrap(),
            vec![&"second"]
        );
    }

    #[test]
    fn cli_lax_store_encryption_accepts_missing_template_key_name() {
        // Exercise the command boundary: a present but unknown KeyName must
        // fall back only when --lax-key-search was explicitly requested.
        let temp = tempfile::tempdir().expect("temporary test directory");
        let template_path = temp.path().join("template.xml");
        let input_path = temp.path().join("input.bin");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/xmlenc/aleksey-xmlenc-01/enc-aes128gcm-keyname.tmpl");
        let template = fs::read_to_string(fixture)
            .expect("encryption template fixture")
            .replace("test-aes128", "absent");
        fs::write(&template_path, template).expect("write encryption template");
        fs::write(&input_path, b"lax fallback payload").expect("write plaintext");
        let store =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/xmlsec/mixed-keys.xml");
        let args = [
            "xmlsec1",
            "encrypt",
            "--keys-file",
            store.to_str().expect("fixture path is UTF-8"),
            "--binary-data",
            input_path.to_str().expect("input path is UTF-8"),
            template_path.to_str().expect("template path is UTF-8"),
        ];
        assert!(execute(invocation(&args), &mut Vec::new(), &mut Vec::new()).is_err());
        let mut lax_args = vec!["xmlsec1", "encrypt", "--lax-key-search"];
        lax_args.extend_from_slice(&args[2..]);
        let mut output = Vec::new();
        execute(invocation(&lax_args), &mut output, &mut Vec::new())
            .expect("lax store encryption finds alternate AES key");
        assert!(String::from_utf8_lossy(&output).contains("CipherValue"));
    }

    #[test]
    fn cli_lax_store_encryption_skips_ineligible_aes_key() {
        // A fallback candidate with the wrong AES length must not hide a later usable key.
        let temp = tempfile::tempdir().expect("temporary test directory");
        let template_path = temp.path().join("template.xml");
        let input_path = temp.path().join("input.bin");
        let store_path = temp.path().join("keys.xml");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/xmlenc/aleksey-xmlenc-01/enc-aes128gcm-keyname.tmpl");
        let template = fs::read_to_string(fixture)
            .expect("encryption template fixture")
            .replace("test-aes128", "absent");
        fs::write(&template_path, template).expect("write encryption template");
        fs::write(&input_path, b"lax fallback payload").expect("write plaintext");
        let source = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/xmlsec/mixed-keys.xml"),
        )
        .expect("key store fixture");
        let extra = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>wrong-aes192</KeyName><KeyValue><AESKeyValue xmlns=\"http://www.aleksey.com/xmlsec/2002\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</AESKeyValue></KeyValue></KeyInfo>";
        fs::write(
            &store_path,
            source.replacen("<KeyInfo", &format!("{extra}<KeyInfo"), 1),
        )
        .expect("write key store");
        let args = [
            "xmlsec1",
            "encrypt",
            "--lax-key-search",
            "--keys-file",
            store_path.to_str().expect("store path is UTF-8"),
            "--binary-data",
            input_path.to_str().expect("input path is UTF-8"),
            template_path.to_str().expect("template path is UTF-8"),
        ];
        let mut output = Vec::new();
        execute(invocation(&args), &mut output, &mut Vec::new())
            .expect("lax search skips AES-192 before AES-128");
        assert!(String::from_utf8_lossy(&output).contains("CipherValue"));
    }

    #[test]
    fn cli_lax_store_encryption_preserves_policy_denial() {
        // Policy denials are terminal even when a later key is eligible.
        // A compliant-only inventory must still complete the round-trip.
        let temp = tempfile::tempdir().expect("temporary test directory");
        let template_path = temp.path().join("template.xml");
        let input_path = temp.path().join("input.bin");
        let store_path = temp.path().join("keys.xml");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "tests/fixtures/xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512.tmpl",
        );
        let template = fs::read_to_string(fixture)
            .expect("encryption template fixture")
            .replace("TestKeyName-rsa-4096", "absent");
        fs::write(&template_path, template).expect("write encryption template");
        fs::write(&input_path, b"<root>lax RSA fallback payload</root>").expect("write plaintext");
        let pem = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
        )
        .expect("public key fixture");
        let public_key = RsaPublicKey::from_public_key_pem(&pem).expect("RSA public key");
        let encode = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
        let extra = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>valid-rsa</KeyName><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo>",
            encode(public_key.n().to_be_bytes_trimmed_vartime().into_vec()),
            encode(public_key.e().to_be_bytes_trimmed_vartime().into_vec())
        );
        let source = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/xmlsec/mixed-keys.xml"),
        )
        .expect("key store fixture");
        fs::write(
            &store_path,
            source.replacen("</Keys>", &format!("{extra}</Keys>"), 1),
        )
        .expect("write key store");
        let args = [
            "xmlsec1",
            "encrypt",
            "--lax-key-search",
            "--keys-file",
            store_path.to_str().expect("store path is UTF-8"),
            "--xml-data",
            input_path.to_str().expect("input path is UTF-8"),
            template_path.to_str().expect("template path is UTF-8"),
        ];
        let mut output = Vec::new();
        assert!(matches!(
            execute(invocation(&args), &mut output, &mut Vec::new()),
            Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                xml_sec::policy::PolicyViolation::KeySize {
                    operation: "encryption",
                    key_type: "RSA",
                    minimum_bits: 2048,
                    maximum_bits: 8192,
                    actual_bits: 1024,
                }
            )))
        ));
        assert!(output.is_empty());
        fs::write(
            &store_path,
            format!("<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\">{extra}</Keys>"),
        )
        .expect("compliant-only store");
        execute(invocation(&args), &mut output, &mut Vec::new())
            .expect("lax search selects the compliant RSA key");
        assert!(String::from_utf8_lossy(&output).contains("CipherValue"));
        let encrypted = temp.path().join("encrypted.xml");
        fs::write(&encrypted, &output).expect("write encrypted output");
        let private =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
        let decrypt_args = [
            "xmlsec1",
            "decrypt",
            "--privkey-pem:valid-rsa",
            private.to_str().expect("key path is UTF-8"),
            encrypted.to_str().expect("encrypted path is UTF-8"),
        ];
        let mut decrypted = Vec::new();
        execute(invocation(&decrypt_args), &mut decrypted, &mut Vec::new())
            .expect("strict decryption uses the fallback recipient name");
        assert_eq!(decrypted, b"lax RSA fallback payload");
    }

    #[test]
    fn store_signing_retries_key_info_mismatch_in_lax_mode() {
        // An algorithm-compatible key is not a valid match for embedded KeyInfo.
        let mut inventory = KeyInventory::default();
        let policy = SigningPolicy::default();
        let wrong = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/rsa/rsa-2048-key.pem"),
        )
        .unwrap();
        let right = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/rsa/rsa-4096-key.pem"),
        )
        .unwrap();
        for (name, pem) in [("wrong", wrong), ("right", right)] {
            inventory
                .add_private_pem(
                    name.into(),
                    &pem,
                    None,
                    key_manager::KeyUsages::SIGN,
                    &policy.resources,
                )
                .unwrap();
        }
        let right_spki = inventory
            .signing_key("right", SignatureAlgorithm::RsaSha256, &policy)
            .unwrap()
            .public_key_info()
            .unwrap()
            .spki_der()
            .unwrap()
            .to_vec();
        let mut info = KeyInfo::default();
        info.sources
            .push(KeyInfoSource::DerEncodedKeyValue(right_spki));
        assert!(
            select_store_signing_key(
                &inventory,
                ["wrong"],
                SignatureAlgorithm::RsaSha256,
                Some(&info),
                &policy,
                false,
                default_provider(),
            )
            .is_err()
        );
        assert!(
            select_store_signing_key(
                &inventory,
                ["wrong", "right"],
                SignatureAlgorithm::RsaSha256,
                Some(&info),
                &policy,
                true,
                default_provider(),
            )
            .is_ok()
        );
    }

    #[test]
    fn lax_store_signing_shares_lookup_budget_across_retries() {
        // Three independent scans cost 1 + 2 + 3 inspections, not three.
        let mut inventory = KeyInventory::default();
        let mut policy = SigningPolicy::default();
        let wrong = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/rsa/rsa-2048-key.pem"),
        )
        .unwrap();
        let right = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/rsa/rsa-4096-key.pem"),
        )
        .unwrap();
        for (name, pem) in [("wrong-a", &wrong), ("wrong-b", &wrong), ("right", &right)] {
            inventory
                .add_private_pem(
                    name.into(),
                    pem,
                    None,
                    key_manager::KeyUsages::SIGN,
                    &policy.resources,
                )
                .unwrap();
        }
        let right_spki = inventory
            .signing_key("right", SignatureAlgorithm::RsaSha256, &policy)
            .unwrap()
            .public_key_info()
            .unwrap()
            .spki_der()
            .unwrap()
            .to_vec();
        let mut info = KeyInfo::default();
        info.sources
            .push(KeyInfoSource::DerEncodedKeyValue(right_spki));
        policy.resources.max_key_candidates = 3;
        assert!(
            select_store_signing_key(
                &inventory,
                ["wrong-a", "wrong-b", "right"],
                SignatureAlgorithm::RsaSha256,
                Some(&info),
                &policy,
                true,
                default_provider(),
            )
            .is_err()
        );
    }

    #[test]
    fn strict_store_signing_requires_template_key_name() {
        // A singleton store must not silently authorize an unnamed template.
        let temp = tempfile::tempdir().expect("temporary signing template");
        let template = temp.path().join("unsigned.xml");
        fs::write(
            &template,
            br#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"#,
        )
        .expect("write template");
        let template = template.to_str().expect("UTF-8 path");
        let store = temp.path().join("keys.xml");
        fs::write(
            &store,
            br#"<Keys xmlns="http://www.aleksey.com/xmlsec/2002"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>only-key</KeyName><KeyValue><HMACKeyValue xmlns="http://www.aleksey.com/xmlsec/2002">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"#,
        )
        .expect("write singleton store");
        let store = store.to_str().expect("UTF-8 path");
        let strict = invocation(&["xmlsec1", "sign", "--keys-file", store, template]);
        let error = sign(&strict, &mut Vec::new()).expect_err("strict mode requires KeyName");
        assert!(
            error.to_string().contains("requires a template KeyName"),
            "{error}"
        );
        let lax = invocation(&[
            "xmlsec1",
            "sign",
            "--lax-key-search",
            "--keys-file",
            store,
            template,
        ]);
        let mut signed = Vec::new();
        sign(&lax, &mut signed).expect("lax mode may select the unnamed singleton");
        assert!(String::from_utf8_lossy(&signed).contains("DigestValue"));
    }

    #[test]
    fn pkcs12_signing_ignores_unrelated_ca_certificate() {
        // A CA-only bundle still provides its private signing key, without a leaf writer.
        let bundle = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!("../../../tests/fixtures/keys/pkcs12/rsa-key-unrelated-ca.p12.b64")
                    .trim(),
            )
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("key.p12");
        fs::write(&path, bundle).unwrap();
        let parsed = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("sign"),
            OsString::from("--pkcs12"),
            path.into_os_string(),
            OsString::from("template.xml"),
        ])
        .unwrap();
        let option = parsed.values("pkcs12").next().unwrap();
        let mut budget = ExternalMaterialBudget::new(usize::MAX);
        let candidate = prepare_signing_key_candidate(
            option,
            SignatureAlgorithm::RsaSha256,
            &SigningPolicy::default(),
            Some(b"secret"),
            &mut budget,
            default_provider(),
        )
        .unwrap();
        assert!(candidate.certificate_writer.is_none());
        assert!(candidate.leaf_certificate_der.is_none());
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

    struct FailingVerificationKey {
        reason: &'static str,
    }

    impl VerifyingKey for FailingVerificationKey {
        fn verify(
            &self,
            _algorithm: SignatureAlgorithm,
            _signed_data: &[u8],
            _signature_value: &[u8],
        ) -> Result<bool, DsigError> {
            Err(DsigError::InvalidStructure {
                reason: self.reason,
            })
        }
    }

    #[test]
    fn candidate_verifier_preserves_mismatch_and_error_precedence() {
        // A definitive cryptographic mismatch outranks provider errors, while
        // an all-error candidate set reports the final attempted provider.
        let mismatch_then_error = CandidateVerifyingKey {
            candidates: vec![
                Box::new(CountingVerificationKey {
                    accepts: false,
                    calls: Rc::new(Cell::new(0)),
                }),
                Box::new(FailingVerificationKey { reason: "last" }),
            ],
        };
        assert!(matches!(
            mismatch_then_error.verify(SignatureAlgorithm::RsaSha256, b"data", b"signature"),
            Ok(false)
        ));

        let errors = CandidateVerifyingKey {
            candidates: vec![
                Box::new(FailingVerificationKey { reason: "first" }),
                Box::new(FailingVerificationKey { reason: "last" }),
            ],
        };
        assert!(matches!(
            errors.verify(SignatureAlgorithm::RsaSha256, b"data", b"signature"),
            Err(DsigError::InvalidStructure { reason: "last" })
        ));
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
        let xml = fs::read_to_string(testdata("enveloping-sha256-rsa-sha256.xml")).unwrap();

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
    fn stored_verification_sources_share_candidate_budget() {
        // Lax search must not reset source-inspection work per imported entry,
        // or swallow the denial because an earlier candidate resolved.
        let mut info = KeyInfo::default();
        info.sources = vec![
            KeyInfoSource::KeyName("first".into()),
            KeyInfoSource::KeyValue(KeyValueInfo::Unsupported {
                namespace: None,
                local_name: "unsupported".into(),
            }),
        ];
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_pem(
                "valid".into(),
                include_bytes!("../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
                &ResourcePolicy::default(),
            )
            .unwrap();
        let valid = inventory.public_keys()[0].key_info.clone();
        for info in [info, valid] {
            let resolver = CandidateVerificationResolver::new(
                vec![
                    ExplicitVerificationCandidate::Certificate(info.clone()),
                    ExplicitVerificationCandidate::Certificate(info),
                ],
                ConfiguredCertificates::default(),
                true,
                false,
            );
            let mut policy = VerificationPolicy::default();
            policy.resources.max_key_candidates = 3;
            assert!(matches!(resolver.resolve_with_policy_and_provider(None,
            SignatureAlgorithm::RsaSha256, &policy, default_provider()),
            Err(DsigError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
                resource, maximum: 3, ..
            })) if resource == "key candidates"));
            policy.resources.max_key_candidates = 4;
            assert!(
                resolver
                    .resolve_with_policy_and_provider(
                        None,
                        SignatureAlgorithm::RsaSha256,
                        &policy,
                        default_provider()
                    )
                    .is_ok()
            );
        }
    }

    #[test]
    fn verification_candidate_collection_obeys_trust_budget() {
        // Lax lookup must not turn caller-provided key files into unbounded
        // public-key verification attempts.
        let candidate = VerificationKey {
            algorithm: SignatureAlgorithm::RsaSha256,
            public_key_bytes: Vec::new(),
            certificate_der: None,
            name: None,
        };
        let mut policy = VerificationPolicy::default();
        policy.key_trust.max_x509_candidate_paths = 1;
        let resolver = CandidateVerificationResolver::new(
            vec![
                ExplicitVerificationCandidate::Direct(candidate.clone()),
                ExplicitVerificationCandidate::Direct(candidate),
            ],
            ConfiguredCertificates::default(),
            true,
            false,
        );

        let error = match resolver.resolve_with_policy_and_provider(
            None,
            SignatureAlgorithm::RsaSha256,
            &policy,
            default_provider(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("candidate count above policy must fail closed"),
        };
        assert!(matches!(
            error,
            DsigError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "verification key candidates",
                maximum: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn raw_recipient_key_is_charged_before_decode() {
        // Raw keys and certificates share one invocation budget; bytes must be
        // charged before an asymmetric format decoder receives them.
        let path = testdata("rsa-2048-cert.pem");
        let mut budget = ExternalMaterialBudget::new(1);
        let error = load_rsa_recipient_candidate(
            path.as_os_str(),
            RecipientPublicKeySource::Public(key_material::PublicKeyEncoding::Pem),
            &EncryptionPolicy::default(),
            &mut budget,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CommandError::ExternalMaterialTooLarge { maximum: 1 }
        ));
    }

    #[test]
    fn certificate_recipient_key_is_charged_before_decode() {
        // Aggregate source accounting must reject certificate bytes before PEM
        // or X.509 parsing, just as it does for raw public-key candidates.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("malformed.pem");
        fs::write(&path, b"xx").unwrap();
        let mut budget = ExternalMaterialBudget::new(1);

        let error = load_rsa_recipient_candidate(
            path.as_os_str(),
            RecipientPublicKeySource::Certificate(key_material::CertificateEncoding::Pem),
            &EncryptionPolicy::default(),
            &mut budget,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CommandError::ExternalMaterialTooLarge { maximum: 1 }
        ));
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
    fn xml_backend_selector_is_strict_and_build_aware() {
        // Runtime selection must neither accept unknown names nor fall back
        // when a thin binary does not contain the requested implementation.
        let invalid = invocation(&["xmlsec1", "verify", "--xml-backend", "libxml2", "input.xml"]);
        assert!(matches!(
            selected_xml_backend(&invalid),
            Err(CommandError::UnsupportedXmlBackend(name)) if name == "libxml2"
        ));

        for (name, backend) in [
            ("xmloxide", XmlBackend::Xmloxide),
            ("roxmltree", XmlBackend::Roxmltree),
            ("differential", XmlBackend::Differential),
        ] {
            let invocation = invocation(&["xmlsec1", "verify", "--xml-backend", name, "input.xml"]);
            let selected = selected_xml_backend(&invocation);
            if backend.is_available() {
                assert_eq!(selected.unwrap(), backend);
            } else {
                assert!(matches!(
                    selected,
                    Err(CommandError::UnavailableXmlBackend(rejected)) if rejected == name
                ));
            }
        }
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
            policy.transforms.xpath_here_semantics,
            xml_sec::xmldsig::XPathHereSemantics::XmlSecLegacy
        );
        assert_eq!(policy.key_trust.dsa_keys.minimum_modulus_bits, 1024);
        assert_eq!(policy.hmac.minimum_key_bits, 40);
        assert_eq!(policy.uris.key_info_references, UriTypeSet::SAME_DOCUMENT);
    }

    #[test]
    fn openssl_compatibility_strict_check_flag_does_not_weaken_trust_policy() {
        // The pinned donor uses OpenSSL, where this backend-specific flag is a
        // no-op; accepting it must not disable Rust certificate/path checks.
        let baseline = xmlsec_compatibility_verification_policy(&invocation(&[
            "xmlsec1",
            "verify",
            "input.xml",
        ]));
        let skipped = xmlsec_compatibility_verification_policy(&invocation(&[
            "xmlsec1",
            "verify",
            "--X509-skip-strict-checks",
            "input.xml",
        ]));

        assert_eq!(skipped.key_trust, baseline.key_trust);
        assert_eq!(skipped.signature_algorithms, baseline.signature_algorithms);
        assert_eq!(skipped.digest_algorithms, baseline.digest_algorithms);
        assert_eq!(skipped.transforms, baseline.transforms);
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
            XmlBackend::default(),
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
            XmlBackend::default(),
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
    fn generated_recipient_replaces_a_split_stale_key_name() {
        // A comment may split direct KeyName text without changing its value.
        // Comparing only the first text child would retain the stale name.
        let template = format!(
            "<e:EncryptedKey xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><s:KeyName>valid<!-- split -->-old</s:KeyName></s:KeyInfo><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedKey>"
        );
        let generated = format!(
            "<e:EncryptedKey xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><s:KeyName>valid</s:KeyName></s:KeyInfo><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey>"
        );
        let template_doc = Document::parse(&template).expect("template parses");
        let generated_doc = Document::parse(&generated).expect("generated key parses");
        let replacement = merge_generated_recipient_key_name(
            &template,
            template_doc.root_element(),
            &generated,
            generated_doc.root_element(),
        )
        .expect("recipient name merge succeeds")
        .expect("the stale full name must be replaced");
        let rendered = format!(
            "{}{}{}",
            &template[..replacement.0.start],
            replacement.1,
            &template[replacement.0.end..]
        );
        let document = Document::parse(&rendered).expect("replacement parses");
        let key_name = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyName")))
            .expect("recipient name remains present");
        assert_eq!(direct_simple_text(key_name, "KeyName").unwrap(), "valid");
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
            XmlBackend::default(),
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
    fn encryption_template_preserves_cipher_value_metadata() {
        // CipherValue is caller-owned: replacing ciphertext must preserve its
        // prefixes, namespace declarations, and extension attributes.
        let template = format!(
            "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\" xmlns:x=\"urn:ext\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue x:kind=\"wrapped\">old</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue x:kind=\"content\"/></e:CipherData></e:EncryptedData>"
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
            XmlBackend::default(),
        )
        .expect("CipherValue payload replacement must preserve template metadata");
        let document = Document::parse(&rendered).unwrap();
        let values = document
            .descendants()
            .filter(|node| node.has_tag_name((XMLENC_NS, "CipherValue")))
            .map(|node| (node.attribute(("urn:ext", "kind")), node.text()))
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                (Some("wrapped"), Some("a2V5")),
                (Some("content"), Some("ZGF0YQ=="))
            ]
        );
    }

    #[test]
    fn encrypted_data_selection_uses_the_first_descendant() {
        // libxmlsec1 starts a depth-first search at the operation root and
        // does not impose global EncryptedData cardinality on that subtree.
        let xml = format!(
            "<root><group Id=\"selected\"><xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\" Id=\"first\"/><xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\" Id=\"second\"/></group></root>"
        );
        let document = Document::parse(&xml).unwrap();

        let selected = select_encrypted_data(&document, None, &[])
            .expect("the first document descendant must be selected");
        assert_eq!(selected.attribute("Id"), Some("first"));

        let selected = select_encrypted_data(&document, Some("selected"), &[])
            .expect("the first operation-subtree descendant must be selected");
        assert_eq!(selected.attribute("Id"), Some("first"));
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

        let error = apply_encryption_template(
            &template,
            &generated,
            None,
            &[],
            &policy,
            XmlBackend::default(),
        )
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

        let error = apply_encryption_template(
            &template,
            &generated,
            None,
            &[],
            &policy,
            XmlBackend::default(),
        )
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
    fn xml_readers_classify_decoded_expansion_as_input_too_large() {
        // A declared single-byte document may fit the raw-byte gate but expand after decoding.
        // Both CLI XML readers must preserve that second boundary as InputTooLarge.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("expanded.xml");
        let bytes = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>\xe9\xe9</root>";
        fs::write(&path, bytes).unwrap();
        let invocation = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("verify"),
            path.clone().into_os_string(),
        ])
        .unwrap();

        assert!(matches!(
            read_input(&invocation, bytes.len()),
            Err(CommandError::InputTooLarge { maximum }) if maximum == bytes.len()
        ));
        assert!(matches!(
            read_xml_data(path.as_os_str(), bytes.len()),
            Err(CommandError::InputTooLarge { maximum }) if maximum == bytes.len()
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

        let error = match encryption_template(
            &xml,
            None,
            &[],
            &EncryptionPolicy::default(),
            XmlBackend::default(),
        ) {
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
        let mut budget = ExternalMaterialBudget::new(5);
        budget.charge(2).unwrap();
        push_configured_certificate(&mut certificates, vec![1, 2]);
        budget.charge(2).unwrap();
        push_configured_certificate(&mut certificates, vec![1, 2]);
        assert_eq!(certificates, [vec![1, 2]]);
        assert_eq!(budget.total_bytes, 4);

        assert!(matches!(
            budget.charge(2),
            Err(CommandError::ExternalMaterialTooLarge { maximum: 5 })
        ));
        assert_eq!(certificates, [vec![1, 2]]);
        assert_eq!(budget.total_bytes, 4);

        assert!(matches!(
            budget.charge(2),
            Err(CommandError::ExternalMaterialTooLarge { maximum: 5 })
        ));
        assert_eq!(budget.total_bytes, 4);
    }

    #[test]
    fn signing_key_source_is_charged_before_private_key_decoding() {
        // Aggregate source limits must stop a candidate before malformed key
        // bytes reach the comparatively expensive private-key decoders.
        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("malformed.pem");
        fs::write(&key_path, b"xx").unwrap();
        let parsed = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("sign"),
            OsString::from("--privkey-pem"),
            key_path.into_os_string(),
            OsString::from("template.xml"),
        ])
        .unwrap();
        let option = parsed.values("privkey-pem").next().unwrap();
        let mut budget = ExternalMaterialBudget::new(1);

        assert!(matches!(
            prepare_signing_key_candidate(
                option,
                SignatureAlgorithm::RsaSha256,
                &SigningPolicy::default(),
                None,
                &mut budget,
                default_provider(),
            ),
            Err(CommandError::ExternalMaterialTooLarge { maximum: 1 })
        ));
    }

    #[test]
    fn lax_signing_propagates_aggregate_material_exhaustion() {
        // A malformed candidate is recoverable in lax mode, but a later source
        // that exhausts the shared budget must stop search before a valid key.
        let temp = tempfile::tempdir().unwrap();
        let malformed = temp.path().join("malformed.pem");
        let oversized = temp.path().join("oversized.pem");
        let valid = testdata("rsa-2048-key.pem");
        fs::write(&malformed, b"x").unwrap();
        let valid_len = fs::metadata(&valid).unwrap().len();
        fs::File::create(&oversized)
            .unwrap()
            .set_len(valid_len + 1)
            .unwrap();
        let parsed = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("sign"),
            OsString::from("--lax-key-search"),
            OsString::from("--privkey-pem:malformed"),
            malformed.into_os_string(),
            OsString::from("--privkey-pem:oversized"),
            oversized.into_os_string(),
            OsString::from("--privkey-pem:valid"),
            valid.into_os_string(),
            OsString::from("template.xml"),
        ])
        .unwrap();
        let mut policy = SigningPolicy::default();
        policy.resources.max_external_resource_total_bytes = valid_len as usize + 1;

        assert!(matches!(
            select_signing_key(
                &parsed,
                &[],
                SignatureAlgorithm::RsaSha256,
                None,
                &policy,
                None,
            ),
            Err(CommandError::ExternalMaterialTooLarge { maximum })
                if maximum == valid_len as usize + 1
        ));
    }

    #[test]
    fn duplicate_configured_certificate_sources_consume_aggregate_budget() {
        // Deduplicating retained DER must not make repeated external file reads
        // free: every explicitly supplied source consumes invocation work.
        let certificate = testdata("rsa-2048-cert.pem");
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
        let mut budget = ExternalMaterialBudget::new(source_len);

        assert!(matches!(
            load_configured_certificates(&invocation, false, &mut budget),
            Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == source_len
        ));
    }

    #[test]
    fn certificate_companions_charge_source_bytes_before_retention() {
        // PEM whitespace is still processed input even though it disappears
        // from decoded DER, so the source size must drive aggregate charging.
        let fixture = testdata("rsa-2048-cert.pem");
        let temp = tempfile::tempdir().unwrap();
        let padded = temp.path().join("padded-cert.pem");
        let mut source = fs::read(&fixture).unwrap();
        source.extend(std::iter::repeat_n(b' ', 4096));
        fs::write(&padded, &source).unwrap();
        let der_len = key_material::load_certificate_with_source_len(
            &padded,
            key_material::CertificateEncoding::Pem,
        )
        .unwrap()
        .0
        .len();
        let mut budget = ExternalMaterialBudget::new(der_len);

        assert!(matches!(
            load_certificate_companions(
                &[padded.as_os_str()],
                key_material::CertificateEncoding::Pem,
                &mut budget,
            ),
            Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == der_len
        ));
    }

    #[test]
    fn explicit_verification_certificate_charges_source_bytes() {
        // Explicit leaf certificates share the invocation budget with trust
        // inputs, including PEM bytes discarded while decoding the DER value.
        let fixture = testdata("rsa-2048-cert.pem");
        let temp = tempfile::tempdir().unwrap();
        let padded = temp.path().join("padded-explicit-cert.pem");
        let mut source = fs::read(&fixture).unwrap();
        source.extend(std::iter::repeat_n(b' ', 4096));
        fs::write(&padded, &source).unwrap();
        let der_len = key_material::load_certificate_with_source_len(
            &padded,
            key_material::CertificateEncoding::Pem,
        )
        .unwrap()
        .0
        .len();
        let option = crate::OptionValue {
            name: "pubkey-cert-pem".into(),
            parameter: None,
            value: Some(padded.into_os_string()),
        };
        let mut budget = ExternalMaterialBudget::new(der_len);

        assert!(matches!(
            load_explicit_certificate_key_info(&option, &mut budget),
            Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == der_len
        ));
    }

    #[test]
    fn recipient_resolver_bounds_applicable_private_keys_before_unwrap() {
        // Lax lookup must not hide an unbounded RSA-OAEP loop behind the single
        // content key eventually returned to the core decryption context.
        let path = testdata("rsa-2048-key.pem");
        let private_key =
            key_material::load_rsa_private(&path, key_material::PrivateKeyFormat::Pem).unwrap();
        let resolver = NamedRecipientDecryptor {
            keys: vec![
                RecipientPrivateKey {
                    inner: PrivateKeyDecryptor::new(private_key.clone()),
                    key_name: None,
                },
                RecipientPrivateKey {
                    inner: PrivateKeyDecryptor::new(private_key),
                    key_name: None,
                },
            ],
            lax_key_search: true,
            unnamed_single_key_fallback: false,
        };
        let encrypted_key = EncryptedKey {
            id: None,
            recipient: None,
            key_name: None,
            encryption_method: EncryptionMethod {
                algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: xml_sec::xmlenc::CipherData {
                value: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [0_u8; 256],
                ),
            },
            reference_list: None,
            carried_key_name: None,
        };

        let mut candidate_budget = KeyCandidateBudget::for_operation();
        let maximum = candidate_budget.remaining();
        let reserved = maximum - 1;
        candidate_budget.consume(reserved).unwrap();
        let error = resolver
            .resolve_key_candidates(
                default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key),
                &mut candidate_budget,
            )
            .expect_err("oversized applicable RSA key sets must fail before unwrap");

        assert!(matches!(
            error,
            XmlEncError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "key candidates",
                maximum: observed_maximum,
                actual,
            }) if observed_maximum == maximum && actual == maximum + 1
        ));
    }

    #[test]
    fn recipient_certificate_loader_charges_the_invocation_budget() {
        // Recipient certificates are external inputs even when used only to
        // extract an RSA wrapping key, so they share the operation-wide budget.
        let certificate = testdata("rsa-2048-cert.pem");
        let mut budget = ExternalMaterialBudget::new(1);

        let error = load_rsa_recipient_candidate(
            certificate.as_os_str(),
            RecipientPublicKeySource::Certificate(key_material::CertificateEncoding::Pem),
            &EncryptionPolicy::default(),
            &mut budget,
        )
        .expect_err("certificate DER must exceed the one-byte aggregate budget");

        assert!(matches!(
            error,
            CommandError::ExternalMaterialTooLarge { maximum: 1 }
        ));
    }

    #[test]
    fn recipient_certificate_loader_charges_pem_source_bytes() {
        // PEM whitespace is processed external input even though decoding drops
        // it, so recipient certificate accounting must use the source length.
        let fixture = testdata("rsa-2048-cert.pem");
        let temp = tempfile::tempdir().unwrap();
        let padded = temp.path().join("padded-recipient-cert.pem");
        let mut source = fs::read(&fixture).unwrap();
        source.extend(std::iter::repeat_n(b' ', 4096));
        fs::write(&padded, source).unwrap();
        let der_len = key_material::load_certificate_with_source_len(
            &padded,
            key_material::CertificateEncoding::Pem,
        )
        .unwrap()
        .0
        .len();
        let mut budget = ExternalMaterialBudget::new(der_len);

        assert!(matches!(
            load_rsa_recipient_candidate(
                padded.as_os_str(),
                RecipientPublicKeySource::Certificate(
                    key_material::CertificateEncoding::Pem,
                ),
                &EncryptionPolicy::default(),
                &mut budget,
            ),
            Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == der_len
        ));
    }

    #[test]
    fn recipient_certificate_cache_reuses_one_budget_charge() {
        // Repeated recipient selection may reuse one CLI option, but external
        // certificate bytes belong to the invocation and are charged once.
        let certificate = testdata("rsa-2048-cert.pem");
        let (_, source_len) = key_material::load_certificate_with_source_len(
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
        let mut budget = ExternalMaterialBudget::new(source_len);

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
            xml_data_plaintext(
                xml,
                &EncryptedDataType::Content,
                &policy,
                XmlBackend::default(),
            ),
            Err(CommandError::PlaintextTooLarge { maximum: 32 })
        ));
    }

    #[test]
    fn xml_data_reader_decodes_utf16_before_template_use() {
        // --xml-data has its own file reader and must share the same XML 1.0
        // encoding contract as the primary command input.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("payload.xml");
        let mut bytes = vec![0xfe, 0xff];
        bytes.extend(
            "<payload>value</payload>"
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        );
        fs::write(&path, &bytes).unwrap();

        assert_eq!(
            read_xml_data(path.as_os_str(), bytes.len()).unwrap(),
            "<payload>value</payload>"
        );
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
