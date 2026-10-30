use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use rsa::{RsaPublicKey, traits::PublicKeyParts as _};
use xml_sec::rsa_encoding::RsaPublicKeyEncoding as _;
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
        UriTypeSet, VerificationKey, VerificationScope, VerifyContext, VerifyResult, VerifyingKey,
        X509CertificateKeyInfoWriter, XPathHereSemantics, parse_key_info,
        uri::UriReferenceResolver, validate_signing_key,
    },
    xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DecryptionKeyResolver,
        EncryptedDataBuilder, EncryptedDataType, EncryptedKey, EncryptionMethod,
        EncryptionRecipient, KekDecryptor, KeyCandidateBudget, KeyTransportAlgorithm,
        KeyWrapAlgorithm, OaepDigestAlgorithm, PrivateKeyDecryptor, RsaOaepParameters, XmlEncError,
        validate_rsa_recipient_key,
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
    utc_facts::UtcFacts,
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
    "pubkey-pem",
    "pubkey-der",
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
    "url-map",
    "enable-visa3d-hack",
    "enable-asn1-signatures-hack",
];
const VERIFY_OPTIONS: &[&str] = &[
    "privkey-pem",
    "privkey-der",
    "pkcs8-pem",
    "pkcs8-der",
    "pwd",
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
    "utc-facts",
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
    "session-key",
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
const XMLDSIG11_NS: &str = "http://www.w3.org/2009/xmldsig11#";
const XMLSEC_COMPATIBILITY_HERE_SEMANTICS: XPathHereSemantics = XPathHereSemantics::XmlSecLegacy;
const XMLSEC_COMPATIBILITY_XSLT_STYLESHEETS: xml_sec::policy::XsltStylesheetSemantics =
    xml_sec::policy::XsltStylesheetSemantics::Libxmlsec1;
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
    #[error(transparent)]
    Policy(#[from] xml_sec::policy::PolicyViolation),
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
    invocation: &Invocation,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), CommandError> {
    if invocation.flag("help") {
        return command_help(invocation.command, stdout);
    }
    validate_provider(invocation)?;
    validate_crypto_config(invocation)?;
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
            selected_provider(invocation)?.name()
        )
        .map_err(stdout_error),
        Command::ListTransforms => {
            validate_options(invocation, &[])?;
            let provider = selected_provider(invocation)?;
            capabilities::list_available(
                "transform klasses",
                TRANSFORMS,
                |name| capabilities::transform_available(name, provider),
                stdout,
            )
            .map_err(stdout_error)
        }
        Command::CheckTransforms => {
            validate_options(invocation, &[])?;
            let provider = selected_provider(invocation)?;
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
            validate_options(invocation, &[])?;
            let provider = selected_provider(invocation)?;
            capabilities::list_available(
                "key data klasses",
                KEY_DATA,
                |name| capabilities::key_data_available(name, provider),
                stdout,
            )
            .map_err(stdout_error)
        }
        Command::CheckKeyData => {
            validate_options(invocation, &[])?;
            let provider = selected_provider(invocation)?;
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
        Command::Keys => keys(invocation, stdout),
        Command::Sign => sign(invocation, stdout),
        Command::Verify => verify(invocation, stdout),
        Command::Encrypt => encrypt(invocation, stdout),
        Command::Decrypt => decrypt(invocation, stdout),
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
    provider_by_name(option_text(invocation, "crypto")?.unwrap_or("default"))
}

pub(crate) fn provider_by_name(name: &str) -> Result<&'static dyn CryptoProvider, CommandError> {
    match name {
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
    requested_names: &[impl AsRef<str>],
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
                .filter(|(_, (key, _))| key.parameter.as_deref() == Some(requested.as_ref()))
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
    requested_names: &[impl AsRef<str>],
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
    requested_names: &[impl AsRef<str>],
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
                .any(|requested| requested.as_ref() == name(entry))
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
    sign_with_policy(
        invocation,
        stdout,
        xmlsec_compatibility_signing_policy(invocation),
    )
}

/// Explicit private or symmetric key options accepted by `sign`.
const SIGNING_KEY_OPTIONS: &[&str] = &[
    "hmac-key",
    "privkey-pem",
    "privkey-der",
    "pkcs8-pem",
    "pkcs8-der",
    "pkcs12",
];

/// Key options must match the template: an encapsulation template takes a
/// recipient public key, any other template takes a signing key, and a key
/// store excludes explicit keys.
fn validate_sign_key_options(
    invocation: &Invocation,
    encapsulation: bool,
    has_key_store: bool,
) -> Result<(), CommandError> {
    if encapsulation {
        if let Some(option) = invocation.ordered_values(SIGNING_KEY_OPTIONS).next() {
            return Err(CommandError::Usage(format!(
                "--{} is inapplicable to sign with EncapsulationMechanism; supply a recipient public key",
                option.name
            )));
        }
    } else if let Some(option) = invocation
        .ordered_values(&["pubkey-pem", "pubkey-der"])
        .next()
    {
        return Err(CommandError::Usage(format!(
            "--{} is inapplicable to sign without EncapsulationMechanism",
            option.name
        )));
    }
    if has_key_store
        && invocation
            .ordered_values(SIGNING_KEY_OPTIONS)
            .next()
            .is_some()
    {
        return Err(CommandError::Usage(
            "sign cannot combine --keys-file with explicit key options".into(),
        ));
    }
    Ok(())
}

/// The signing key the template names in the key store, HMAC or asymmetric
/// by the template's signature method.
fn store_signing_candidate(
    invocation: &Invocation,
    store: &KeyInventory,
    signature: &key_material::SigningTemplateMetadata,
    policy: &SigningPolicy,
) -> Result<SigningKeyCandidate, CommandError> {
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
        store,
        candidates,
        signature.algorithm,
        signature.key_info.as_ref(),
        policy,
        lax_candidates,
        selected_provider(invocation)?,
    )
}

fn sign_with_policy(
    invocation: &Invocation,
    stdout: &mut dyn Write,
    policy: SigningPolicy,
) -> Result<(), CommandError> {
    validate_options(invocation, SIGN_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    let password = invocation.password_bytes();
    // This binary is an explicit libxmlsec1 compatibility boundary. Its sign
    // and verify commands must bind XPath here() identically for round trips.
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    // One parse serves the template metadata and the signing operation.
    let document = key_material::parse_operation_document(xml, &policy, xml_backend)?;
    let signature = key_material::signing_signature_metadata(
        &document,
        start_node_id,
        &id_attributes,
        &policy,
        xml_backend,
        selected_provider(invocation)?,
    )?;
    let has_key_store = invocation.values("keys-file").next().is_some();
    validate_sign_key_options(invocation, signature.encapsulation.is_some(), has_key_store)?;
    let mut external_budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    let encapsulated = signature
        .encapsulation
        .map(|algorithm| {
            select_encapsulation_key(
                invocation,
                &signature.key_names,
                algorithm,
                &policy.key_establishment,
                &policy,
                xml_backend,
                &mut external_budget,
            )
        })
        .transpose()?;
    let selected = if encapsulated.is_some() {
        None
    } else {
        Some(if has_key_store {
            if signature.key_names.is_empty() && !invocation.flag("lax-key-search") {
                return Err(CommandError::Usage(
                    "sign with --keys-file requires a template KeyName unless --lax-key-search is set"
                        .into(),
                ));
            }
            let store =
                load_xml_key_stores(invocation, &policy, xml_backend, &mut external_budget)?;
            store_signing_candidate(invocation, &store, &signature, &policy)?
        } else {
            select_signing_key(
                invocation,
                &signature.key_names,
                signature.algorithm,
                signature.key_info.as_ref(),
                &policy,
                password,
                &mut external_budget,
            )?
        })
    };
    let external_resources =
        load_mapped_reference_resources(invocation, &policy.resources, &mut external_budget)?;
    let mut context = match (&selected, &encapsulated) {
        (Some(selected), None) => SignContext::new(selected.key.as_ref()),
        (None, Some(key)) => SignContext::new_encapsulation(key.as_ref()),
        _ => return Err(CommandError::Usage("ambiguous signing key request".into())),
    }
    .provider(selected_provider(invocation)?)
    .policy(policy)
    .xml_backend(xml_backend)
    .signature_template_selection(SignatureTemplateSelection::FirstDescendant)
    .external_resources(&external_resources);
    if let Some(id) = start_node_id {
        context = context.start_node_id(id);
    }
    context = context.id_attributes(&id_attributes);
    if let Some(writer) = selected
        .as_ref()
        .and_then(|selected| selected.certificate_writer.as_ref())
        && signature.key_info.is_some()
    {
        context = context.key_info_writer(writer);
    }
    let signed = context
        .sign_template_document(document)
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
        key_establishment: xmlsec_compatibility_key_establishment_policy(),
        parameterized_rsa_pss: xml_sec::policy::RsaPssPermission::AllSupported,
        signature_algorithms: Some(BTreeSet::from(SignatureAlgorithm::ALL)),
        digest_algorithms: Some(BTreeSet::from(DigestAlgorithm::ALL)),
        manifest_processing: if invocation.flag("ignore-manifests") {
            ManifestProcessing::Ignore
        } else {
            ManifestProcessing::Process
        },
        transforms: TransformPolicy {
            xpath_here_semantics: XMLSEC_COMPATIBILITY_HERE_SEMANTICS,
            opc_relationship_edition: xml_sec::policy::OpcRelationshipEdition::Ecma2012,
            same_document_id_semantics: same_document_id_semantics(invocation),
            xslt_stylesheet_semantics: XMLSEC_COMPATIBILITY_XSLT_STYLESHEETS,
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
    if invocation.values("url-map").next().is_some() {
        policy.uris.references = UriTypeSet::ALL;
    }
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
    let mut parsing = xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&policy.resources)
        .map_err(certificate_signing_error)?;
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
                validate_signing_key_info(key_info, &candidate, provider, &mut parsing)?;
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
    material_budget: &mut ExternalMaterialBudget,
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
    let mut parsing = xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&policy.resources)
        .map_err(certificate_signing_error)?;
    for (option, ()) in candidates {
        let attempt = prepare_signing_key_candidate(
            option,
            algorithm,
            policy,
            password,
            material_budget,
            selected_provider(invocation)?,
        )
        .and_then(|candidate| {
            validate_signing_key_info(
                key_info,
                &candidate,
                selected_provider(invocation)?,
                &mut parsing,
            )?;
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

/// The PKCS#12 key, with a `KeyInfo` writer for its matching certificate
/// chain proven to describe that key.
fn pkcs12_signing_candidate(
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
    Ok(SigningKeyCandidate {
        key,
        certificate_writer,
        leaf_certificate_der: imported
            .matching_certificate_chain()
            .and_then(|chain| chain.first())
            .cloned(),
    })
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
        return pkcs12_signing_candidate(
            option,
            algorithm,
            policy,
            password,
            SigningKeyImport {
                material_budget,
                inventory,
                resources,
            },
            provider,
        );
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
            &key_material::PrivateKeyImport {
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
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
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
                    certificate_public_key(certificate, parsing, |spki| {
                        Some(spki) == public.spki_der()
                    })
                    .map_err(certificate_signing_error)?
                } else {
                    let certificate =
                        selected.leaf_certificate_der.as_deref().ok_or_else(|| {
                            signing_key_info_error(
                                "X509Data selectors require a signing certificate companion",
                            )
                        })?;
                    parsing
                        .certificate_matches_selectors(data, certificate, provider)
                        .map_err(certificate_signing_error)?
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
        key_establishment: xmlsec_compatibility_key_establishment_policy(),
        parameterized_rsa_pss: xml_sec::policy::RsaPssPermission::AllSupported,
        digest_algorithms: Some(BTreeSet::from(DigestAlgorithm::ALL)),
        // The compatibility executable explicitly permits every compiled XML
        // signature method, including experimental PQ methods. Library defaults
        // remain restrictive; provider capability still gates execution.
        signature_algorithms: Some(BTreeSet::from(SignatureAlgorithm::ALL)),
        manifest_processing: if invocation.flag("ignore-manifests") {
            ManifestProcessing::Ignore
        } else {
            ManifestProcessing::Process
        },
        uris: UriPolicy {
            references: UriTypeSet::ALL,
            // URL mappings authorize signed reference payloads, not key
            // material. Keep metadata URI permissions independent of them.
            retrieval_methods: UriTypeSet::SAME_DOCUMENT,
            key_info_references: UriTypeSet::SAME_DOCUMENT,
        },
        transforms: TransformPolicy {
            xpath_here_semantics: XMLSEC_COMPATIBILITY_HERE_SEMANTICS,
            opc_relationship_edition: xml_sec::policy::OpcRelationshipEdition::Ecma2012,
            same_document_id_semantics: same_document_id_semantics(invocation),
            xslt_stylesheet_semantics: XMLSEC_COMPATIBILITY_XSLT_STYLESHEETS,
            ..TransformPolicy::default()
        },
        ecdsa_signature_value_encoding: ecdsa_signature_value_encoding(invocation),
        ..VerificationPolicy::default()
    };
    policy.key_trust.allowed_legacy_signature_algorithms = BTreeSet::from([
        SignatureAlgorithm::RsaSha1,
        SignatureAlgorithm::RsaPssSha1,
        SignatureAlgorithm::DsaSha1,
        SignatureAlgorithm::HmacSha1,
        SignatureAlgorithm::EcdsaSha1,
    ]);
    policy.key_trust.parameterized_rsa_pss = xml_sec::policy::RsaPssPermission::AllSupported;
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

/// Private-key options that select a decapsulation recipient for `verify`.
const VERIFY_RECIPIENT_OPTIONS: &[&str] = &["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"];

/// The verification key sources requested on the command line.
struct VerifyKeyOptions<'a> {
    /// Explicit keys, each flagged when it is a certificate.
    explicit: Vec<(&'a crate::OptionValue, bool)>,
    has_key_store: bool,
    has_recipient_key: bool,
}

impl VerifyKeyOptions<'_> {
    /// Document `KeyName`s matter only when they can select among named keys.
    fn key_name_resolution(
        &self,
        lax_key_search: bool,
    ) -> key_material::VerificationKeyNameResolution {
        if lax_key_search
            || (self.explicit.is_empty() && !self.has_key_store && !self.has_recipient_key)
            || matches!(self.explicit.as_slice(), [(key, _)] if key.parameter.is_none())
        {
            key_material::VerificationKeyNameResolution::IgnoreDocumentKeyInfo
        } else {
            key_material::VerificationKeyNameResolution::ResolveDocumentKeyInfo
        }
    }
}

fn verify_key_options(invocation: &Invocation) -> Result<VerifyKeyOptions<'_>, CommandError> {
    let explicit = invocation
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
    let has_key_store = invocation.values("keys-file").next().is_some();
    if has_key_store && !explicit.is_empty() {
        return Err(CommandError::Usage(
            "verify cannot combine --keys-file with explicit key options".into(),
        ));
    }
    let has_recipient_key = invocation
        .ordered_values(VERIFY_RECIPIENT_OPTIONS)
        .next()
        .is_some();
    // With an explicit public key there is no key-manager search to relax.
    // Reject the flag on resolver-backed paths until its semantics exist.
    if invocation.flag("lax-key-search")
        && explicit.is_empty()
        && !has_key_store
        && !has_recipient_key
    {
        return Err(CommandError::UnsupportedOption("lax-key-search".into()));
    }
    Ok(VerifyKeyOptions {
        explicit,
        has_key_store,
        has_recipient_key,
    })
}

/// Decode explicit verification keys; lax search keeps going past
/// recoverable candidate failures and reports the last one if none loads.
fn explicit_verification_candidates(
    selected_keys: Vec<(&crate::OptionValue, bool)>,
    algorithm: SignatureAlgorithm,
    lax_key_search: bool,
    budget: &mut ExternalMaterialBudget,
) -> Result<Vec<ExplicitVerificationCandidate>, CommandError> {
    let mut candidates = Vec::with_capacity(selected_keys.len());
    let mut last_load_error = None;
    for (option, certificate) in selected_keys {
        let candidate = if option.name == "hmac-key" {
            (|| {
                let path = Path::new(option.value.as_deref().unwrap_or_default());
                let bytes = key_material::read(path)?;
                budget.charge(bytes.len())?;
                HmacVerificationKey::new(bytes)
                    .map(ExplicitVerificationCandidate::Hmac)
                    .map_err(|error| CommandError::Signature(error.to_string()))
            })()
        } else if certificate {
            load_explicit_certificate_key_info(option, budget)
                .map(ExplicitVerificationCandidate::Certificate)
        } else {
            (|| {
                let path = Path::new(option.value.as_deref().unwrap_or_default());
                let bytes = key_material::read(path)?;
                budget.charge(bytes.len())?;
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
    Ok(candidates)
}

/// Key-store verification candidates: HMAC keys for an HMAC method,
/// otherwise public keys with their `KeyInfo`.
fn stored_verification_candidates(
    stored_keys: &KeyInventory,
    key_names: &[String],
    algorithm: SignatureAlgorithm,
    lax_key_search: bool,
    resources: &ResourcePolicy,
) -> Result<Vec<ExplicitVerificationCandidate>, CommandError> {
    let mut budget = KeyCandidateBudget::with_limit(resources.max_key_candidates);
    if algorithm.hmac_output_bits().is_some() {
        let selected = select_store_candidates(
            stored_keys.symmetric_keys().iter().filter(|entry| {
                entry.kind == SymmetricKeyKind::Hmac
                    && entry.usages.allows(key_manager::KeyUsage::Verify)
            }),
            key_names,
            lax_key_search,
            resources.max_key_candidates,
            |entry| &entry.name,
        )?;
        budget
            .consume(selected.len())
            .map_err(|error| CommandError::Signature(error.to_string()))?;
        return selected
            .into_iter()
            .map(|entry| {
                HmacVerificationKey::new(entry.bytes.to_vec())
                    .map(ExplicitVerificationCandidate::Hmac)
                    .map_err(|error| CommandError::Signature(error.to_string()))
            })
            .collect();
    }
    let selected = select_store_candidates(
        stored_keys
            .public_keys()
            .iter()
            .filter(|entry| entry.usages.allows(key_manager::KeyUsage::Verify)),
        key_names,
        lax_key_search,
        resources.max_key_candidates,
        |entry| &entry.name,
    )?;
    budget
        .consume(selected.len())
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    Ok(selected
        .into_iter()
        .map(|entry| ExplicitVerificationCandidate::Certificate(entry.key_info.clone()))
        .collect())
}

/// Where `verify` obtains its key: a decapsulation recipient, selected
/// candidates, or the configured certificate resolver.
enum VerificationKeySource {
    Decapsulation(std::sync::Arc<dyn xml_sec::provider::KeyDecapsulationKey>),
    Candidates(CandidateVerificationResolver),
    Certificates(DefaultKeyResolver),
}

/// Key material already selected or loaded for one verification.
struct VerificationKeyInputs<'a> {
    selected_keys: Vec<(&'a crate::OptionValue, bool)>,
    has_key_store: bool,
    stored_keys: &'a KeyInventory,
    configured_certificates: ConfiguredCertificates,
}

/// Decapsulation for an encapsulation signature, otherwise explicit keys
/// before key-store entries, otherwise the configured certificate resolver.
fn verification_key_source(
    invocation: &Invocation,
    signature: &key_material::SignatureMetadata,
    inputs: VerificationKeyInputs<'_>,
    policy: &VerificationPolicy,
    budget: &mut ExternalMaterialBudget,
) -> Result<VerificationKeySource, CommandError> {
    let VerificationKeyInputs {
        selected_keys,
        has_key_store,
        stored_keys,
        configured_certificates,
    } = inputs;
    let lax_key_search = invocation.flag("lax-key-search");
    if let Some(algorithm) = signature.encapsulation {
        if !selected_keys.is_empty() {
            return Err(CommandError::Usage("encapsulation verification requires a recipient private key, not --hmac-key or a signing public key".into()));
        }
        return Ok(VerificationKeySource::Decapsulation(
            select_decapsulation_key(
                invocation,
                &signature.key_names,
                algorithm,
                &policy.key_establishment,
                policy,
                budget,
            )?,
        ));
    }
    if selected_keys.is_empty() && !has_key_store {
        return Ok(VerificationKeySource::Certificates(
            DefaultKeyResolver::new(configured_certificates.into_resolver_config()),
        ));
    }
    let candidates = if selected_keys.is_empty() {
        stored_verification_candidates(
            stored_keys,
            &signature.key_names,
            signature.algorithm,
            lax_key_search,
            &policy.resources,
        )?
    } else {
        explicit_verification_candidates(
            selected_keys,
            signature.algorithm,
            lax_key_search,
            budget,
        )?
    };
    Ok(VerificationKeySource::Candidates(
        CandidateVerificationResolver::new(
            candidates,
            configured_certificates,
            lax_key_search,
            policy.key_trust.check_crls,
        ),
    ))
}

fn verify(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, VERIFY_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    reject_unimplemented_verification_policy(invocation)?;
    let key_options = verify_key_options(invocation)?;
    let lax_key_search = invocation.flag("lax-key-search");
    let policy = xmlsec_compatibility_verification_policy(invocation);
    let mut certificate_budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    let utc_facts = UtcFacts::load(invocation, &policy.resources, &mut certificate_budget)?;
    let utc_table = utc_facts.as_ref().map(UtcFacts::table).transpose()?;
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let start_node_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let key_name_resolution = key_options.key_name_resolution(lax_key_search);
    let VerifyKeyOptions {
        explicit: explicit_keys,
        has_key_store,
        ..
    } = key_options;
    // One parse serves signature selection, key metadata and verification.
    let document = key_material::parse_operation_document(xml, &policy, xml_backend)?;
    let signature = key_material::verification_signature_metadata(
        &document,
        start_node_id,
        &id_attributes,
        &policy,
        key_name_resolution,
        xml_backend,
        selected_provider(invocation)?,
    )?;
    if signature.encapsulation.is_none()
        && let Some(option) = invocation.ordered_values(VERIFY_RECIPIENT_OPTIONS).next()
    {
        return Err(CommandError::Usage(format!(
            "--{} is inapplicable to verify without EncapsulationMechanism",
            option.name
        )));
    }
    let selected_keys = if explicit_keys.is_empty() {
        Vec::new()
    } else {
        let names = &signature.key_names;
        named_candidate_search(
            &explicit_keys,
            names,
            lax_key_search,
            true,
            "verification key",
        )?
    };
    validate_verification_candidate_count(selected_keys.len(), &policy)
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    let external_resources =
        load_mapped_reference_resources(invocation, &policy.resources, &mut certificate_budget)?;
    let configured_certificates = load_configured_certificates(
        invocation,
        selected_keys.is_empty(),
        &mut certificate_budget,
    )?;
    // Recipient selection owns its inventory import and aggregate budget;
    // loading the same store here would decode and charge it twice.
    let stored_keys = if signature.encapsulation.is_some() {
        KeyInventory::default()
    } else {
        load_xml_key_stores(invocation, &policy, xml_backend, &mut certificate_budget)?
    };
    let key_source = verification_key_source(
        invocation,
        &signature,
        VerificationKeyInputs {
            selected_keys,
            has_key_store,
            stored_keys: &stored_keys,
            configured_certificates,
        },
        &policy,
        &mut certificate_budget,
    )?;
    let context = verification_context(
        policy,
        start_node_id,
        &id_attributes,
        xml_backend,
        utc_table,
    )
    .external_resources(&external_resources)
    .provider(selected_provider(invocation)?);
    let context = match &key_source {
        VerificationKeySource::Decapsulation(key) => context.decapsulation_key(key.as_ref()),
        VerificationKeySource::Candidates(resolver) => context.key_resolver(resolver),
        VerificationKeySource::Certificates(resolver) => context.key_resolver(resolver),
    };
    let result = context
        .verify_parsed(&document)
        .map_err(|error| CommandError::Signature(error.to_string()))?;
    write_verification_diagnostics(invocation, &result, stdout)?;
    if aggregate_verification_status(&result) != DsigStatus::Valid {
        return Err(CommandError::InvalidSignature);
    }
    Ok(())
}

pub(super) struct ExternalMaterialBudget {
    total_bytes: usize,
    maximum_bytes: usize,
    kdf_work: usize,
}

fn load_mapped_reference_resources(
    invocation: &Invocation,
    resources: &ResourcePolicy,
    budget: &mut ExternalMaterialBudget,
) -> Result<BTreeMap<String, Vec<u8>>, CommandError> {
    // libxmlsec1's --url-map:<url> <file> is an exact mapping. Only these
    // explicit files are acquired; unmapped document URIs never cause I/O.
    // Payload is moved once into the map and borrowed by every reference.
    let mut mapped = BTreeMap::new();
    for option in invocation.values("url-map") {
        let uri = option
            .parameter
            .as_deref()
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| {
                CommandError::Usage("--url-map requires a non-empty :URL parameter".into())
            })?;
        if mapped.contains_key(uri) {
            return Err(CommandError::Usage(format!(
                "duplicate --url-map for {uri}"
            )));
        }
        let path = Path::new(option.value.as_deref().unwrap_or_default());
        let mut file = File::open(path).map_err(|source| CommandError::Io {
            path: path.to_owned(),
            source,
        })?;
        let mut bytes = Vec::new();
        let length = file
            .metadata()
            .map_err(|source| CommandError::Io {
                path: path.to_owned(),
                source,
            })?
            .len();
        let maximum = resources
            .max_external_resource_bytes
            .min(budget.remaining());
        let length = usize::try_from(length)
            .ok()
            .filter(|length| *length <= maximum)
            .ok_or(CommandError::ExternalMaterialTooLarge { maximum })?;
        // Metadata sizes the normal regular-file path once. It is only a hint:
        // subsequent reads still enforce limits if the file grows concurrently.
        budget.charge(length)?;
        bytes.try_reserve_exact(length).map_err(|_| {
            CommandError::Signature("unable to allocate mapped reference bytes".into())
        })?;
        let mut chunk = [0_u8; 8192];
        loop {
            let slack = bytes.capacity() - bytes.len();
            let remaining = resources
                .max_external_resource_bytes
                .saturating_sub(bytes.len())
                .min(slack.saturating_add(budget.remaining()));
            let count = file
                .read(&mut chunk[..remaining.saturating_add(1).min(8192)])
                .map_err(|source| CommandError::Io {
                    path: path.to_owned(),
                    source,
                })?;
            if count == 0 {
                break;
            }
            if count > remaining {
                return Err(CommandError::ExternalMaterialTooLarge {
                    maximum: resources
                        .max_external_resource_bytes
                        .min(budget.maximum_bytes),
                });
            }
            // Check and charge before growing, not after read_to_end has already
            // allocated. The one-byte overflow probe lives only on the stack.
            if count > slack {
                let old_capacity = bytes.capacity();
                let needed = bytes.len() + count;
                let capacity = old_capacity
                    .saturating_mul(2)
                    .max(8192)
                    .max(needed)
                    .min(resources.max_external_resource_bytes)
                    .min(budget.remaining());
                if capacity < needed {
                    return Err(CommandError::ExternalMaterialTooLarge {
                        maximum: budget.maximum_bytes,
                    });
                }
                // Both allocations can be live during realloc. Charge the new
                // capacity first, then release the old charge after growth.
                budget.charge(capacity)?;
                bytes
                    .try_reserve_exact(capacity - bytes.len())
                    .map_err(|_| {
                        CommandError::Signature("unable to allocate mapped reference bytes".into())
                    })?;
                budget.total_bytes -= old_capacity;
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        mapped.insert(uri.to_owned(), bytes);
    }
    Ok(mapped)
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
    pub(super) fn new(maximum_bytes: usize) -> Self {
        Self {
            total_bytes: 0,
            maximum_bytes,
            kdf_work: 0,
        }
    }

    pub(super) fn charge(&mut self, bytes: usize) -> Result<(), CommandError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum_bytes)
            .ok_or(CommandError::ExternalMaterialTooLarge {
                maximum: self.maximum_bytes,
            })?;
        Ok(())
    }

    pub(super) fn remaining(&self) -> usize {
        self.maximum_bytes - self.total_bytes
    }

    pub(super) fn maximum(&self) -> usize {
        self.maximum_bytes
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
    import: &key_material::PrivateKeyImport<'_>,
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
        &key_material::PrivateKeyImport {
            resources: &remaining,
            ..*import
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
        CommandError::Policy(_)
            | CommandError::ExternalMaterialTooLarge { .. }
            | CommandError::KeyStore(
                key_manager::KeyStoreError::ProtectedContainer
                    | key_manager::KeyStoreError::Policy(_)
            )
            | CommandError::Key(
                key_material::KeyMaterialError::ProtectedContainer
                    | key_material::KeyMaterialError::PrivateKeyComponents(_)
                    | key_material::KeyMaterialError::Policy(_)
            )
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
        DsigStatus::Invalid(
            FailureReason::ReferenceDigestMismatch { .. }
            | FailureReason::ReferencePolicyViolation { .. }
            | FailureReason::ReferenceProcessingFailure { .. }
            | FailureReason::ReferenceUnavailable { .. },
        ) => ("FAILED", "REFERENCE"),
        DsigStatus::Invalid(FailureReason::SignatureMismatch) => ("FAILED", "SIGNATURE"),
        DsigStatus::Invalid(FailureReason::KeyNotFound) => ("FAILED", "KEY-NOT-FOUND"),
        // Includes an unprocessed Reference: libxmlsec1's xmlSecDSigStatusUnknown,
        // which xmlSecDSigCtxGetStatusString renders as "ERROR".
        _ => ("ERROR", "UNKNOWN"),
    }
}

fn verification_context<'a>(
    policy: VerificationPolicy,
    start_node_id: Option<&'a str>,
    id_attributes: &'a [IdAttributeRegistration],
    xml_backend: XmlBackend,
    utc_facts: Option<structured_pkix::temporal::LeapTable<'a>>,
) -> VerifyContext<'a> {
    let context = VerifyContext::new()
        .policy(policy)
        .xml_backend(xml_backend)
        .id_attributes(id_attributes);
    let context = match utc_facts {
        Some(facts) => context.utc_facts(facts),
        None => context,
    };
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

impl CandidateVerificationResolver {
    fn resolve_candidates<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &VerificationPolicy,
        provider: &dyn CryptoProvider,
        candidate_budget: &mut InspectedKeyCandidateBudget<'_>,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        validate_verification_candidate_count(self.candidates.len(), policy)?;
        policy.validate()?;
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
                        candidate_budget,
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
                match key.validate_policy(&candidate_budget.verification_scope(policy)) {
                    Ok(()) => resolved.push(key),
                    Err(error) if self.lax_key_search && !matches!(error, DsigError::Policy(_)) => {
                        last_error = Some(error);
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
        self.resolve_candidates(
            key_info,
            algorithm,
            policy,
            provider,
            &mut InspectedKeyCandidateBudget::new(policy),
        )
    }

    fn resolve_for_verification_with_budget<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &VerificationPolicy,
        provider: &dyn CryptoProvider,
        budget: &mut InspectedKeyCandidateBudget<'_>,
    ) -> Result<Option<xml_sec::xmldsig::ResolvedVerificationKey<'a>>, DsigError> {
        // Carry the operation's UTC facts and account into explicit candidates,
        // rather than restarting a certificate execution domain in this adapter.
        self.resolve_candidates(key_info, algorithm, policy, provider, budget)
            .map(|key| key.map(xml_sec::xmldsig::ResolvedVerificationKey::CallerTrusted))
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
        scope: &VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.first_accepting(|candidate| {
            candidate.validate_signature_value_with_policy(scope, algorithm, signature_value)
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
        scope: &VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        context: &xml_sec::xmldsig::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.first_accepting(|candidate| {
            candidate.verify_with_policy(scope, algorithm, context, signed_data, signature_value)
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

/// One `encrypt` invocation's selected template, policy and backends.
struct EncryptCommand<'a> {
    invocation: &'a Invocation,
    template: &'a str,
    start_node_id: Option<&'a str>,
    id_attributes: &'a [IdAttributeRegistration],
    policy: &'a EncryptionPolicy,
    xml_backend: XmlBackend,
    provider: &'a dyn CryptoProvider,
}

impl EncryptCommand<'_> {
    fn lax(&self) -> bool {
        self.invocation.flag("lax-key-search")
    }

    /// A fresh aggregate budget for one key-selection path's external material.
    fn material_budget(&self) -> ExternalMaterialBudget {
        ExternalMaterialBudget::new(self.policy.resources.max_external_resource_total_bytes)
    }

    /// Charge `count` key candidates against the operation's candidate limit.
    fn charge_candidates(&self, count: usize) -> Result<(), CommandError> {
        KeyCandidateBudget::with_limit(self.policy.resources.max_key_candidates)
            .consume(count)
            .map_err(|error| CommandError::Encryption(error.to_string()))
    }

    fn recipient_metadata(
        &self,
        recipients: usize,
        parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
    ) -> Result<Vec<Option<ParsedRecipientKeyMetadata>>, CommandError> {
        recipient_key_metadata(
            self.template,
            self.start_node_id,
            self.id_attributes,
            self.policy,
            recipients,
            CommandBackends {
                xml: self.xml_backend,
                crypto: self.provider,
            },
            parsing,
        )
    }
}

/// Template recipients, or one unnamed transport recipient for a template
/// that declares none.
fn recipients_or_default(
    recipients: Vec<EncryptionTemplateRecipient>,
) -> Vec<EncryptionTemplateRecipient> {
    if recipients.is_empty() {
        vec![EncryptionTemplateRecipient {
            key_name: None,
            transport: None,
            wrap: None,
            oaep_parameters: None,
        }]
    } else {
        recipients
    }
}

/// The first explicit symmetric key whose kind and length fit the content
/// algorithm, named as the template's content key requests.
fn explicit_content_key(
    command: &EncryptCommand<'_>,
    builder: EncryptedDataBuilder,
    keys: &[&crate::OptionValue],
    names: &[String],
    algorithm: DataEncryptionAlgorithm,
) -> Result<EncryptedDataBuilder, CommandError> {
    let candidates = keys
        .iter()
        .copied()
        .map(|option| (option, ()))
        .collect::<Vec<_>>();
    let candidates =
        named_candidate_search(&candidates, names, command.lax(), true, "symmetric key")?;
    command.charge_candidates(candidates.len())?;
    let mut material_budget = command.material_budget();
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
                let builder = builder.direct_key(key);
                return Ok(match option.parameter.as_deref() {
                    Some(name) => builder.direct_key_name(name),
                    None => builder,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| CommandError::Usage("no compatible symmetric key input".into())))
}

/// The first key-store symmetric key whose kind and length fit the content
/// algorithm, named as the template's content key requests.
fn stored_content_key(
    command: &EncryptCommand<'_>,
    builder: EncryptedDataBuilder,
    names: &[String],
    algorithm: DataEncryptionAlgorithm,
) -> Result<EncryptedDataBuilder, CommandError> {
    let store = load_xml_key_stores(
        command.invocation,
        command.policy,
        command.xml_backend,
        &mut command.material_budget(),
    )?;
    let candidates = select_store_candidates(
        store.symmetric_keys().iter().filter(|entry| {
            symmetric_kind_accepts(entry.kind, algorithm)
                && entry.usages.allows(key_manager::KeyUsage::Encrypt)
        }),
        names,
        command.lax(),
        command.policy.resources.max_key_candidates,
        |entry| &entry.name,
    )?;
    command.charge_candidates(candidates.len())?;
    let selected = candidates
        .into_iter()
        .find(|entry| entry.bytes.len() == algorithm.key_len())
        .ok_or_else(|| CommandError::Usage("no compatible symmetric key in --keys-file".into()))?;
    let key = key_material::decode_symmetric(selected.bytes.to_vec(), Some(algorithm.key_len()))?;
    Ok(builder.direct_key(key).direct_key_name(&selected.name))
}

/// Encryption-capable key-store public keys by name, with lax-search
/// reservations and decoded candidates shared across template recipients.
struct StoreRecipientPool<'s> {
    store: &'s KeyInventory,
    available: HashMap<&'s str, AvailableStoreRecipient<'s>>,
    only_public_key: Option<&'s key_manager::StoredPublicKey>,
    public_key_count: usize,
}

impl<'s> StoreRecipientPool<'s> {
    fn new(store: &'s KeyInventory) -> Self {
        let mut available = HashMap::new();
        let mut only_public_key = None;
        let mut public_key_count = 0;
        for entry in store
            .public_keys()
            .iter()
            .filter(|entry| entry.usages.allows(key_manager::KeyUsage::Encrypt))
        {
            public_key_count += 1;
            only_public_key = Some(entry);
            available.insert(
                entry.name.as_str(),
                AvailableStoreRecipient {
                    entry,
                    reservations: 0,
                    loaded: None,
                },
            );
        }
        Self {
            store,
            available,
            only_public_key,
            public_key_count,
        }
    }

    /// Reserve each named recipient's entry before any fallback assignment,
    /// returning whether each template slot holds a reservation.
    fn reserve_named(
        &mut self,
        command: &EncryptCommand<'_>,
        recipients: &[EncryptionTemplateRecipient],
        metadata: &[Option<ParsedRecipientKeyMetadata>],
        budget: &mut KeyCandidateBudget,
        parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
    ) -> Result<Vec<bool>, CommandError> {
        let mut reserved_slots = Vec::with_capacity(recipients.len());
        // A stale name contradicted by recipient metadata is not an exact
        // match. Cache decoded candidates so reservation checks do not
        // repeat RSA decoding during assignment; names remain borrowed.
        for (recipient, metadata) in recipients.iter().zip(metadata) {
            let mut reserved = false;
            if let Some(name) = recipient.key_name.as_deref()
                && let Some(available) = self.available.get_mut(name)
            {
                if metadata.as_ref().is_some_and(|metadata| {
                    metadata
                        .0
                        .sources
                        .iter()
                        .any(|source| !matches!(source, KeyInfoSource::KeyName(_)))
                }) {
                    if available.loaded.is_none() {
                        budget
                            .consume(1)
                            .map_err(|error| CommandError::Encryption(error.to_string()))?;
                        match load_stored_recipient_candidate(available.entry, command.policy) {
                            Ok(candidate) => available.loaded = Some(candidate),
                            Err(
                                error @ CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                                    _,
                                )),
                            ) => return Err(error),
                            Err(_) => {}
                        }
                    }
                    if let Some(candidate) = available.loaded.as_ref() {
                        reserved = match validate_recipient_key_metadata(
                            metadata.as_ref(),
                            candidate,
                            command.provider,
                            parsing,
                        ) {
                            Ok(()) => true,
                            Err(error) if lax_candidate_error_is_recoverable(&error) => false,
                            Err(error) => return Err(error),
                        };
                    }
                } else {
                    reserved = true;
                }
                if reserved {
                    available.reservations += 1;
                }
            }
            reserved_slots.push(reserved);
        }
        Ok(reserved_slots)
    }

    /// The exact entry for one recipient, or under lax search the first
    /// unreserved entry whose key matches the recipient metadata.
    fn select(
        &mut self,
        command: &EncryptCommand<'_>,
        key_name: Option<&str>,
        metadata: Option<&ParsedRecipientKeyMetadata>,
        reserved: bool,
        budget: &mut KeyCandidateBudget,
        parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
    ) -> Result<
        (
            &'s key_manager::StoredPublicKey,
            RecipientPublicKeyCandidate,
        ),
        CommandError,
    > {
        let lax = command.lax();
        let exact = match key_name {
            Some(name) => self.available.get(name).map(|available| available.entry),
            None if self.public_key_count == 1 => self.only_public_key.and_then(|entry| {
                self.available
                    .get(entry.name.as_str())
                    .filter(|available| !lax || available.reservations == 0)
                    .map(|available| available.entry)
            }),
            None if !lax && self.public_key_count > 1 => {
                return Err(CommandError::Usage(
                    "multiple matching keys in --keys-file".into(),
                ));
            }
            None => None,
        };
        if exact.is_none() && !lax {
            return Err(CommandError::Usage("no matching key in --keys-file".into()));
        }
        let fallbacks = self.store.public_keys().iter().filter(|entry| {
            lax && entry.usages.allows(key_manager::KeyUsage::Encrypt)
                && !exact.is_some_and(|selected| std::ptr::eq(selected, *entry))
        });
        let mut last_error = None;
        for entry in exact.into_iter().chain(fallbacks) {
            let is_exact = exact.is_some_and(|selected| std::ptr::eq(selected, entry));
            if !is_exact
                && self
                    .available
                    .get(entry.name.as_str())
                    .is_none_or(|available| available.reservations != 0)
            {
                continue;
            }
            let cached = self
                .available
                .get_mut(entry.name.as_str())
                .and_then(|available| available.loaded.take());
            // Reservation already charged decoding for a retained candidate.
            // Charge new inspections before work, not movement out of the cache.
            let candidate = if let Some(candidate) = cached {
                Ok(candidate)
            } else {
                budget
                    .consume(1)
                    .map_err(|error| CommandError::Encryption(error.to_string()))?;
                load_stored_recipient_candidate(entry, command.policy)
            }
            .and_then(|candidate| {
                // This exact slot was checked against immutable metadata
                // before reservation. Do not repeat its conversions.
                if !(lax && reserved && is_exact) {
                    validate_recipient_key_metadata(
                        metadata,
                        &candidate,
                        command.provider,
                        parsing,
                    )?;
                }
                Ok(candidate)
            });
            match candidate {
                Ok(candidate) => return Ok((entry, candidate)),
                Err(error) if !lax_candidate_error_is_recoverable(&error) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| CommandError::Usage("no compatible RSA key in --keys-file".into())))
    }
}

/// RSA transport recipients for every template recipient from the key store.
fn stored_rsa_recipients(
    command: &EncryptCommand<'_>,
    mut builder: EncryptedDataBuilder,
    recipients: Vec<EncryptionTemplateRecipient>,
) -> Result<EncryptedDataBuilder, CommandError> {
    let store = load_xml_key_stores(
        command.invocation,
        command.policy,
        command.xml_backend,
        &mut command.material_budget(),
    )?;
    let mut parsing =
        xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&command.policy.resources)
            .map_err(certificate_command_error)?;
    let recipients = recipients_or_default(recipients);
    command.charge_candidates(recipients.len())?;
    let metadata = command.recipient_metadata(recipients.len(), &mut parsing)?;
    let mut budget = KeyCandidateBudget::with_limit(command.policy.resources.max_key_candidates);
    let mut pool = StoreRecipientPool::new(&store);
    let lax = command.lax();
    let reserved_slots = if lax {
        pool.reserve_named(command, &recipients, &metadata, &mut budget, &mut parsing)?
    } else {
        Vec::new()
    };
    for (slot, (recipient, metadata)) in recipients.into_iter().zip(metadata).enumerate() {
        let reserved = lax && reserved_slots[slot];
        if reserved
            && let Some(name) = recipient.key_name.as_deref()
            && let Some(available) = pool.available.get_mut(name)
        {
            available.reservations -= 1;
        }
        let (entry, candidate) = pool.select(
            command,
            recipient.key_name.as_deref(),
            metadata.as_ref(),
            reserved,
            &mut budget,
            &mut parsing,
        )?;
        // Lax recipient search assigns each available entry once, as the
        // explicit-key path does. Keep store order for subsequent fallbacks.
        if lax {
            pool.available.remove(entry.name.as_str());
        }
        let mut configured =
            configured_template_recipient(candidate.public_key, recipient.transport)
                .key_name(&entry.name);
        if let Some(parameters) = recipient.oaep_parameters {
            configured = configured.oaep_parameters(parameters);
        }
        builder = builder.add_recipient(configured);
    }
    Ok(builder)
}

/// Explicit RSA keys and certificates already decoded for this command,
/// keyed by option identity.
type LoadedRecipientKeys =
    HashMap<*const crate::OptionValue, Result<RecipientPublicKeyCandidate, String>>;

/// The first available explicit RSA key, named as the recipient requests,
/// whose key matches the recipient metadata.
fn select_explicit_rsa_recipient<'o>(
    command: &EncryptCommand<'_>,
    available: &[(&'o crate::OptionValue, bool)],
    names: &[String],
    metadata: Option<&ParsedRecipientKeyMetadata>,
    loaded: &mut LoadedRecipientKeys,
    budget: &mut ExternalMaterialBudget,
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
) -> Result<(&'o crate::OptionValue, bool, RsaPublicKey), CommandError> {
    let candidates =
        named_candidate_search(available, names, command.lax(), true, "RSA recipient key")?;
    let mut last_error = None;
    for (option, certificate) in candidates {
        match cached_rsa_recipient_candidate(loaded, option, certificate, command.policy, budget)
            .and_then(|key| {
                validate_recipient_key_metadata(metadata, &key, command.provider, parsing)?;
                Ok(key)
            }) {
            Ok(key) => return Ok((option, certificate, key.public_key)),
            Err(error) if !lax_candidate_error_is_recoverable(&error) => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| CommandError::Usage("no compatible RSA recipient key input".into())))
}

/// RSA transport recipients for every template recipient from explicit keys;
/// lax search assigns each explicit key at most once.
fn explicit_rsa_recipients(
    command: &EncryptCommand<'_>,
    mut builder: EncryptedDataBuilder,
    recipients: Vec<EncryptionTemplateRecipient>,
    public_keys: &[(&crate::OptionValue, bool)],
) -> Result<EncryptedDataBuilder, CommandError> {
    let mut parsing =
        xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&command.policy.resources)
            .map_err(certificate_command_error)?;
    let recipients = recipients_or_default(recipients);
    let lax_key_search = command.lax();
    let mut available = public_keys.to_vec();
    if lax_key_search {
        command.charge_candidates(available.len())?;
    }
    let mut loaded = LoadedRecipientKeys::new();
    let mut certificate_budget = command.material_budget();
    let mut selected_recipients = Vec::with_capacity(recipients.len());
    let metadata = command.recipient_metadata(recipients.len(), &mut parsing)?;
    for (recipient, metadata) in recipients.into_iter().zip(metadata) {
        let (option, certificate, public_key) = select_explicit_rsa_recipient(
            command,
            &available,
            recipient.key_name.as_slice(),
            metadata.as_ref(),
            &mut loaded,
            &mut certificate_budget,
            &mut parsing,
        )?;
        if lax_key_search {
            let index = available
                .iter()
                .position(|(candidate, candidate_certificate)| {
                    std::ptr::eq(*candidate, option) && *candidate_certificate == certificate
                })
                .ok_or_else(|| {
                    CommandError::Encryption(
                        "selected recipient key is absent from the candidate set".into(),
                    )
                })?;
            available.remove(index);
        }
        let key_name = recipient.key_name.or_else(|| option.parameter.clone());
        selected_recipients.push((
            public_key,
            recipient.transport,
            recipient.oaep_parameters,
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
    Ok(builder)
}

/// The key requirements a template declares for its content key.
struct EncryptionKeyRequest {
    encapsulation: Option<(xml_sec::provider::KeyEncapsulationAlgorithm, Vec<String>)>,
    has_encrypted_key_recipient: bool,
    recipients: Vec<EncryptionTemplateRecipient>,
    content_key_name: Option<String>,
    algorithm: DataEncryptionAlgorithm,
}

/// Configure the encapsulation, wrapping, direct or transport keys the
/// template and the key options together select.
fn configure_encryption_keys(
    command: &EncryptCommand<'_>,
    builder: EncryptedDataBuilder,
    request: EncryptionKeyRequest,
) -> Result<EncryptedDataBuilder, CommandError> {
    let invocation = command.invocation;
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
    let names = request.content_key_name.as_slice();
    if let Some((algorithm, names)) = &request.encapsulation {
        if !aes_keys.is_empty() || request.has_encrypted_key_recipient {
            return Err(CommandError::Usage("direct EncapsulationMechanism cannot be combined with raw symmetric keys or EncryptedKey recipients".into()));
        }
        let key = select_encapsulation_key(
            invocation,
            names,
            *algorithm,
            &command.policy.key_establishment,
            command.policy,
            command.xml_backend,
            &mut command.material_budget(),
        )?;
        Ok(builder.encapsulation_key(key))
    } else if request
        .recipients
        .iter()
        .any(|recipient| recipient.wrap.is_some())
    {
        configure_wrapping_recipients(
            builder,
            &request.recipients,
            invocation,
            &aes_keys,
            command.policy,
            command.xml_backend,
        )
    } else if !aes_keys.is_empty() {
        if request.has_encrypted_key_recipient {
            return Err(CommandError::Usage(
                "direct AES key cannot satisfy an EncryptedKey recipient in the template".into(),
            ));
        }
        explicit_content_key(command, builder, &aes_keys, names, request.algorithm)
    } else if has_key_store && !request.has_encrypted_key_recipient {
        stored_content_key(command, builder, names, request.algorithm)
    } else if has_key_store {
        stored_rsa_recipients(command, builder, request.recipients)
    } else if !public_keys.is_empty() {
        explicit_rsa_recipients(command, builder, request.recipients, &public_keys)
    } else {
        Err(CommandError::Usage(
            "encrypt requires --aes-key, an RSA public key, or an RSA certificate".into(),
        ))
    }
}

fn encrypt(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    let provider = selected_provider(invocation)?;
    validate_options(invocation, ENCRYPT_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(
        invocation,
        &["node-id", "node-name", "id-attr", "add-id-attr"],
    )?;
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
    let id_attributes = id_attribute_registrations(invocation)?;
    // libxmlsec1 fills the first EncryptedData of the template and resolves --node-id or
    // --node-name in the --xml-data document (apps/xmlsec.c, xmlSecAppEncryptTmpl,
    // xmlSecAppXmlDataCreate).
    let metadata = encryption_template(&template, None, &id_attributes, &policy, xml_backend)?;
    check_session_key(
        invocation,
        metadata.algorithm,
        metadata.has_encrypted_key_recipient,
    )?;
    let algorithm = metadata.algorithm;
    let encrypted_type = metadata.encrypted_type;
    let explicit_xml_type = metadata.explicit_xml_type;
    let template_placement = metadata.placement;
    let mut builder = EncryptedDataBuilder::new(algorithm)
        .provider(shared_provider(provider)?)
        .policy(policy.clone())
        .xml_backend(xml_backend);
    if let Some(parameters) = metadata.chacha {
        builder = builder.chacha_parameters(parameters);
    }
    let command = EncryptCommand {
        invocation,
        template: &template,
        start_node_id: None,
        id_attributes: &id_attributes,
        policy: &policy,
        xml_backend,
        provider,
    };
    builder = configure_encryption_keys(
        &command,
        builder,
        EncryptionKeyRequest {
            encapsulation: metadata.encapsulation,
            has_encrypted_key_recipient: metadata.has_encrypted_key_recipient,
            recipients: metadata.recipients,
            content_key_name: metadata.content_key_name,
            algorithm,
        },
    )?;
    builder = builder.encryption_type(encrypted_type.clone());
    let data = invocation
        .last_value("xml-data")
        .map(|path| read_xml_data(path, maximum_document_bytes))
        .transpose()?;
    let data_document = data
        .as_deref()
        .map(|data| parse_encryption_document(data, policy.xml, &policy.resources, xml_backend))
        .transpose()?;
    let target = data_document
        .as_ref()
        .map(|document| xml_data_target(document, invocation, &id_attributes))
        .transpose()?;
    let result = if let Some(path) = invocation.last_value("binary-data") {
        ensure_binary_template(template_placement, explicit_xml_type)?;
        let data = read_plaintext(path, maximum_plaintext_bytes)?;
        builder.encrypt_binary(&data)
    } else if let (Some(data), Some(target)) = (data.as_deref(), target) {
        let plaintext = xml_data_plaintext(data, target, &encrypted_type, &policy)?;
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
        None,
        &id_attributes,
        &policy,
        xml_backend,
    )?;
    // The filled EncryptedData replaces the selected data node (Element) or its children
    // (Content), and the data document is the result.
    let rendered = match (data.as_deref(), target) {
        (Some(data), Some(target)) => {
            place_encrypted_data(&command, data, target, &encrypted_type, &rendered)?
        }
        _ => rendered,
    };
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

fn shared_provider(
    provider: &dyn xml_sec::provider::CryptoProvider,
) -> Result<std::sync::Arc<dyn xml_sec::provider::CryptoProvider>, CommandError> {
    Ok(match provider.name() {
        "rustcrypto" => std::sync::Arc::new(xml_sec::provider::RustCryptoProvider),
        #[cfg(feature = "aws-lc-fips")]
        "aws-lc-fips" => std::sync::Arc::new(xml_sec::provider::AwsLcFipsProvider),
        name => return Err(CommandError::UnsupportedProvider(name.to_owned())),
    })
}

/// libxmlsec1 `--session-key` generates the content key of the named type, and the template's
/// `EncryptedKey` recipients transport it. The content key is always fresh here, so the option
/// only has to agree with the template algorithm and have a recipient to carry it.
fn check_session_key(
    invocation: &Invocation,
    algorithm: DataEncryptionAlgorithm,
    has_encrypted_key_recipient: bool,
) -> Result<(), CommandError> {
    let Some(spec) = option_text(invocation, "session-key")? else {
        return Ok(());
    };
    let key_len = capabilities::generated_key_len(spec)
        .ok_or_else(|| CommandError::Usage(format!("unsupported --session-key type: {spec}")))?;
    if !algorithm.uri().contains("#aes") || key_len != algorithm.key_len() {
        return Err(CommandError::Usage(format!(
            "--session-key {spec} does not match the template EncryptionMethod {}",
            algorithm.uri()
        )));
    }
    if !has_encrypted_key_recipient {
        return Err(CommandError::Usage(
            "--session-key requires an EncryptedKey recipient in the template".into(),
        ));
    }
    Ok(())
}

fn ensure_binary_template(
    placement: EncryptionTemplatePlacement,
    explicit_xml_type: bool,
) -> Result<(), CommandError> {
    if placement == EncryptionTemplatePlacement::Embedded {
        return Err(CommandError::Usage(
            "--binary-data requires a standalone EncryptedData template; embedded templates require --xml-data so decryption can replace XML".into(),
        ));
    }
    if explicit_xml_type {
        return Err(CommandError::Usage(
            "--binary-data cannot be used with an XML Element or Content template Type".into(),
        ));
    }
    Ok(())
}

/// The --xml-data node libxmlsec1 encrypts: the `--node-id` element of the data document,
/// else the first element named by `--node-name`, else its root element (`apps/xmlsec.c`,
/// `xmlSecAppXmlDataCreate`).
fn xml_data_target<'a>(
    document: &'a Document<'a>,
    invocation: &Invocation,
    id_attributes: &[IdAttributeRegistration],
) -> Result<Node<'a, 'a>, CommandError> {
    if let Some(id) = option_text(invocation, "node-id")? {
        return UriReferenceResolver::with_id_registrations(document, id_attributes)
            .node_for_id(id)
            .filter(Node::is_element)
            .ok_or_else(|| {
                CommandError::Encryption(format!("selected node ID is missing or ambiguous: {id}"))
            });
    }
    let Some(selector) = option_text(invocation, "node-name")? else {
        return Ok(document.root_element());
    };
    // `[<namespace-uri>:]<name>` splits at the last colon, since the URI itself contains
    // colons; without one, only elements in no namespace match (`xmlSecCheckNodeName`).
    let (namespace, name) = match selector.rsplit_once(':') {
        Some((namespace, name)) => (Some(namespace), name),
        None => (None, selector),
    };
    document
        .root_element()
        .descendants()
        .find(|node| node.has_tag_name((namespace, name)))
        .ok_or_else(|| {
            CommandError::Encryption(format!("failed to find node with name=\"{name}\""))
        })
}

fn xml_data_plaintext<'a>(
    xml: &'a str,
    target: Node<'_, '_>,
    encrypted_type: &EncryptedDataType,
    policy: &EncryptionPolicy,
) -> Result<Cow<'a, str>, CommandError> {
    // xmlSecEncCtxXmlEncrypt serializes the selected node for Element and only its
    // children for Content. The document declaration and boundary nodes therefore never
    // become encrypted replacement plaintext.
    let maximum = policy.resources.max_encryption_plaintext_bytes;
    match encrypted_type {
        EncryptedDataType::Element if target.parent_element().is_none() => {
            // The root has no ancestors, so its source text is already standalone.
            let element = &xml[target.range()];
            ensure_plaintext_capacity(0, element.len(), maximum)?;
            Ok(Cow::Borrowed(element))
        }
        EncryptedDataType::Element => {
            // A nested element carries the namespaces it inherits from its ancestors.
            let mut element = String::with_capacity(target.range().len().min(maximum));
            append_standalone_element(&mut element, xml, target, maximum)?;
            Ok(Cow::Owned(element))
        }
        EncryptedDataType::Content => {
            let mut content = String::with_capacity(target.range().len().min(maximum));
            for child in target.children() {
                append_serialized_xml_child(&mut content, xml, child, maximum)?;
            }
            Ok(Cow::Owned(content))
        }
        EncryptedDataType::Other(_) => Err(CommandError::Encryption(
            "unsupported EncryptedData Type for XML data".into(),
        )),
    }
}

/// Write `data` with the filled template `EncryptedData` in place of the selected node
/// (Element) or of its children (Content), as `xmlSecEncCtxXmlEncrypt` replaces them.
fn place_encrypted_data(
    command: &EncryptCommand<'_>,
    data: &str,
    target: Node<'_, '_>,
    encrypted_type: &EncryptedDataType,
    rendered_template: &str,
) -> Result<String, CommandError> {
    let rendered = parse_encryption_document(
        rendered_template,
        command.policy.xml,
        &command.policy.resources,
        command.xml_backend,
    )?;
    // The template may declare namespaces on a wrapper; the moved element keeps them.
    let encrypted_data = select_encrypted_data(&rendered, None, command.id_attributes)?;
    let mut filled = standalone_element(rendered_template, encrypted_data)?;
    // An unprefixed name takes the default namespace in scope (Namespaces in XML 1.0,
    // section 6.2). Without one in the template, the moved element undeclares the one
    // its new parent provides, so its unprefixed descendants keep their expanded names.
    let has_default = |node: Node<'_, '_>| {
        node.namespaces()
            .any(|namespace| namespace.name().is_none() && !namespace.uri().is_empty())
    };
    let context = match encrypted_type {
        EncryptedDataType::Content => Some(target),
        _ => target.parent_element(),
    };
    // An undeclaration the template already carries (`xmlns=""`) is kept as is; a second
    // one would be a duplicate attribute (section 6.3).
    let opening_end = opening_tag_end(&filled)
        .ok_or_else(|| CommandError::Encryption("EncryptedData has no opening tag".into()))?;
    let declares_default = owned_namespace_declarations(&filled[..opening_end])?.contains("");
    if !declares_default && !has_default(encrypted_data) && context.is_some_and(has_default) {
        let name_end = filled[1..]
            .find(|character: char| {
                character.is_whitespace() || character == '>' || character == '/'
            })
            .map_or(filled.len(), |end| end + 1);
        filled.insert_str(name_end, " xmlns=\"\"");
    }
    let filled_len = filled.len();
    let (range, replacement, filled_offset) = match encrypted_type {
        EncryptedDataType::Content => {
            let (range, replacement) = replace_element_text(data, target, &filled)?;
            let offset = replacement.find(filled.as_str()).ok_or_else(|| {
                CommandError::Encryption("EncryptedData is missing from its replacement".into())
            })?;
            (range, replacement, offset)
        }
        _ => (target.range(), filled, 0),
    };
    // The data document fits the policy, but the EncryptedData can be larger than the
    // node it replaces; output the CLI could not read back must not be written.
    // `range` lies inside `data`, so only the addition can overflow, and an overflow
    // exceeds every limit.
    let projected = (data.len() - range.len())
        .checked_add(replacement.len())
        .filter(|projected| *projected <= command.policy.resources.max_xml_document_bytes)
        .ok_or_else(|| {
            CommandError::Encryption("encrypted XML data output exceeds XML document policy".into())
        })?;
    let mut output = String::with_capacity(projected);
    output.push_str(&data[..range.start]);
    output.push_str(&replacement);
    output.push_str(&data[range.end..]);
    let moved_start = range.start + filled_offset;
    ensure_self_contained(&output, moved_start..moved_start + filled_len, command)?;
    // Both inputs passed their own checks, but the moved EncryptedData can still take
    // the result past the depth, node or namespace limits; parse it under the full
    // operation policy, as decryption will, and hand the same string back.
    xml_sec::XmlDocument::parse_with_policy_and_backend(output, command.policy, command.xml_backend)
        .map(xml_sec::XmlDocument::into_xml)
        .map_err(|error| CommandError::Encryption(error.to_string()))
}

/// Only the filled `EncryptedData` moves into the data document (`xmlSecReplaceNode`), so a
/// same-document reference to another template node would dangle and the output could not
/// be decrypted. Refuse it instead of writing that output. References are resolved in the
/// assembled document `xml`, where decryption resolves them, and must reach an element
/// inside the moved range: a data-document ID can duplicate a template ID there.
fn ensure_self_contained(
    xml: &str,
    moved: std::ops::Range<usize>,
    command: &EncryptCommand<'_>,
) -> Result<(), CommandError> {
    let document = parse_encryption_document(
        xml,
        command.policy.xml,
        &command.policy.resources,
        command.xml_backend,
    )?;
    let inside = |node: Node<'_, '_>| {
        let range = node.range();
        moved.start <= range.start && range.end <= moved.end
    };
    // The elements whose URI decryption resolves: cipher, key-retrieval and key-info
    // references, and the ReferenceList entries that associate keys with data. Other
    // `URI` attributes, such as application metadata in EncryptionProperty (XMLEnc 1.1
    // section 3.7), carry no reference semantics and are preserved as they are.
    let resolved_reference = |node: Node<'_, '_>| {
        node.has_tag_name((XMLENC_NS, "CipherReference"))
            || node.has_tag_name((XMLENC_NS, "DataReference"))
            || node.has_tag_name((XMLENC_NS, "KeyReference"))
            || node.has_tag_name((XMLDSIG_NS, "RetrievalMethod"))
            || node.has_tag_name((XMLDSIG11_NS, "KeyInfoReference"))
    };
    let resolver = UriReferenceResolver::with_id_registrations(&document, command.id_attributes);
    let dangling = document
        .descendants()
        .filter(|node| inside(*node) && resolved_reference(*node))
        .find_map(|node| {
            let uri = node.attribute("URI")?;
            uri.strip_prefix('#')?;
            // The same element resolution the core key-source parser uses, for bare IDs and
            // `#xpointer(id('x'))` alike, without projecting the target's subtree per URI. An
            // ambiguous ID resolves to nothing. `#xpointer(/)` names the document node, which
            // after the move is the data document, so it is refused like any outside target.
            let reachable = matches!(
                resolver.node_for_same_document_reference(uri),
                Ok(Some(target)) if inside(target)
            );
            (!reachable).then_some(uri)
        });
    match dangling {
        Some(uri) => Err(CommandError::Encryption(format!(
            "template EncryptedData references {uri} outside itself; with --xml-data only the EncryptedData moves into the data document"
        ))),
        None => Ok(()),
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
    backends: CommandBackends<'_>,
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
) -> Result<Vec<Option<ParsedRecipientKeyMetadata>>, CommandError> {
    let document =
        parse_encryption_document(template, policy.xml, &policy.resources, backends.xml)?;
    let encrypted_data = select_encrypted_data(&document, start_node_id, id_attributes)?;
    let encrypted_keys = direct_child_element(encrypted_data, XMLDSIG_NS, "KeyInfo")
        .into_iter()
        .flat_map(Node::children)
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
                .map(|node| {
                    parsing
                        .parse_with_provider(node, backends.crypto)
                        .map(ParsedRecipientKeyMetadata)
                })
                .transpose()
                .map_err(certificate_command_error)
        })
        .collect()
}

fn validate_recipient_key_metadata(
    metadata: Option<&ParsedRecipientKeyMetadata>,
    selected_key: &RecipientPublicKeyCandidate,
    provider: &dyn CryptoProvider,
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
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
                        let public_key = certificate_public_key(certificate, parsing, |spki| {
                            RsaPublicKey::from_public_key_der(spki).map_err(|_| {
                                recipient_metadata_error(
                                    "X509Certificate does not contain an RSA key",
                                )
                            })
                        })
                        .map_err(certificate_command_error)??;
                        rsa_public_keys_match(&selected_key.public_key, &public_key)
                    } else {
                        let certificate =
                            selected_key.certificate_der.as_deref().ok_or_else(|| {
                                recipient_metadata_error(
                                    "X509Data selectors require a selected RSA certificate",
                                )
                            })?;
                        parsing
                            .certificate_matches_selectors(data, certificate, provider)
                            .map_err(certificate_command_error)?
                    }
                }
                KeyInfoSource::DerEncodedKeyValue(der) => {
                    let public_key = RsaPublicKey::from_public_key_der(der).map_err(|_| {
                        recipient_metadata_error("DEREncodedKeyValue is not an RSA public key")
                    })?;
                    rsa_public_keys_match(&selected_key.public_key, &public_key)
                }
                // Non-RSA key values, retrieval methods and every other source
                // make an identity claim this RSA recipient cannot confirm.
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
        method.mgf_algorithm.as_deref().unwrap_or(
            OaepDigestAlgorithm::Sha1
                .mgf_uri()
                .expect("XML Encryption defines MGF1-SHA1"),
        ),
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
        .filter_map(Node::text)
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
        .filter_map(Node::text)
        .flat_map(str::bytes);
    let right_bytes = right
        .children()
        .filter(Node::is_text)
        .filter_map(Node::text)
        .flat_map(str::bytes);
    Ok(left_bytes.eq(right_bytes))
}

fn oaep_digest_from_uri(uri: &str) -> Result<OaepDigestAlgorithm, CommandError> {
    OaepDigestAlgorithm::from_uri(uri)
        .ok_or_else(|| CommandError::Encryption(format!("unsupported OAEP digest: {uri}")))
}

fn oaep_mgf_from_uri(uri: &str) -> Result<OaepDigestAlgorithm, CommandError> {
    OaepDigestAlgorithm::from_mgf_uri(uri)
        .ok_or_else(|| CommandError::Encryption(format!("unsupported OAEP MGF: {uri}")))
}

/// One text substitution in the template source.
type TemplateReplacement = (std::ops::Range<usize>, String);

/// The caller's template and the core-generated `EncryptedData` it is merged with.
struct TemplateSources<'a> {
    template: &'a str,
    generated: &'a str,
}

/// Append the generated `ChaCha` nonce to a template method that declares none.
fn chacha_nonce_replacement(
    sources: &TemplateSources<'_>,
    template_data: Node<'_, '_>,
    generated_data: Node<'_, '_>,
    maximum_bytes: usize,
) -> Result<Option<TemplateReplacement>, CommandError> {
    let Some(method) = direct_child_element(template_data, XMLENC_NS, "EncryptionMethod") else {
        return Ok(None);
    };
    if !matches!(
        method.attribute("Algorithm"),
        Some(
            "http://www.w3.org/2021/04/xmldsig-more#chacha20"
                | "http://www.w3.org/2021/04/xmldsig-more#chacha20poly1305"
        )
    )
        // RFC 9231 sections 2.6.7-2.6.8 use unqualified Nonce elements; retain
        // those and the namespaced donor form accepted by the core parser.
        // https://www.rfc-editor.org/rfc/rfc9231.html#section-2.6.7
        || method.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "Nonce"
                && matches!(
                    child.tag_name().namespace(),
                    None | Some("http://www.w3.org/2021/04/xmldsig-more#")
                )
        })
    {
        return Ok(None);
    }
    let generated_method = direct_child_element(generated_data, XMLENC_NS, "EncryptionMethod")
        .ok_or_else(|| CommandError::Encryption("generated ChaCha method is absent".into()))?;
    let nonce = direct_child_element(
        generated_method,
        "http://www.w3.org/2021/04/xmldsig-more#",
        "Nonce",
    )
    .ok_or_else(|| CommandError::Encryption("generated ChaCha nonce is absent".into()))?;
    let malformed = || CommandError::Encryption("ChaCha template method is malformed".into());
    let fragment = &sources.template[method.range()];
    let opening = opening_tag_end(fragment).ok_or_else(malformed)?;
    let original = if fragment[..opening].trim_end().ends_with('/') {
        ""
    } else {
        &fragment[opening + 1..fragment.rfind("</").ok_or_else(malformed)?]
    };
    let mut content = String::new();
    push_plaintext(&mut content, original, maximum_bytes)?;
    append_standalone_element(&mut content, sources.generated, nonce, maximum_bytes)?;
    replace_element_text(sources.template, method, &content).map(Some)
}

/// Replace the template's encapsulation ciphertext with the generated one,
/// returning the template's declared mechanisms. A declared mechanism must
/// have been executed with the same parameter set, and none may appear
/// unannounced.
fn merge_template_encapsulation<'i>(
    sources: &TemplateSources<'_>,
    (_, generated_key_info): (Node<'_, '_>, Node<'_, '_>),
    inspected: Option<&'i xml_sec::xmlenc::EncryptedDataTemplate<'_>>,
    replacements: &mut Vec<TemplateReplacement>,
) -> Result<&'i [xml_sec::key_establishment::EncapsulationMechanism], CommandError> {
    let generated_kem = xml_sec::key_establishment::direct_encapsulation(generated_key_info, false)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let template_kem = inspected.map_or(&[][..], |inspected| {
        inspected.data().encapsulation_methods.as_slice()
    });
    if let ([template_mechanism], Some(generated_kem)) = (template_kem, &generated_kem) {
        if template_mechanism.algorithm != generated_kem.algorithm {
            return Err(CommandError::Encryption(
                "generated encapsulation parameter set differs from template".into(),
            ));
        }
        let origin = *inspected
            .expect("selected template mechanism was inspected")
            .encapsulation_cipher_values()
            .first()
            .ok_or_else(|| {
                CommandError::Encryption("template encapsulation origin is missing".into())
            })?;
        replacements.push(replace_element_text(
            sources.template,
            origin,
            generated_kem.cipher_value.text().unwrap_or_default(),
        )?);
    } else if !template_kem.is_empty() || generated_kem.is_some() {
        return Err(CommandError::Encryption(
            "template encapsulation was not executed".into(),
        ));
    }
    Ok(template_kem)
}

/// Merge the generated `KeyName` and `KeyInfo` children into the template: an
/// empty template takes all children, otherwise only missing element kinds are
/// appended and existing recipient `CipherValue`s receive the generated ciphertexts.
fn merge_template_key_info_children(
    sources: &TemplateSources<'_>,
    (template_key_info, generated_key_info): (Node<'_, '_>, Node<'_, '_>),
    template_kem: &[xml_sec::key_establishment::EncapsulationMechanism],
    replacements: &mut Vec<TemplateReplacement>,
) -> Result<(), CommandError> {
    let TemplateSources {
        template,
        generated,
    } = *sources;
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
    // Both value sets are validated before either merge shape is chosen.
    let template_values = encrypted_key_cipher_values(template_key_info, "template")?;
    let generated_values = encrypted_key_cipher_values(generated_key_info, "generated")?;
    if !template_key_info.children().any(|node| node.is_element()) {
        let generated_children = generated_key_info
            .children()
            .filter(Node::is_element)
            .map(|node| standalone_element(generated, node))
            .collect::<Result<Vec<_>, _>>()?;
        if !generated_children.is_empty() {
            replacements.push(append_element_children_replacement(
                template,
                template_key_info,
                &generated_children.concat(),
            )?);
        }
        return Ok(());
    }
    // Only generated element kinds the template lacks are appended.
    let mut children_to_append = generated_key_info
        .children()
        .filter(|node| node.is_element() && !node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .filter(|node| {
            template_kem.is_empty()
                || !node.has_tag_name((
                    xml_sec::key_establishment::ENCAPSULATION_NS,
                    "EncapsulationMechanism",
                ))
        })
        .filter(|generated_child| {
            !template_key_info.children().any(|template_child| {
                template_child.is_element()
                    && template_child.tag_name() == generated_child.tag_name()
            })
        })
        .map(|node| standalone_element(generated, node))
        .collect::<Result<Vec<_>, _>>()?;
    if template_values.is_empty() && !generated_values.is_empty() {
        let generated_keys = generated_key_info
            .children()
            .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
            .map(|node| standalone_element(generated, node))
            .collect::<Result<Vec<_>, _>>()?;
        if generated_keys.len() != generated_values.len() {
            return Err(CommandError::Encryption(
                "generated KeyInfo does not contain one direct EncryptedKey per recipient".into(),
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
    if template_values.is_empty() {
        return Ok(());
    }
    if template_values.len() != generated_values.len() {
        return Err(CommandError::Encryption(
            "template KeyInfo does not contain one CipherValue per generated recipient".into(),
        ));
    }
    let template_keys = direct_encrypted_keys(template_key_info);
    let generated_keys = direct_encrypted_keys(generated_key_info);
    for (template_key, generated_key) in template_keys.into_iter().zip(generated_keys) {
        if let Some(replacement) =
            merge_generated_recipient_key_name(template, template_key, generated, generated_key)?
        {
            replacements.push(replacement);
        }
    }
    for (template_value, generated_value) in template_values.into_iter().zip(generated_values) {
        replacements.push(replace_element_text(
            template,
            template_value,
            generated_value.text().unwrap_or_default(),
        )?);
    }
    Ok(())
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
        parse_encryption_document(template, policy.xml, &policy.resources, xml_backend)?;
    let generated_document =
        parse_encryption_document(generated, policy.xml, &policy.resources, xml_backend)?;
    let template_data = select_encrypted_data(&template_document, start_node_id, id_attributes)?;
    let generated_data = generated_document.root_element();
    let inspected = if template_document.descendants().any(|node| {
        node.has_tag_name((
            xml_sec::key_establishment::ENCAPSULATION_NS,
            "EncapsulationMechanism",
        ))
    }) {
        Some(
            xml_sec::xmlenc::inspect_encrypted_data_template_node_with_context(
                template_data,
                policy,
                xml_backend,
                xml_sec::provider::default_provider(),
                id_attributes,
            )
            .map_err(|error| CommandError::Encryption(error.to_string()))?,
        )
    } else {
        None
    };
    let template_cipher = required_cipher_value(template_data, "template EncryptedData")?;
    let generated_cipher = required_cipher_value(generated_data, "generated EncryptedData")?;
    let mut replacements = vec![replace_element_text(
        template,
        template_cipher,
        generated_cipher.text().unwrap_or_default(),
    )?];
    let sources = TemplateSources {
        template,
        generated,
    };
    if let Some(replacement) = chacha_nonce_replacement(
        &sources,
        template_data,
        generated_data,
        policy.resources.max_xml_document_bytes,
    )? {
        replacements.push(replacement);
    }
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
            let key_infos = (template_key_info, generated_key_info);
            let template_kem = merge_template_encapsulation(
                &sources,
                key_infos,
                inspected.as_ref(),
                &mut replacements,
            )?;
            merge_template_key_info_children(&sources, key_infos, template_kem, &mut replacements)?;
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
    parse_encryption_document(&output, policy.xml, &policy.resources, xml_backend)?;
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

/// Whether any direct `EncryptedKey` recipient wraps its key symmetrically.
fn has_key_wrap_recipient(encrypted_data: Node<'_, '_>) -> bool {
    encrypted_data
        .children()
        .filter(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .flat_map(Node::children)
        .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .any(|node| {
            node.children()
                .filter(|child| child.has_tag_name((XMLENC_NS, "EncryptionMethod")))
                .any(|method| {
                    method
                        .attribute("Algorithm")
                        .is_some_and(|uri| KeyWrapAlgorithm::from_uri(uri).is_ok())
                })
        })
}

/// One `decrypt` invocation's input document, selected data and backends.
struct DecryptCommand<'a> {
    invocation: &'a Invocation,
    xml: &'a str,
    encrypted_data_id: Option<&'a str>,
    standalone: bool,
    id_attributes: &'a [IdAttributeRegistration],
    xml_backend: XmlBackend,
}

impl DecryptCommand<'_> {
    fn lax(&self) -> bool {
        self.invocation.flag("lax-key-search")
    }

    fn decrypt(
        &self,
        resolver: &dyn DecryptionKeyResolver,
        policy: DecryptionPolicy,
    ) -> Result<Vec<u8>, CommandError> {
        decrypt_input(
            resolver,
            self.xml,
            self.encrypted_data_id,
            self.standalone,
            policy,
            self.id_attributes,
            CommandBackends {
                xml: self.xml_backend,
                crypto: selected_provider(self.invocation)?,
            },
        )
    }
}

/// Symmetric key names the document requests for content and wrapped keys.
struct SymmetricKeyNames<'a> {
    content_key_name: Option<&'a str>,
    requested: Vec<&'a str>,
    wrapping_only: bool,
}

/// Certificate companions use the DER or PEM encoding of their private key.
fn companion_certificate_encoding(
    format: key_material::PrivateKeyFormat,
) -> key_material::CertificateEncoding {
    if matches!(
        format,
        key_material::PrivateKeyFormat::Der | key_material::PrivateKeyFormat::Pkcs8Der
    ) {
        key_material::CertificateEncoding::Der
    } else {
        key_material::CertificateEncoding::Pem
    }
}

/// Decrypt through the recipient `EncapsulationMechanism` the inspection found.
fn decrypt_with_encapsulation(
    command: &DecryptCommand<'_>,
    policy: DecryptionPolicy,
    parsed: xml_sec::xmlenc::EncryptedDataInspection,
    has_aes_keys: bool,
) -> Result<Vec<u8>, CommandError> {
    let invocation = command.invocation;
    let mechanism = parsed
        .recipient_encapsulation()
        .expect("only inspections with a recipient mechanism reach decapsulation");
    policy
        .key_establishment
        .check_encapsulation(mechanism.algorithm)?;
    if has_aes_keys {
        return Err(CommandError::Usage(
            "EncapsulationMechanism requires a recipient private key, not --aes-key".into(),
        ));
    }
    let names = mechanism
        .key_info
        .sources
        .iter()
        .filter_map(|source| match source {
            KeyInfoSource::KeyName(name) => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    let key = select_decapsulation_key(
        invocation,
        &names,
        mechanism.algorithm,
        &policy.key_establishment,
        &policy,
        &mut budget,
    )?;
    let resolver = xml_sec::xmlenc::EncapsulationDecryptor::provider_key(key);
    if command.standalone && !parsed.requires_document_context() {
        // Reuse the validated descriptor graph for byte output. Re-reading
        // the XML would decode and allocate every recipient a second time.
        return DecryptContext::new(&resolver)
            .provider(selected_provider(invocation)?)
            .policy(policy)
            .decrypt_data(parsed.data())
            .map(|content| match content {
                DecryptedContent::Xml(xml) => xml.into_bytes(),
                DecryptedContent::Bytes(bytes) => bytes,
            })
            .map_err(|error| CommandError::Encryption(error.to_string()));
    }
    // Associations and CipherReference require the original document's
    // registered IDs, even for standalone byte output. Keep only the
    // provider key, not a second live recipient graph.
    drop(parsed);
    command.decrypt(&resolver, policy)
}

/// Decrypt with the explicit symmetric keys the document's names select.
fn decrypt_with_explicit_symmetric_keys(
    command: &DecryptCommand<'_>,
    policy: DecryptionPolicy,
    aes_keys: &[&crate::OptionValue],
    names: &SymmetricKeyNames<'_>,
) -> Result<Vec<u8>, CommandError> {
    let candidates = aes_keys
        .iter()
        .copied()
        .map(|option| (option, ()))
        .collect::<Vec<_>>();
    let lax_key_search = command.lax();
    let candidates = named_candidate_search(
        &candidates,
        &names.requested,
        lax_key_search,
        true,
        "symmetric key",
    )?;
    KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
        .consume(candidates.len())
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
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
        return Err(last_error
            .unwrap_or_else(|| CommandError::Usage("no compatible symmetric key input".into())));
    }
    let resolver = CandidateSymmetricKeyDecryptor {
        keys,
        lax_key_search,
        content_key_name: names.content_key_name,
        wrapping_only: names.wrapping_only,
    };
    command.decrypt(&resolver, policy)
}

/// Decrypt with the key store's symmetric keys; it holds no RSA private keys.
fn decrypt_with_stored_keys(
    command: &DecryptCommand<'_>,
    policy: DecryptionPolicy,
    names: &SymmetricKeyNames<'_>,
    has_recipient_names: bool,
) -> Result<Vec<u8>, CommandError> {
    let mut budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    let store = load_xml_key_stores(
        command.invocation,
        &policy,
        command.xml_backend,
        &mut budget,
    )?;
    let decryption_key = |entry: &&key_manager::StoredSymmetricKey| {
        entry.kind.is_encryption_key() && entry.usages.allows(key_manager::KeyUsage::Decrypt)
    };
    if has_recipient_names
        && !store
            .symmetric_keys()
            .iter()
            .any(|entry| decryption_key(&entry))
    {
        // XMLDSig 1.1 section 4.5.2.2 defines RSAKeyValue as Modulus and
        // Exponent, not a private-key container:
        // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-RSAKeyValue
        return Err(CommandError::Usage(
            "--keys-file does not supply RSA recipient private keys for decrypt: RSAKeyValue imports are public-only; use --privkey-pem, --privkey-der, or --pkcs12".into(),
        ));
    }
    let selected = select_store_candidates(
        store.symmetric_keys().iter().filter(decryption_key),
        &names.requested,
        command.lax(),
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
        lax_key_search: command.lax(),
        content_key_name: names.content_key_name,
        wrapping_only: names.wrapping_only,
    };
    command.decrypt(&resolver, policy)
}

/// A PKCS#12 recipient key, held by the selected provider when it is native.
fn load_pkcs12_recipient(
    command: &DecryptCommand<'_>,
    option: &crate::OptionValue,
    budget: &mut ExternalMaterialBudget,
    inventory: &mut KeyInventory,
    resources: &ResourcePolicy,
    policy_resources: &ResourcePolicy,
) -> Result<RecipientPrivateKey, CommandError> {
    let path = Path::new(option.value.as_deref().unwrap_or_default());
    let bytes = read_key_material_with_budget(path, budget)?;
    let password = command
        .invocation
        .password_bytes()
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or(key_manager::KeyStoreError::ProtectedContainer)?;
    let name = option.parameter.clone().unwrap_or_else(|| "pkcs12".into());
    inventory.add_pkcs12(name, &bytes, password, resources)?;
    let imported = inventory
        .private_keys()
        .first()
        .ok_or_else(|| CommandError::Usage("PKCS#12 contains no usable private key".into()))?;
    let provider = selected_provider(command.invocation)?;
    let inner = if provider.name() == "rustcrypto" {
        PrivateKeyDecryptor::new(key_material::decode_rsa_private_with_password(
            path,
            imported.pkcs8_der(),
            key_material::PrivateKeyFormat::Pkcs8Der,
            None,
            policy_resources,
        )?)
    } else {
        PrivateKeyDecryptor::provider_key(
            provider
                .import_recovery_key(imported.pkcs8_der())
                .map_err(|error| CommandError::Encryption(error.to_string()))?,
        )
    };
    Ok(RecipientPrivateKey {
        inner,
        key_name: option.parameter.clone(),
    })
}

/// Import a private key into the native provider, proving any certificate
/// companion describes the recovered public identity.
fn load_provider_recipient(
    command: &DecryptCommand<'_>,
    option: &crate::OptionValue,
    (path, bytes, certificate_paths): (&OsStr, &[u8], &[&OsStr]),
    budget: &mut ExternalMaterialBudget,
    inventory: &mut KeyInventory,
    resources: &ResourcePolicy,
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
) -> Result<RecipientPrivateKey, CommandError> {
    let format = private_key_format(option);
    import_explicit_private_key(
        inventory,
        bytes,
        &key_material::PrivateKeyImport {
            path: Path::new(path),
            name: "explicit",
            format,
            password: command.invocation.password_bytes(),
            usages: key_manager::KeyUsages::DECRYPT,
            resources,
        },
        budget,
    )?;
    let imported = inventory
        .private_keys()
        .last()
        .ok_or_else(|| CommandError::Usage("no RSA private key imported".into()))?;
    let key = selected_provider(command.invocation)?
        .import_recovery_key(imported.pkcs8_der())
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    if !certificate_paths.is_empty() {
        let certificates = load_certificate_companions(
            certificate_paths,
            companion_certificate_encoding(format),
            budget,
        )?;
        let spki = key.public_spki().ok_or_else(|| {
            CommandError::Encryption("recovery key exposes no public identity".into())
        })?;
        ensure_leaf_certificate_matches_spki(&certificates[0], spki, parsing)?;
    }
    Ok(RecipientPrivateKey {
        inner: PrivateKeyDecryptor::provider_key(key),
        key_name: option.parameter.clone(),
    })
}

/// Load one explicit recipient private key with its certificate companions.
fn load_recipient_private_key(
    command: &DecryptCommand<'_>,
    option: &crate::OptionValue,
    budget: &mut ExternalMaterialBudget,
    inventory: &mut KeyInventory,
    resources: &ResourcePolicy,
    policy_resources: &ResourcePolicy,
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
) -> Result<RecipientPrivateKey, CommandError> {
    if option.name == "pkcs12" {
        return load_pkcs12_recipient(
            command,
            option,
            budget,
            inventory,
            resources,
            policy_resources,
        );
    }
    let (path, certificate_paths) =
        split_key_and_certificates(option.value.as_deref().unwrap_or_default())?;
    let bytes = read_key_material_with_budget(Path::new(path), budget)?;
    if selected_provider(command.invocation)?.name() != "rustcrypto" {
        return load_provider_recipient(
            command,
            option,
            (path, &bytes, &certificate_paths),
            budget,
            inventory,
            resources,
            parsing,
        );
    }
    let private_key = key_material::decode_rsa_private_with_inventory(
        Path::new(path),
        &bytes,
        private_key_format(option),
        command.invocation.password_bytes(),
        resources,
        inventory,
    )?;
    if !certificate_paths.is_empty() {
        let certificates = load_certificate_companions(
            &certificate_paths,
            companion_certificate_encoding(private_key_format(option)),
            budget,
        )?;
        ensure_leaf_certificate_matches_rsa_key(&certificates[0], &private_key, parsing)?;
    }
    Ok(RecipientPrivateKey {
        inner: PrivateKeyDecryptor::new(private_key),
        key_name: option.parameter.clone(),
    })
}

/// Decrypt with the explicit RSA private keys the recipient names select.
fn decrypt_with_private_keys(
    command: &DecryptCommand<'_>,
    policy: DecryptionPolicy,
    private_keys: &[&crate::OptionValue],
    recipient_key_names: &[Option<String>],
) -> Result<Vec<u8>, CommandError> {
    let lax_key_search = command.lax();
    let selected =
        select_recipient_private_keys(private_keys, recipient_key_names, lax_key_search)?;
    KeyCandidateBudget::with_limit(policy.resources.max_key_candidates)
        .consume(selected.len())
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let mut keys = Vec::with_capacity(selected.len());
    let mut last_load_error = None;
    let mut certificate_budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    let mut certificate_parsing =
        xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&policy.resources)
            .map_err(certificate_command_error)?;
    for option in selected {
        let loaded = certificate_budget.with_key_import(
            &policy.resources,
            |budget, inventory, resources| {
                load_recipient_private_key(
                    command,
                    option,
                    budget,
                    inventory,
                    resources,
                    &policy.resources,
                    &mut certificate_parsing,
                )
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
        return Err(last_load_error
            .unwrap_or_else(|| CommandError::Usage("no compatible RSA private key input".into())));
    }
    let resolver = NamedRecipientDecryptor {
        keys,
        lax_key_search,
        unnamed_single_key_fallback: private_keys.len() == 1 && private_keys[0].parameter.is_none(),
    };
    command.decrypt(&resolver, policy)
}

fn decrypt(invocation: &Invocation, stdout: &mut dyn Write) -> Result<(), CommandError> {
    validate_options(invocation, DECRYPT_OPTIONS)?;
    let xml_backend = selected_xml_backend(invocation)?;
    validate_supported_selectors(invocation, &["node-id", "id-attr", "add-id-attr"])?;
    let policy = xmlsec_compatibility_decryption_policy();
    let xml = read_input(invocation, policy.resources.max_xml_document_bytes)?;
    let encrypted_data_id = option_text(invocation, "node-id")?;
    let id_attributes = id_attribute_registrations(invocation)?;
    let document = parse_encryption_document(&xml, policy.xml, &policy.resources, xml_backend)?;
    let encrypted_data = select_encrypted_data(&document, encrypted_data_id, &id_attributes)?;
    let standalone = encrypted_data == document.root_element();
    let content_key_name = encrypted_data_key_name(encrypted_data)?;
    let recipient_key_names = encrypted_key_recipient_names(encrypted_data)?;
    let has_wrap_recipients = has_key_wrap_recipient(encrypted_data);
    let symmetric_names = SymmetricKeyNames {
        content_key_name: content_key_name.as_deref(),
        requested: content_key_name
            .iter()
            .chain(
                recipient_key_names
                    .iter()
                    .flatten()
                    .filter(|_| has_wrap_recipients),
            )
            .map(String::as_str)
            .collect(),
        wrapping_only: has_wrap_recipients && content_key_name.is_none(),
    };
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
    // References may nominate a sibling KeyInfo, not only a descendant of the
    // selected data. With no mechanism anywhere in this same-document-only
    // source domain, keep ordinary decryption free of extra model construction.
    let parsed = if document.descendants().any(|node| {
        node.has_tag_name((
            xml_sec::key_establishment::ENCAPSULATION_NS,
            "EncapsulationMechanism",
        ))
    }) {
        Some(
            xml_sec::xmlenc::inspect_encrypted_data_node_with_context(
                encrypted_data,
                &policy,
                xml_backend,
                selected_provider(invocation)?,
                &id_attributes,
            )
            .map_err(|error| CommandError::Encryption(error.to_string()))?,
        )
    } else {
        None
    };
    // Keep the inspected graph only when it carries a recipient mechanism;
    // other paths re-read the document and must not hold a second copy.
    let parsed = parsed.filter(|parsed| parsed.recipient_encapsulation().is_some());
    let command = DecryptCommand {
        invocation,
        xml: &xml,
        encrypted_data_id,
        standalone,
        id_attributes: &id_attributes,
        xml_backend,
    };
    let bytes = if let Some(parsed) = parsed {
        decrypt_with_encapsulation(&command, policy, parsed, !aes_keys.is_empty())?
    } else if !aes_keys.is_empty() {
        decrypt_with_explicit_symmetric_keys(&command, policy, &aes_keys, &symmetric_names)?
    } else if has_key_store {
        let has_recipient_names = !recipient_key_names.is_empty();
        decrypt_with_stored_keys(&command, policy, &symmetric_names, has_recipient_names)?
    } else if !private_keys.is_empty() {
        decrypt_with_private_keys(&command, policy, &private_keys, &recipient_key_names)?
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
    fn wrapping_candidate(
        &self,
        key: &SymmetricCandidate<'_>,
        recipient: &EncryptedKey,
        wrap: KeyWrapAlgorithm,
    ) -> bool {
        if key.kind != wrap.key_kind() {
            return false;
        }
        self.lax_key_search
            || recipient.key_name.as_deref() == key.name.as_deref()
            || recipient.key_name.is_none() && self.keys.len() == 1
    }
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
    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        source: xml_sec::xmlenc::KeyEncryptionKeySource<'_>,
        policy: &DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, XmlEncError> {
        let xml_sec::xmlenc::KeyEncryptionKeySource::Encrypted(recipient) = source else {
            return Err(XmlEncError::KeyNotFound);
        };
        let transport = KeyWrapAlgorithm::from_uri(&recipient.encryption_method.algorithm)?;
        let mut resolved = Vec::new();
        let mut last_error = XmlEncError::KeyNotFound;
        for key in &self.keys {
            if !self.wrapping_candidate(key, recipient, transport) {
                continue;
            }
            match KekDecryptor::borrowed_with_kind(&key.bytes, key.kind)
                .resolve_key_encryption_keys_with_policy(
                    provider,
                    algorithm,
                    xml_sec::xmlenc::KeyEncryptionKeySource::Encrypted(recipient),
                    policy,
                    budget,
                ) {
                Ok(mut keys) => resolved.append(&mut keys),
                Err(error @ XmlEncError::Policy(_)) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        if resolved.is_empty() {
            Err(last_error)
        } else {
            Ok(resolved)
        }
    }
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
            if !self.wrapping_candidate(key, recipient, wrap) {
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
    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        source: xml_sec::xmlenc::KeyEncryptionKeySource<'_>,
        policy: &DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, XmlEncError> {
        let xml_sec::xmlenc::KeyEncryptionKeySource::Encrypted(recipient) = source else {
            return Err(XmlEncError::KeyNotFound);
        };
        let mut resolved = Vec::new();
        let mut last_error = XmlEncError::KeyNotFound;
        for key in self.applicable_keys(recipient) {
            budget.consume(1)?;
            match key.inner.resolve_key_encryption_keys_with_policy(
                provider,
                algorithm,
                xml_sec::xmlenc::KeyEncryptionKeySource::Encrypted(recipient),
                policy,
                budget,
            ) {
                Ok(mut keys) => resolved.append(&mut keys),
                Err(error @ XmlEncError::Policy(_)) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        if resolved.is_empty() {
            Err(last_error)
        } else {
            Ok(resolved)
        }
    }
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

#[derive(Clone, Copy)]
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
    encapsulation: Option<(xml_sec::provider::KeyEncapsulationAlgorithm, Vec<String>)>,
    algorithm: DataEncryptionAlgorithm,
    chacha: Option<xml_sec::xmlenc::ChaChaParameters>,
    encrypted_type: EncryptedDataType,
    explicit_xml_type: bool,
    placement: EncryptionTemplatePlacement,
    has_encrypted_key_recipient: bool,
    content_key_name: Option<String>,
    recipients: Vec<EncryptionTemplateRecipient>,
}

fn xmlsec_compatibility_key_establishment_policy() -> xml_sec::policy::KeyEstablishmentPolicy {
    let policy = xml_sec::policy::KeyEstablishmentPolicy::default();
    #[cfg(feature = "experimental-pq")]
    let policy = xml_sec::policy::KeyEstablishmentPolicy {
        // The compatibility CLI preserves donor CBC semantics. It cannot
        // establish external authentication; callers must supply that boundary.
        kem_content_authentication:
            xml_sec::policy::KemContentAuthentication::ExternalAuthenticated,
        encapsulation_algorithms: [
            xml_sec::provider::KeyEncapsulationAlgorithm::MlKem512,
            xml_sec::provider::KeyEncapsulationAlgorithm::MlKem768,
            xml_sec::provider::KeyEncapsulationAlgorithm::MlKem1024,
        ]
        .into(),
        ..policy
    };
    policy
}

/// The first named key-store entry that yields an encapsulation key; lax
/// search skips only recoverable candidate failures.
fn stored_encapsulation_key(
    invocation: &Invocation,
    store: &KeyInventory,
    names: &[impl AsRef<str>],
    provider: &dyn CryptoProvider,
    algorithm: xml_sec::provider::KeyEncapsulationAlgorithm,
    establishment: &xml_sec::policy::KeyEstablishmentPolicy,
    resources: &ResourcePolicy,
) -> Result<std::sync::Arc<dyn xml_sec::provider::KeyEncapsulationKey>, CommandError> {
    let entries = select_store_candidates(
        store
            .public_keys()
            .iter()
            .filter(|entry| entry.usages.allows(key_manager::KeyUsage::Encrypt)),
        names,
        invocation.flag("lax-key-search"),
        resources.max_key_candidates,
        |entry| &entry.name,
    )?;
    let mut last = None;
    for entry in entries {
        match entry.encapsulation_key(provider, algorithm, establishment, resources) {
            Ok(key) => return Ok(key),
            Err(error) => {
                let error = CommandError::from(error);
                if !invocation.flag("lax-key-search") || !lax_candidate_error_is_recoverable(&error)
                {
                    return Err(error);
                }
                last = Some(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| CommandError::Usage("no recipient public key found".into())))
}

fn select_encapsulation_key<P: xml_sec::document::XmlDocumentPolicy>(
    invocation: &Invocation,
    names: &[impl AsRef<str>],
    algorithm: xml_sec::provider::KeyEncapsulationAlgorithm,
    establishment: &xml_sec::policy::KeyEstablishmentPolicy,
    policy: &P,
    backend: XmlBackend,
    budget: &mut ExternalMaterialBudget,
) -> Result<std::sync::Arc<dyn xml_sec::provider::KeyEncapsulationKey>, CommandError> {
    establishment.validate()?;
    establishment.check_encapsulation(algorithm)?;
    let provider = selected_provider(invocation)?;
    provider
        .require_capability(xml_sec::provider::ProviderCapability::Encapsulate(
            algorithm,
        ))
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let resources = policy.resource_policy();
    if let Some(option) = invocation
        .ordered_values(&["pubkey-cert-pem", "pubkey-cert-der"])
        .next()
    {
        return Err(CommandError::Usage(format!(
            "--{} is inapplicable to {} with EncapsulationMechanism; supply --pubkey-pem, --pubkey-der or --keys-file",
            option.name, invocation.command
        )));
    }
    let options = invocation
        .ordered_values(&["pubkey-pem", "pubkey-der"])
        .map(|option| (option, ()))
        .collect::<Vec<_>>();
    if invocation.values("keys-file").next().is_some() {
        if !options.is_empty() {
            return Err(CommandError::Usage(
                "cannot combine --keys-file with explicit recipient keys".into(),
            ));
        }
        let store = load_xml_key_stores(invocation, policy, backend, budget)?;
        return stored_encapsulation_key(
            invocation,
            &store,
            names,
            provider,
            algorithm,
            establishment,
            resources,
        );
    }
    if options.is_empty() {
        return Err(CommandError::Usage(format!(
            "{} with EncapsulationMechanism requires a recipient --pubkey-pem, --pubkey-der or --keys-file",
            invocation.command
        )));
    }
    let candidates = named_candidate_search(
        &options,
        names,
        invocation.flag("lax-key-search"),
        true,
        "ML-KEM recipient",
    )?;
    resources.validate_key_candidates(candidates.len())?;
    let mut last = None;
    for (option, ()) in candidates {
        let attempt = (|| {
            let bytes = read_key_material_with_budget(
                Path::new(option.value.as_deref().unwrap_or_default()),
                budget,
            )?;
            let mut store = KeyInventory::default();
            if option.name == "pubkey-pem" {
                store.add_public_pem_with_usages(
                    "recipient".into(),
                    &bytes,
                    key_manager::KeyUsages::ENCRYPT,
                    resources,
                )?;
            } else {
                store.add_public_der_with_usages(
                    "recipient".into(),
                    bytes,
                    key_manager::KeyUsages::ENCRYPT,
                    resources,
                )?;
            }
            Ok::<_, CommandError>(store.public_keys()[0].encapsulation_key(
                provider,
                algorithm,
                establishment,
                resources,
            )?)
        })();
        match attempt {
            Ok(key) => return Ok(key),
            Err(error)
                if invocation.flag("lax-key-search")
                    && lax_candidate_error_is_recoverable(&error) =>
            {
                last = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| CommandError::Usage("no ML-KEM public key supplied".into())))
}

fn select_decapsulation_key<P: xml_sec::document::XmlDocumentPolicy>(
    invocation: &Invocation,
    names: &[impl AsRef<str>],
    algorithm: xml_sec::provider::KeyEncapsulationAlgorithm,
    establishment: &xml_sec::policy::KeyEstablishmentPolicy,
    policy: &P,
    budget: &mut ExternalMaterialBudget,
) -> Result<std::sync::Arc<dyn xml_sec::provider::KeyDecapsulationKey>, CommandError> {
    establishment.validate()?;
    establishment.check_encapsulation(algorithm)?;
    let provider = selected_provider(invocation)?;
    provider
        .require_capability(xml_sec::provider::ProviderCapability::Decapsulate(
            algorithm,
        ))
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let resources = policy.resource_policy();
    if invocation.values("pkcs12").next().is_some() {
        return Err(CommandError::Usage(format!(
            "--pkcs12 is inapplicable to {} with EncapsulationMechanism; supply --privkey-pem/der or --pkcs8-pem/der",
            invocation.command
        )));
    }
    let options = invocation
        .ordered_values(&["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"])
        .map(|option| (option, ()))
        .collect::<Vec<_>>();
    if invocation.values("keys-file").next().is_some() {
        // XMLDSig 1.1 §4.5.9 carries public SPKI, not private PKCS#8.
        // https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue
        return Err(CommandError::Usage(format!(
            "--keys-file is inapplicable to ML-KEM decapsulation in {}; supply the recipient PKCS#8 using --pkcs8-pem or --pkcs8-der instead",
            invocation.command
        )));
    }
    if options.is_empty() {
        return Err(CommandError::Usage(format!(
            "{} with EncapsulationMechanism requires a recipient --privkey-pem/der or --pkcs8-pem/der",
            invocation.command
        )));
    }
    let candidates = named_candidate_search(
        &options,
        names,
        invocation.flag("lax-key-search"),
        true,
        "ML-KEM recipient",
    )?;
    resources.validate_key_candidates(candidates.len())?;
    let mut last = None;
    for (option, ()) in candidates {
        let attempt = budget.with_key_import(resources, |budget, store, resources| {
            let path = Path::new(option.value.as_deref().unwrap_or_default());
            let bytes = read_key_material_with_budget(path, budget)?;
            import_explicit_private_key(
                store,
                &bytes,
                &key_material::PrivateKeyImport {
                    path,
                    name: "recipient",
                    format: private_key_format(option),
                    password: invocation.password_bytes(),
                    usages: key_manager::KeyUsages::DECRYPT,
                    resources,
                },
                budget,
            )?;
            Ok(store.private_keys()[0].decapsulation_key(
                provider,
                algorithm,
                establishment,
                resources,
            )?)
        });
        match attempt {
            Ok(key) => return Ok(key),
            Err(error)
                if invocation.flag("lax-key-search")
                    && lax_candidate_error_is_recoverable(&error) =>
            {
                last = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| CommandError::Usage("no ML-KEM private key supplied".into())))
}

fn xmlsec_compatibility_encryption_policy() -> EncryptionPolicy {
    // The compatibility executable is an explicit profile boundary, as for
    // XMLDSig. Library defaults remain restrictive, and provider capability
    // still gates every requested primitive independently of this allowlist.
    EncryptionPolicy {
        key_establishment: xmlsec_compatibility_key_establishment_policy(),
        data_algorithms: Some(
            [
                #[cfg(feature = "legacy-algorithms")]
                DataEncryptionAlgorithm::TripleDesCbc,
                #[cfg(feature = "legacy-algorithms")]
                DataEncryptionAlgorithm::Aes192Cbc,
                #[cfg(feature = "legacy-algorithms")]
                DataEncryptionAlgorithm::Aes192Gcm,
                DataEncryptionAlgorithm::Aes128Cbc,
                DataEncryptionAlgorithm::Aes256Cbc,
                DataEncryptionAlgorithm::Aes128Gcm,
                DataEncryptionAlgorithm::Aes256Gcm,
                DataEncryptionAlgorithm::Camellia128Cbc,
                DataEncryptionAlgorithm::Camellia192Cbc,
                DataEncryptionAlgorithm::Camellia256Cbc,
                DataEncryptionAlgorithm::ChaCha20,
                DataEncryptionAlgorithm::ChaCha20Poly1305,
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
        key_wrap_algorithms: Some(
            [
                #[cfg(feature = "legacy-algorithms")]
                xml_sec::xmlenc::KeyWrapAlgorithm::TripleDes,
                #[cfg(feature = "legacy-algorithms")]
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw192,
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw128,
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw256,
                xml_sec::xmlenc::KeyWrapAlgorithm::CamelliaKw128,
                xml_sec::xmlenc::KeyWrapAlgorithm::CamelliaKw192,
                xml_sec::xmlenc::KeyWrapAlgorithm::CamelliaKw256,
                xml_sec::xmlenc::KeyWrapAlgorithm::Cbc(DataEncryptionAlgorithm::Camellia256Cbc),
            ]
            .into(),
        ),
        ..EncryptionPolicy::default()
    }
}

/// The first explicit symmetric key of `wrap`'s kind and length matching the
/// requested names. `cache`, present only for batched recipients, keeps decoded
/// inputs so a key shared by several recipients is read from disk once.
fn explicit_wrapping_key(
    invocation: &Invocation,
    explicit: &[&crate::OptionValue],
    wrap: KeyWrapAlgorithm,
    requested: &[String],
    budget: &mut KeyCandidateBudget,
    material: &mut ExternalMaterialBudget,
    mut cache: Option<&mut HashMap<usize, zeroize::Zeroizing<Vec<u8>>>>,
) -> Result<(Option<String>, Vec<u8>), CommandError> {
    let candidates = explicit
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, option)| symmetric_option_kind(&option.name) == wrap.key_kind())
        .map(|(index, option)| (option, index))
        .collect::<Vec<_>>();
    let candidates = named_candidate_search(
        &candidates,
        requested,
        invocation.flag("lax-key-search"),
        true,
        "wrapping key",
    )?;
    budget
        .consume(candidates.len())
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let mut last_error = None;
    for (option, index) in candidates {
        if let Some(key) = cache.as_deref().and_then(|cache| cache.get(&index)) {
            if key.len() == wrap.key_len() {
                return Ok((option.parameter.clone(), key.to_vec()));
            }
            last_error = Some(CommandError::Usage(
                "wrapping key length does not match the template method".into(),
            ));
            continue;
        }
        match load_symmetric_with_budget(
            option.value.as_deref().unwrap_or_default(),
            Some(wrap.key_len()),
            material,
        ) {
            Ok(key) => {
                // Recipient builders retain their own key bytes; only batched
                // inputs are cached, so single recipients allocate no cache entry.
                if let Some(cache) = cache.as_deref_mut() {
                    cache.insert(index, zeroize::Zeroizing::new(key.clone()));
                }
                return Ok((option.parameter.clone(), key));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| CommandError::Usage("no compatible wrapping key input".into())))
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
            explicit_wrapping_key(
                invocation,
                explicit,
                wrap,
                &requested,
                &mut budget,
                &mut material,
                (recipients.len() > 1).then_some(&mut decoded),
            )?
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
        key_establishment: compatibility.key_establishment,
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

fn has_nested_encapsulation(keys: &[xml_sec::xmlenc::EncryptedKey]) -> bool {
    // Inspection already enforces the non-configurable key-indirection
    // ceiling; this borrowed graph walk adds neither allocation nor parsing.
    keys.iter().any(|key| {
        !key.sources.encapsulation_methods.is_empty()
            || has_nested_encapsulation(&key.sources.encrypted_keys)
    })
}

fn encryption_template(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[IdAttributeRegistration],
    policy: &EncryptionPolicy,
    xml_backend: XmlBackend,
) -> Result<EncryptionTemplateMetadata, CommandError> {
    let document = parse_encryption_document(xml, policy.xml, &policy.resources, xml_backend)?;
    let encrypted_data = select_encrypted_data(&document, start_node_id, id_attributes)?;
    // Templates preserve every non-cipher field. Parse the selected node through
    // the reciprocal core path first so encryption cannot emit a document that
    // the same policy snapshot would reject during decryption.
    let parsed = xml_sec::xmlenc::inspect_encrypted_data_template_node_with_context(
        encrypted_data,
        policy,
        xml_backend,
        xml_sec::provider::default_provider(),
        id_attributes,
    )
    .map_err(|error| CommandError::Encryption(error.to_string()))?
    .into_data();
    if has_nested_encapsulation(&parsed.encrypted_keys) {
        return Err(CommandError::Encryption(
            "nested EncapsulationMechanism templates are not supported for encryption".into(),
        ));
    }
    let algorithm = DataEncryptionAlgorithm::from_uri(&parsed.encryption_method.algorithm)
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    let encapsulation = match parsed.encapsulation_methods.as_slice() {
        [] => None,
        [mechanism] => {
            policy
                .key_establishment
                .check_encapsulation(mechanism.algorithm)?;
            Some((
                mechanism.algorithm,
                mechanism
                    .key_info
                    .sources
                    .iter()
                    .filter_map(|source| match source {
                        KeyInfoSource::KeyName(name) => Some(name.clone()),
                        _ => None,
                    })
                    .collect(),
            ))
        }
        _ => {
            return Err(CommandError::Encryption(
                "multiple direct template encapsulation mechanisms are ambiguous".into(),
            ));
        }
    };
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
        encapsulation,
        algorithm,
        chacha: parsed.encryption_method.chacha,
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
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
) -> Result<(), CommandError> {
    let public_key = RsaPublicKey::from(private_key)
        .to_public_key_der()
        .map_err(|error| CommandError::Encryption(error.to_string()))?;
    ensure_leaf_certificate_matches_spki(certificate_der, public_key.as_bytes(), parsing)
}

fn ensure_leaf_certificate_matches_spki(
    certificate_der: &[u8],
    public_spki: &[u8],
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
) -> Result<(), CommandError> {
    // RFC 5280 §4.1.2.7: SPKI includes AlgorithmIdentifier and its parameters,
    // not just key bits. The companion must match this complete key identity.
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7
    if !certificate_public_key(certificate_der, parsing, |spki| spki == public_spki)
        .map_err(certificate_command_error)?
    {
        return Err(CommandError::Encryption(
            "X.509 certificate public key does not match private key".into(),
        ));
    }
    Ok(())
}

fn certificate_public_key<R>(
    certificate: &[u8],
    parsing: &mut xml_sec::xmldsig::parse::KeyInfoParsingSession<'_>,
    inspect: impl FnOnce(&[u8]) -> R,
) -> Result<R, xml_sec::xmldsig::ParseError> {
    parsing.with_certificate_public_key(certificate, inspect)
}

fn certificate_command_error(error: xml_sec::xmldsig::ParseError) -> CommandError {
    certificate_operation_error(error, CommandError::Encryption)
}

fn certificate_signing_error(error: xml_sec::xmldsig::ParseError) -> CommandError {
    certificate_operation_error(error, CommandError::Signature)
}

fn certificate_operation_error(
    error: xml_sec::xmldsig::ParseError,
    diagnostic: fn(String) -> CommandError,
) -> CommandError {
    match error {
        xml_sec::xmldsig::ParseError::Policy(error) => CommandError::Policy(error),
        error => diagnostic(error.to_string()),
    }
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
        .flat_map(Node::children)
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
        let requested_names: [&str; 0] = [];
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
    xml_policy: XmlInputPolicy,
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
    use std::fmt::Write as _;
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
        entries.push_str("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n");
        if let Some(name) = generated.parameter.as_deref() {
            writeln!(entries, "<KeyName>{}</KeyName>", escape_text(name))
                .expect("writing to a String cannot fail");
        }
        write!(
            entries,
            "<KeyValue>\n\
             <AESKeyValue xmlns=\"http://www.aleksey.com/xmlsec/2002\">{encoded}</AESKeyValue>\n\
             </KeyValue>\n\
             </KeyInfo>\n"
        )
        .expect("writing to a String cannot fail");
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
mod tests;
