//! Donor-compatible command-line grammar.
//!
//! This layer recognizes option names, aliases, arity, and repetition only.
//! Applicability belongs to command validation: a known option used with the
//! wrong command must be reported as recognized but inapplicable, with both
//! names in the diagnostic, rather than as malformed syntax.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Help,
    HelpAll,
    Version,
    ListKeyData,
    CheckKeyData,
    ListTransforms,
    CheckTransforms,
    Keys,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
}

impl Command {
    pub(crate) const ALL: &[Self] = &[
        Self::Help,
        Self::HelpAll,
        Self::Version,
        Self::ListKeyData,
        Self::CheckKeyData,
        Self::ListTransforms,
        Self::CheckTransforms,
        Self::Keys,
        Self::Sign,
        Self::Verify,
        Self::Encrypt,
        Self::Decrypt,
    ];

    pub(crate) const fn canonical_name(self) -> &'static str {
        match self {
            Self::Help => "help",
            Self::HelpAll => "help-all",
            Self::Version => "version",
            Self::ListKeyData => "list-key-data",
            Self::CheckKeyData => "check-key-data",
            Self::ListTransforms => "list-transforms",
            Self::CheckTransforms => "check-transforms",
            Self::Keys => "keys",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
        }
    }

    fn parse_direct(value: &str) -> Option<Self> {
        Some(match value {
            "help" => Self::Help,
            "help-all" => Self::HelpAll,
            "version" => Self::Version,
            "list-key-data" | "list-key-data-klasses" => Self::ListKeyData,
            "check-key-data" | "check-key-data-klass" => Self::CheckKeyData,
            "list-transforms" => Self::ListTransforms,
            "check-transforms" => Self::CheckTransforms,
            "keys" => Self::Keys,
            "sign" => Self::Sign,
            "verify" => Self::Verify,
            "encrypt" => Self::Encrypt,
            "decrypt" => Self::Decrypt,
            _ => return None,
        })
    }

    fn parse(value: &str) -> Option<(Self, Option<HelpTarget>)> {
        let value = if let Some(long) = value.strip_prefix("--") {
            if long.starts_with('-') {
                return None;
            }
            long
        } else {
            if value.starts_with('-') {
                return None;
            }
            value
        };
        if let Some(command) = Self::parse_direct(value) {
            return Some((command, None));
        }
        let target = value.strip_prefix("help-")?;
        let target = Self::parse_direct(target).map_or(HelpTarget::Unknown, HelpTarget::Command);
        Some((Self::Help, Some(target)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelpTarget {
    Command(Command),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionValue {
    pub name: String,
    pub parameter: Option<String>,
    pub value: Option<OsString>,
}

#[derive(PartialEq, Eq)]
pub struct Invocation {
    pub command: Command,
    pub(crate) help_target: Option<HelpTarget>,
    pub options: BTreeMap<String, Vec<OptionValue>>,
    ordered_options: Vec<OptionValue>,
    pub positional: Vec<OsString>,
    password: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for Invocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Invocation")
            .field("command", &self.command)
            .field("help_target", &self.help_target)
            .field("options", &self.options)
            .field("ordered_options", &self.ordered_options)
            .field("positional", &self.positional)
            .field("password_present", &self.password.is_some())
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("command is required")]
    MissingCommand,
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("option {0} requires a value")]
    MissingOptionValue(String),
    #[error("unsupported option: {0}")]
    UnsupportedOption(String),
    #[error("option {0} does not accept a name parameter")]
    UnexpectedOptionParameter(String),
    #[error("option {0} cannot be repeated")]
    RepeatedOption(String),
    #[error("arguments are not valid UTF-8")]
    NonUtf8,
}

#[derive(Clone, Copy)]
pub(crate) enum Arity {
    Flag,
    Value,
}

pub(crate) struct OptionSpec {
    pub canonical: &'static str,
    pub aliases: &'static [&'static str],
    pub arity: Arity,
    pub accepts_parameter: bool,
    repeatability: Repeatability,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Repeatability {
    Singleton,
    Multiple,
}

const FLAG: Arity = Arity::Flag;
const VALUE: Arity = Arity::Value;
const SINGLE: Repeatability = Repeatability::Singleton;
const MULTIPLE: Repeatability = Repeatability::Multiple;

macro_rules! option_spec {
    ($canonical:literal, [$($alias:literal),* $(,)?], $arity:expr, $parameter:expr, $repeatability:expr) => {
        OptionSpec {
            canonical: $canonical,
            aliases: &[$($alias),*],
            arity: $arity,
            accepts_parameter: $parameter,
            repeatability: $repeatability,
        }
    };
}

pub(crate) const OPTION_SPECS: &[OptionSpec] = &[
    option_spec!("output", ["o"], VALUE, false, SINGLE),
    option_spec!("crypto", [], VALUE, false, SINGLE),
    option_spec!("xml-backend", [], VALUE, false, SINGLE),
    option_spec!("crypto-config", [], VALUE, false, SINGLE),
    option_spec!("verbose", [], FLAG, false, SINGLE),
    option_spec!("print-crypto-library-errors", [], FLAG, false, SINGLE),
    option_spec!("print-debug", [], FLAG, false, SINGLE),
    option_spec!("print-xml-debug", [], FLAG, false, SINGLE),
    option_spec!("repeat", [], VALUE, false, SINGLE),
    option_spec!("keys-file", [], VALUE, false, MULTIPLE),
    option_spec!("gen-key", ["g"], VALUE, true, MULTIPLE),
    option_spec!("privkey-pem", ["privkey"], VALUE, true, MULTIPLE),
    option_spec!("privkey-der", [], VALUE, true, MULTIPLE),
    option_spec!("pkcs8-pem", ["privkey-p8-pem"], VALUE, true, MULTIPLE),
    option_spec!("pkcs8-der", ["privkey-p8-der"], VALUE, true, MULTIPLE),
    option_spec!("pkcs12", [], VALUE, true, MULTIPLE),
    option_spec!("pubkey-pem", ["pubkey"], VALUE, true, MULTIPLE),
    option_spec!("pubkey-der", [], VALUE, true, MULTIPLE),
    option_spec!("pubkey-cert-pem", ["pubkey-cert"], VALUE, true, MULTIPLE),
    option_spec!("pubkey-cert-der", [], VALUE, true, MULTIPLE),
    option_spec!("trusted-pem", ["trusted"], VALUE, false, MULTIPLE),
    option_spec!("trusted-der", [], VALUE, false, MULTIPLE),
    option_spec!("untrusted-pem", ["untrusted"], VALUE, false, MULTIPLE),
    option_spec!("untrusted-der", [], VALUE, false, MULTIPLE),
    option_spec!("aes-key", ["aeskey"], VALUE, true, MULTIPLE),
    #[cfg(feature = "legacy-algorithms")]
    option_spec!("des-key", ["deskey"], VALUE, true, MULTIPLE),
    option_spec!("hmac-key", ["hmackey"], VALUE, true, MULTIPLE),
    option_spec!("pwd", [], VALUE, false, SINGLE),
    option_spec!("enabled-key-data", [], VALUE, false, MULTIPLE),
    option_spec!("enabled-reference-uris", [], VALUE, false, SINGLE),
    option_spec!("enabled-retrieval-method-uris", [], VALUE, false, SINGLE),
    option_spec!("enabled-cipher-reference-uris", [], VALUE, false, SINGLE),
    option_spec!("ignore-manifests", [], FLAG, false, SINGLE),
    option_spec!("lax-key-search", [], FLAG, false, SINGLE),
    option_spec!("verify-keys", [], FLAG, false, SINGLE),
    option_spec!("verify-crls", [], FLAG, false, SINGLE),
    option_spec!("utc-facts", [], VALUE, false, SINGLE),
    option_spec!("X509-skip-time-checks", [], FLAG, false, SINGLE),
    option_spec!("X509-skip-strict-checks", [], FLAG, false, SINGLE),
    option_spec!("insecure", [], FLAG, false, SINGLE),
    option_spec!(
        "verification-time",
        ["verification-gmt-time"],
        VALUE,
        false,
        SINGLE
    ),
    option_spec!("depth", [], VALUE, false, SINGLE),
    option_spec!("node-id", [], VALUE, false, SINGLE),
    option_spec!("node-name", [], VALUE, false, SINGLE),
    option_spec!("node-xpath", [], VALUE, false, SINGLE),
    option_spec!("id-attr", [], VALUE, true, MULTIPLE),
    option_spec!("add-id-attr", [], VALUE, false, MULTIPLE),
    option_spec!("binary-data", ["binary"], VALUE, false, SINGLE),
    option_spec!("xml-data", [], VALUE, false, SINGLE),
    option_spec!("session-key", [], VALUE, false, SINGLE),
    option_spec!("url-map", [], VALUE, true, MULTIPLE),
    option_spec!("enable-visa3d-hack", [], FLAG, false, SINGLE),
    option_spec!("enable-asn1-signatures-hack", [], FLAG, false, SINGLE),
    option_spec!("help", ["h"], FLAG, false, SINGLE),
];

impl Invocation {
    /// Parse `argv` with libxmlsec1's command, option and positional rules.
    ///
    /// # Errors
    /// Returns a missing, non-UTF-8 or unknown command, and an unsupported,
    /// repeated, parameterized or value-less option.
    ///
    /// # Panics
    /// Never: option-shaped arguments are checked to be UTF-8 and to start
    /// with a dash before they are split.
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, ParseError> {
        let mut args = args.into_iter();
        let _program = args.next();
        let command_text = args.next().ok_or(ParseError::MissingCommand)?;
        let command_text = command_text
            .into_string()
            .map_err(|_| ParseError::NonUtf8)?;
        let (command, help_target) = Command::parse(&command_text)
            .ok_or_else(|| ParseError::UnknownCommand(command_text.clone()))?;
        let mut remaining = args.collect::<Vec<_>>();
        let mut options = BTreeMap::<String, Vec<OptionValue>>::new();
        let mut ordered_options = Vec::new();
        let mut positional = Vec::new();
        let mut password = None;
        let mut index = 0;
        let mut options_finished = false;
        while index < remaining.len() {
            let argument = &remaining[index];
            if options_finished {
                positional.push(std::mem::take(&mut remaining[index]));
                index += 1;
                continue;
            }
            if argument == OsStr::new("--") {
                options_finished = true;
                index += 1;
                continue;
            }
            let option_text = argument.to_str();
            if argument == OsStr::new("-")
                || !option_text.is_some_and(|value| value.starts_with('-'))
            {
                positional.push(std::mem::take(&mut remaining[index]));
                options_finished = true;
                index += 1;
                continue;
            }
            // libxmlsec1 distinguishes long names from short aliases by their
            // exact prefix; accepting arbitrary leading dashes changes argv.
            let argument_text = option_text.expect("option-shaped arguments are valid UTF-8");
            let (stripped, alias_only) = if let Some(long) = argument_text.strip_prefix("--") {
                (long, false)
            } else {
                (
                    argument_text
                        .strip_prefix('-')
                        .expect("option-shaped arguments start with a dash"),
                    true,
                )
            };
            let (raw_name, parameter) = stripped
                .split_once(':')
                .map_or((stripped, None), |(name, parameter)| {
                    (name, Some(parameter.to_owned()))
                });
            let name = canonical_option(raw_name, alias_only)
                .ok_or_else(|| ParseError::UnsupportedOption(argument_text.to_owned()))?;
            if parameter.is_some() && !option_spec(name).accepts_parameter {
                return Err(ParseError::UnexpectedOptionParameter(
                    argument_text.to_owned(),
                ));
            }
            if option_spec(name).repeatability == Repeatability::Singleton
                && options.contains_key(name)
            {
                return Err(ParseError::RepeatedOption(format!("--{name}")));
            }
            let missing_value_error = argument_text.to_owned();
            let value = match option_arity(name) {
                Arity::Flag => None,
                Arity::Value => {
                    index += 1;
                    let raw = remaining
                        .get_mut(index)
                        .map(std::mem::take)
                        .ok_or(ParseError::MissingOptionValue(missing_value_error))?;
                    if name == "pwd" {
                        password = Some(Zeroizing::new(raw.into_encoded_bytes()));
                        None
                    } else {
                        Some(raw)
                    }
                }
            };
            let option = OptionValue {
                name: name.to_owned(),
                parameter,
                value,
            };
            ordered_options.push(option.clone());
            options.entry(name.to_owned()).or_default().push(option);
            index += 1;
        }
        Ok(Self {
            command,
            help_target,
            options,
            ordered_options,
            positional,
            password,
        })
    }

    #[must_use]
    pub fn flag(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }

    #[must_use]
    pub fn last_value(&self, name: &str) -> Option<&OsStr> {
        self.options
            .get(name)
            .and_then(|values| values.last())
            .and_then(|entry| entry.value.as_deref())
    }

    pub(crate) fn password_bytes(&self) -> Option<&[u8]> {
        self.password.as_deref().map(Vec::as_slice)
    }

    pub fn values(&self, name: &str) -> impl Iterator<Item = &OptionValue> {
        self.options.get(name).into_iter().flatten()
    }

    pub fn ordered_values<'a>(
        &'a self,
        names: &'a [&str],
    ) -> impl Iterator<Item = &'a OptionValue> {
        self.ordered_options
            .iter()
            .filter(move |option| names.contains(&option.name.as_str()))
    }
}

fn canonical_option(name: &str, alias_only: bool) -> Option<&'static str> {
    OPTION_SPECS
        .iter()
        .find(|spec| {
            if alias_only {
                name.len() == 1 && spec.aliases.contains(&name)
            } else {
                spec.canonical == name || (name.len() > 1 && spec.aliases.contains(&name))
            }
        })
        .map(|spec| spec.canonical)
}

fn option_arity(name: &str) -> Arity {
    option_spec(name).arity
}

fn option_spec(name: &str) -> &'static OptionSpec {
    OPTION_SPECS
        .iter()
        .find(|spec| spec.canonical == name)
        .expect("canonical options must have metadata")
}

impl fmt::Display for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical_name())
    }
}

#[cfg(test)]
mod tests;
