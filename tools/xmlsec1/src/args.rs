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
        let target = Self::parse_direct(target)
            .map(HelpTarget::Command)
            .unwrap_or(HelpTarget::Unknown);
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
    option_spec!("pubkey-pem", ["pubkey"], VALUE, true, MULTIPLE),
    option_spec!("pubkey-der", [], VALUE, true, MULTIPLE),
    option_spec!("pubkey-cert-pem", ["pubkey-cert"], VALUE, true, MULTIPLE),
    option_spec!("pubkey-cert-der", [], VALUE, true, MULTIPLE),
    option_spec!("trusted-pem", ["trusted"], VALUE, false, MULTIPLE),
    option_spec!("trusted-der", [], VALUE, false, MULTIPLE),
    option_spec!("untrusted-pem", ["untrusted"], VALUE, false, MULTIPLE),
    option_spec!("untrusted-der", [], VALUE, false, MULTIPLE),
    option_spec!("aes-key", ["aeskey"], VALUE, true, MULTIPLE),
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
                positional.push(argument.clone());
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
                positional.push(argument.clone());
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

    pub fn flag(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }

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
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Invocation, ParseError> {
        Invocation::parse(arguments.iter().map(OsString::from))
    }

    #[test]
    fn parses_alias_named_and_repeated_options() {
        let parsed = parse(&[
            "xmlsec1",
            "sign",
            "-o",
            "signed.xml",
            "--privkey-pem:signer",
            "key.pem",
            "--trusted-pem",
            "root-a.pem",
            "--trusted-pem",
            "root-b.pem",
            "input.xml",
        ])
        .expect("valid donor-shaped arguments must parse");
        assert_eq!(parsed.command, Command::Sign);
        assert_eq!(parsed.last_value("output"), Some(OsStr::new("signed.xml")));
        assert_eq!(parsed.values("trusted-pem").count(), 2);
        assert_eq!(
            parsed
                .values("privkey-pem")
                .next()
                .unwrap()
                .parameter
                .as_deref(),
            Some("signer")
        );
        assert_eq!(parsed.positional, [OsString::from("input.xml")]);
    }

    #[test]
    fn preserves_global_order_across_option_names() {
        // Lax key lookup consumes compatible options in command-line order, so
        // grouping occurrences by canonical option name changes key selection.
        let parsed = parse(&[
            "xmlsec1",
            "sign",
            "--privkey-der",
            "first.der",
            "--privkey-pem",
            "second.pem",
            "--pkcs8-der",
            "third.der",
            "input.xml",
        ])
        .expect("mixed key encodings must parse");

        let values = parsed
            .ordered_values(&["privkey-pem", "privkey-der", "pkcs8-pem", "pkcs8-der"])
            .map(|option| option.value.as_deref().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            [
                OsStr::new("first.der"),
                OsStr::new("second.pem"),
                OsStr::new("third.der")
            ]
        );
    }

    #[test]
    fn password_is_not_retained_in_ordinary_option_storage() {
        // Password bytes must have one zeroizing owner and must never be
        // duplicated into debuggable option values.
        let parsed = parse(&["xmlsec1", "sign", "--pwd", "private-value", "input.xml"])
            .expect("password-bearing arguments must parse");

        assert!(parsed.flag("pwd"));
        assert_eq!(parsed.last_value("pwd"), None);
        assert_eq!(parsed.password_bytes(), Some(b"private-value".as_slice()));
        assert!(!format!("{parsed:?}").contains("private-value"));
    }

    #[test]
    fn parses_the_donor_leading_dash_command_aliases() {
        assert_eq!(
            parse(&["xmlsec1", "--verify", "input.xml"])
                .unwrap()
                .command,
            Command::Verify
        );
        assert_eq!(
            parse(&["xmlsec1", "--list-transforms"]).unwrap().command,
            Command::ListTransforms
        );
    }

    #[test]
    fn rejects_options_after_input_like_the_donor_parser() {
        let parsed = parse(&["xmlsec1", "verify", "input.xml", "--verbose"])
            .expect("the donor treats trailing options as filenames");
        assert_eq!(
            parsed.positional,
            [OsString::from("input.xml"), OsString::from("--verbose")]
        );
        assert!(!parsed.flag("verbose"));
    }

    #[test]
    fn preserves_sentinels_after_option_parsing_has_finished() {
        // Only the first sentinel changes parser state; later tokens named `--`
        // are filenames and must reach command-level input cardinality checks.
        let after_sentinel = parse(&["xmlsec1", "verify", "--", "--"]).unwrap();
        assert_eq!(after_sentinel.positional, [OsString::from("--")]);

        let after_input = parse(&["xmlsec1", "verify", "input.xml", "--"]).unwrap();
        assert_eq!(
            after_input.positional,
            [OsString::from("input.xml"), OsString::from("--")]
        );
    }

    #[test]
    fn rejects_unknown_and_missing_option_values() {
        assert!(matches!(
            parse(&["xmlsec1", "verify", "--made-up"]),
            Err(ParseError::UnsupportedOption(_))
        ));
        assert!(matches!(
            parse(&["xmlsec1", "verify", "--output"]),
            Err(ParseError::MissingOptionValue(_))
        ));
        assert!(
            parse(&["xmlsec1", "verify", "--insecure:false", "input.xml"]).is_err(),
            "flag parameters must not silently enable the underlying flag"
        );
        assert!(
            parse(&[
                "xmlsec1",
                "verify",
                "--trusted-pem:anchor",
                "root.pem",
                "input.xml"
            ])
            .is_err(),
            "only key options with named lookup semantics accept parameters"
        );
    }

    #[test]
    fn rejects_non_donor_option_prefixes() {
        for option in ["---output", "-output", "--o"] {
            assert!(
                matches!(
                    parse(&["xmlsec1", "verify", option, "value", "input.xml"]),
                    Err(ParseError::UnsupportedOption(rejected)) if rejected == option
                ),
                "unexpectedly accepted {option}"
            );
        }
    }

    #[test]
    fn every_registered_alias_resolves_to_its_canonical_option() {
        for spec in OPTION_SPECS {
            for alias in spec.aliases {
                let short = alias.len() == 1;
                assert_eq!(canonical_option(alias, short), Some(spec.canonical));
                assert_eq!(canonical_option(alias, !short), None);
            }
            assert_eq!(
                canonical_option(spec.canonical, false),
                Some(spec.canonical)
            );
        }
    }

    #[test]
    fn command_display_uses_donor_vocabulary() {
        assert_eq!(Command::ListKeyData.to_string(), "list-key-data");
    }

    #[test]
    fn command_parser_uses_exact_donor_help_grammar() {
        for target in Command::ALL
            .iter()
            .copied()
            .filter(|target| !matches!(target, Command::Help | Command::HelpAll))
        {
            for command in [
                format!("help-{}", target.canonical_name()),
                format!("--help-{}", target.canonical_name()),
            ] {
                let parsed = Invocation::parse([OsString::from("xmlsec1"), command.into()])
                    .expect("donor help command");
                assert_eq!(parsed.command, Command::Help);
                assert_eq!(parsed.help_target, Some(HelpTarget::Command(target)));
            }
        }

        for command in ["help-dsig", "help-enc", "help-x509"] {
            let parsed = parse(&["xmlsec1", command]).expect("donor help prefix");
            assert_eq!(parsed.command, Command::Help);
            assert_eq!(parsed.help_target, Some(HelpTarget::Unknown));
        }
        for command in ["---h", "---?"] {
            assert!(
                matches!(
                    parse(&["xmlsec1", command]),
                    Err(ParseError::UnknownCommand(rejected)) if rejected == command
                ),
                "unexpectedly accepted {command}"
            );
        }
    }

    #[test]
    fn rejects_repeated_singleton_options_across_aliases() {
        for arguments in [
            &[
                "xmlsec1",
                "sign",
                "--output",
                "first.xml",
                "-o",
                "second.xml",
                "input.xml",
            ][..],
            &[
                "xmlsec1",
                "verify",
                "--node-id",
                "first",
                "--node-id",
                "second",
                "input.xml",
            ],
            &["xmlsec1", "verify", "--insecure", "--insecure", "input.xml"],
        ] {
            assert!(parse(arguments).is_err(), "{arguments:?}");
        }
    }

    #[test]
    fn consumes_dash_prefixed_option_values_verbatim() {
        // Option arity, not the first byte of its value, determines parsing.
        let parsed = parse(&["xmlsec1", "verify", "--pubkey-pem", "-key.pem", "input.xml"])
            .expect("the donor consumes the argument after a valued option");
        assert_eq!(
            parsed.last_value("pubkey-pem"),
            Some(OsStr::new("-key.pem"))
        );
    }

    #[test]
    fn parses_the_stdin_marker_as_positional_input() {
        let parsed = parse(&["xmlsec1", "verify", "--pubkey-pem", "key.pem", "-"])
            .expect("a lone dash is the donor stdin marker");
        assert_eq!(parsed.positional, [OsString::from("-")]);
    }

    #[test]
    fn recognizes_donor_key_generation_and_pkcs8_aliases() {
        // These spellings are used by unmodified donor automation.
        let generated = parse(&["xmlsec1", "keys", "-g:session", "aes-128"])
            .expect("short key-generation alias must parse");
        assert_eq!(generated.values("gen-key").count(), 1);

        for alias in ["--privkey-p8-pem", "--privkey-p8-der"] {
            let parsed = parse(&["xmlsec1", "sign", alias, "key.p8", "template.xml"])
                .expect("PKCS#8 donor alias must parse");
            assert_eq!(
                parsed
                    .values(if alias.ends_with("pem") {
                        "pkcs8-pem"
                    } else {
                        "pkcs8-der"
                    })
                    .count(),
                1
            );
        }
    }

    #[test]
    fn recognizes_all_aliases_for_native_donor_options() {
        // The pinned donor metadata is the source of truth for aliases; accepting
        // only each canonical spelling breaks otherwise native command lines.
        for (alias, canonical) in [
            ("--pubkey-cert", "pubkey-cert-pem"),
            ("--binary", "binary-data"),
        ] {
            let parsed = parse(&["xmlsec1", "verify", alias, "value", "input.xml"])
                .expect("native donor alias must parse");
            assert_eq!(parsed.values(canonical).count(), 1, "alias {alias}");
        }

        let parsed = parse(&["xmlsec1", "verify", "-h", "input.xml"])
            .expect("short command-help alias must parse");
        assert!(parsed.flag("help"));
    }

    #[test]
    fn rejects_commands_absent_from_the_pinned_donor_surface() {
        // libxmlsec1 1.3.13 has no sign-tmpl command. Advertising it as an alias
        // for sign would claim template generation while requiring a template.
        assert!(matches!(
            parse(&["xmlsec1", "sign-tmpl"]),
            Err(ParseError::UnknownCommand(command)) if command == "sign-tmpl"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_filesystem_arguments() {
        // Unix paths are opaque bytes and must not pass through String.
        use std::os::unix::ffi::OsStringExt as _;

        let path = OsString::from_vec(vec![b'i', b'n', 0xff]);
        let parsed = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("verify"),
            OsString::from("--pubkey-pem"),
            path.clone(),
            path.clone(),
        ])
        .expect("filesystem arguments are opaque bytes on Unix");
        assert_eq!(parsed.last_value("pubkey-pem"), Some(path.as_os_str()));
        assert_eq!(parsed.positional, [path]);
    }
}
