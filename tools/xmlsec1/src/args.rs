use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Help,
    HelpAll,
    HelpDsig,
    HelpEnc,
    HelpKeys,
    HelpX509,
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
    fn parse(value: &str) -> Option<Self> {
        let value = value.strip_prefix("--").unwrap_or(value);
        Some(match value {
            "help" | "-h" | "-?" => Self::Help,
            "help-all" => Self::HelpAll,
            "help-dsig" => Self::HelpDsig,
            "help-enc" => Self::HelpEnc,
            "help-keys" => Self::HelpKeys,
            "help-x509" => Self::HelpX509,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionValue {
    pub name: String,
    pub parameter: Option<String>,
    pub value: Option<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub command: Command,
    pub options: BTreeMap<String, Vec<OptionValue>>,
    pub positional: Vec<OsString>,
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
    aliases: &'static [&'static str],
    pub arity: Arity,
    pub accepts_parameter: bool,
}

const FLAG: Arity = Arity::Flag;
const VALUE: Arity = Arity::Value;

pub(crate) const OPTION_SPECS: &[OptionSpec] = &[
    OptionSpec {
        canonical: "output",
        aliases: &["o"],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "crypto",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "crypto-config",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "verbose",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "print-crypto-library-errors",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "print-debug",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "print-xml-debug",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "repeat",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "keys-file",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "gen-key",
        aliases: &["g"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "privkey-pem",
        aliases: &["privkey"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "privkey-der",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "pkcs8-pem",
        aliases: &["privkey-p8-pem"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "pkcs8-der",
        aliases: &["privkey-p8-der"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "pubkey-pem",
        aliases: &["pubkey"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "pubkey-der",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "pubkey-cert-pem",
        aliases: &["pubkey-cert"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "pubkey-cert-der",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "trusted-pem",
        aliases: &["trusted"],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "trusted-der",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "untrusted-pem",
        aliases: &["untrusted"],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "untrusted-der",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "aes-key",
        aliases: &["aeskey"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "hmac-key",
        aliases: &["hmackey"],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "pwd",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "enabled-key-data",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "enabled-reference-uris",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "enabled-retrieval-uris",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "enabled-cipher-reference-uris",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "ignore-manifests",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "lax-key-search",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "verify-keys",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "verify-crls",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "X509-skip-time-checks",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "X509-skip-strict-checks",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "insecure",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "verification-time",
        aliases: &["verification-gmt-time"],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "depth",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "node-id",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "node-name",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "node-xpath",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "id-attr",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "add-id-attr",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "binary-data",
        aliases: &["binary"],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "xml-data",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "session-key",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "url-map",
        aliases: &[],
        arity: VALUE,
        accepts_parameter: true,
    },
    OptionSpec {
        canonical: "enable-asn1-signatures-hack",
        aliases: &[],
        arity: FLAG,
        accepts_parameter: false,
    },
    OptionSpec {
        canonical: "help",
        aliases: &["h"],
        arity: FLAG,
        accepts_parameter: false,
    },
];

impl Invocation {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, ParseError> {
        let mut args = args.into_iter();
        let _program = args.next();
        let command_text = args.next().ok_or(ParseError::MissingCommand)?;
        let command_text = command_text
            .into_string()
            .map_err(|_| ParseError::NonUtf8)?;
        let command = Command::parse(&command_text)
            .ok_or_else(|| ParseError::UnknownCommand(command_text.clone()))?;
        let remaining = args.collect::<Vec<_>>();
        let mut options = BTreeMap::<String, Vec<OptionValue>>::new();
        let mut positional = Vec::new();
        let mut index = 0;
        let mut options_finished = false;
        while index < remaining.len() {
            let argument = &remaining[index];
            if argument == OsStr::new("--") {
                options_finished = true;
                index += 1;
                continue;
            }
            let option_text = argument.to_str();
            if options_finished
                || argument == OsStr::new("-")
                || !option_text.is_some_and(|value| value.starts_with('-'))
            {
                positional.push(argument.clone());
                options_finished = true;
                index += 1;
                continue;
            }
            let argument_text = option_text.ok_or(ParseError::NonUtf8)?;
            let stripped = argument_text.trim_start_matches('-');
            let (raw_name, parameter) = stripped
                .split_once(':')
                .map_or((stripped, None), |(name, parameter)| {
                    (name, Some(parameter.to_owned()))
                });
            let name = canonical_option(raw_name)
                .ok_or_else(|| ParseError::UnsupportedOption(argument_text.to_owned()))?;
            if parameter.is_some() && !option_spec(name).accepts_parameter {
                return Err(ParseError::UnexpectedOptionParameter(
                    argument_text.to_owned(),
                ));
            }
            let value =
                match option_arity(name) {
                    Arity::Flag => None,
                    Arity::Value => {
                        index += 1;
                        Some(remaining.get(index).cloned().ok_or_else(|| {
                            ParseError::MissingOptionValue(argument_text.to_owned())
                        })?)
                    }
                };
            options
                .entry(name.to_owned())
                .or_default()
                .push(OptionValue {
                    name: name.to_owned(),
                    parameter,
                    value,
                });
            index += 1;
        }
        Ok(Self {
            command,
            options,
            positional,
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

    pub fn values(&self, name: &str) -> impl Iterator<Item = &OptionValue> {
        self.options.get(name).into_iter().flatten()
    }
}

fn canonical_option(name: &str) -> Option<&'static str> {
    OPTION_SPECS
        .iter()
        .find(|spec| spec.canonical == name || spec.aliases.contains(&name))
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
        write!(formatter, "{:?}", self)
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
