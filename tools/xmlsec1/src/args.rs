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
    SignTemplate,
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
            "sign-tmpl" | "sign-template" => Self::SignTemplate,
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
    #[error("arguments are not valid UTF-8")]
    NonUtf8,
}

#[derive(Clone, Copy)]
enum Arity {
    Flag,
    Value,
}

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
    Some(match name {
        "o" | "output" => "output",
        "crypto" => "crypto",
        "crypto-config" => "crypto-config",
        "verbose" => "verbose",
        "print-crypto-library-errors" => "print-crypto-library-errors",
        "print-debug" => "print-debug",
        "print-xml-debug" => "print-xml-debug",
        "repeat" => "repeat",
        "keys-file" => "keys-file",
        "g" | "gen-key" => "gen-key",
        "privkey" | "privkey-pem" => "privkey-pem",
        "privkey-der" => "privkey-der",
        "pkcs8-pem" | "privkey-p8-pem" => "pkcs8-pem",
        "pkcs8-der" | "privkey-p8-der" => "pkcs8-der",
        "pubkey" | "pubkey-pem" => "pubkey-pem",
        "pubkey-der" => "pubkey-der",
        "pubkey-cert-pem" => "pubkey-cert-pem",
        "pubkey-cert-der" => "pubkey-cert-der",
        "trusted-pem" | "trusted" => "trusted-pem",
        "trusted-der" => "trusted-der",
        "untrusted-pem" | "untrusted" => "untrusted-pem",
        "untrusted-der" => "untrusted-der",
        "aes-key" | "aeskey" => "aes-key",
        "hmac-key" | "hmackey" => "hmac-key",
        "pwd" => "pwd",
        "enabled-key-data" => "enabled-key-data",
        "enabled-reference-uris" => "enabled-reference-uris",
        "enabled-retrieval-uris" => "enabled-retrieval-uris",
        "enabled-cipher-reference-uris" => "enabled-cipher-reference-uris",
        "ignore-manifests" => "ignore-manifests",
        "lax-key-search" => "lax-key-search",
        "verify-keys" => "verify-keys",
        "verify-crls" => "verify-crls",
        "X509-skip-time-checks" => "X509-skip-time-checks",
        "X509-skip-strict-checks" => "X509-skip-strict-checks",
        "insecure" => "insecure",
        "verification-time" | "verification-gmt-time" => "verification-time",
        "depth" => "depth",
        "node-id" => "node-id",
        "node-name" => "node-name",
        "node-xpath" => "node-xpath",
        "id-attr" => "id-attr",
        "add-id-attr" => "add-id-attr",
        "binary-data" => "binary-data",
        "xml-data" => "xml-data",
        "session-key" => "session-key",
        "url-map" => "url-map",
        "enable-asn1-signatures-hack" => "enable-asn1-signatures-hack",
        "help" => "help",
        _ => return None,
    })
}

fn option_arity(name: &str) -> Arity {
    match name {
        "verbose"
        | "print-crypto-library-errors"
        | "print-debug"
        | "print-xml-debug"
        | "ignore-manifests"
        | "lax-key-search"
        | "verify-keys"
        | "verify-crls"
        | "X509-skip-time-checks"
        | "X509-skip-strict-checks"
        | "insecure"
        | "enable-asn1-signatures-hack"
        | "help" => Arity::Flag,
        _ => Arity::Value,
    }
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
            "sign-tmpl",
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
        assert_eq!(parsed.command, Command::SignTemplate);
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
