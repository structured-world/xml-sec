use std::{collections::BTreeMap, ffi::OsString, fmt};

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
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub command: Command,
    pub options: BTreeMap<String, Vec<OptionValue>>,
    pub positional: Vec<String>,
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
        let remaining = args
            .map(|arg| arg.into_string().map_err(|_| ParseError::NonUtf8))
            .collect::<Result<Vec<_>, _>>()?;
        let mut options = BTreeMap::<String, Vec<OptionValue>>::new();
        let mut positional = Vec::new();
        let mut index = 0;
        let mut options_finished = false;
        while index < remaining.len() {
            let argument = &remaining[index];
            if argument == "--" {
                options_finished = true;
                index += 1;
                continue;
            }
            if options_finished || !argument.starts_with('-') {
                positional.push(argument.clone());
                options_finished = true;
                index += 1;
                continue;
            }
            let stripped = argument.trim_start_matches('-');
            let (raw_name, parameter) = stripped
                .split_once(':')
                .map_or((stripped, None), |(name, parameter)| {
                    (name, Some(parameter.to_owned()))
                });
            let name = canonical_option(raw_name)
                .ok_or_else(|| ParseError::UnsupportedOption(argument.clone()))?;
            let value = match option_arity(name) {
                Arity::Flag => None,
                Arity::Value => {
                    index += 1;
                    Some(
                        remaining
                            .get(index)
                            .filter(|value| !value.starts_with('-'))
                            .cloned()
                            .ok_or_else(|| ParseError::MissingOptionValue(argument.clone()))?,
                    )
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

    pub fn last_value(&self, name: &str) -> Option<&str> {
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
        "gen-key" => "gen-key",
        "privkey" | "privkey-pem" => "privkey-pem",
        "privkey-der" => "privkey-der",
        "pkcs8-pem" => "pkcs8-pem",
        "pkcs8-der" => "pkcs8-der",
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
        assert_eq!(parsed.last_value("output"), Some("signed.xml"));
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
        assert_eq!(parsed.positional, ["input.xml"]);
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
        assert_eq!(parsed.positional, ["input.xml", "--verbose"]);
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
}
