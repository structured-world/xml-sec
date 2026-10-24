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
