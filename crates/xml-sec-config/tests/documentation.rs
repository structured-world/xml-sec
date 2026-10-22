use xml_sec::{policy::PolicyCompileContext, provider::RustCryptoProvider};
use xml_sec_config::{Configuration, LoadLimits};

#[test]
fn documented_schema_sample_restricts_and_round_trips() {
    // Test the exact published sample, not a separately maintained equivalent.
    let source = include_str!("../../../docs/examples/policy-v1.toml");
    let config = Configuration::from_str(source, LoadLimits::default()).unwrap();
    let context = PolicyCompileContext {
        external_resources: false,
        target_evidence: true,
    };
    for (name, maximum, signing) in [
        ("system", 10000, true),
        ("application", 5000, true),
        ("tenant", 1000, false),
    ] {
        let effective = config
            .compile(name, &RustCryptoProvider, &context, None)
            .unwrap();
        assert_eq!(
            effective
                .compiled()
                .verification()
                .unwrap()
                .resources
                .max_xml_nodes,
            maximum
        );
        assert_eq!(effective.compiled().signing().is_some(), signing);
        let text = effective.to_toml().unwrap();
        let restored = Configuration::from_str(&text, LoadLimits::default())
            .unwrap()
            .compile("effective", &RustCryptoProvider, &context, None)
            .unwrap();
        assert_eq!(restored.to_toml().unwrap(), text);
        assert!(effective.diff(&restored).is_empty());
    }
    // A plausible child ceiling cannot undo inherited restrictions.
    let wider = source.replace("max_xml_nodes = 1000\n", "max_xml_nodes = 20000\n");
    let wider = Configuration::from_str(&wider, LoadLimits::default())
        .unwrap()
        .compile("tenant", &RustCryptoProvider, &context, None)
        .unwrap();
    assert_eq!(
        wider
            .compiled()
            .verification()
            .unwrap()
            .resources
            .max_xml_nodes,
        5000
    );
    // Disabled means disabled: even a child explicitly asking for signing fails.
    let reenable = format!(
        "{source}\n[profiles.child]\nextends='tenant'\n[profiles.child.signing]\nenabled=true\n"
    );
    let reenable = Configuration::from_str(&reenable, LoadLimits::default()).unwrap();
    assert!(
        reenable
            .compile("child", &RustCryptoProvider, &context, None)
            .is_err()
    );
}
