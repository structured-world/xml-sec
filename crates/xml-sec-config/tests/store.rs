use std::collections::BTreeMap;
use std::sync::Barrier;
use xml_sec::{
    XmlSecurity,
    api::Operation,
    policy::{CompiledPolicies, Instant, PolicyCompileContext, PolicyValidity},
    provider::default_provider,
    xmldsig::{DigestAlgorithm, compute_digest},
};
use xml_sec_config::{Configuration, LoadLimits, PolicyStore, Source};

const CONTEXT: PolicyCompileContext = PolicyCompileContext {
    external_resources: false,
    target_evidence: true,
};

/// Tenants `a` and `b` over one system profile, each with its own node limit.
fn tenants(a_nodes: usize, b_nodes: usize) -> Configuration {
    Configuration::from_str(
        &format!(
            "schema_version = 1\n\
             [profiles.system]\nbase = 'Modern'\n\
             [profiles.a]\nextends = 'system'\n\
             [profiles.a.verification.resources]\nmax_xml_nodes = {a_nodes}\n\
             [profiles.b]\nextends = 'system'\n\
             [profiles.b.verification.resources]\nmax_xml_nodes = {b_nodes}\n"
        ),
        LoadLimits::default(),
    )
    .expect("tenant configuration")
}

fn source<'a>(configuration: &'a Configuration, profile: &'a str) -> Source<'a> {
    Source {
        configuration,
        profile,
        provider: default_provider(),
        context: &CONTEXT,
        authorization: None,
    }
}

fn nodes(snapshot: &CompiledPolicies) -> usize {
    snapshot
        .verification()
        .expect("verification enabled")
        .resources
        .max_xml_nodes
}

fn revision(snapshot: &CompiledPolicies) -> u64 {
    snapshot.identity().expect("published identity").revision()
}

/// The digest a snapshot of `profile` must carry: SHA-256 of its canonical
/// effective settings.
fn expected_digest(configuration: &Configuration, profile: &str) -> [u8; 32] {
    let effective = configuration
        .compile(profile, default_provider(), &CONTEXT, None)
        .expect("compiled");
    compute_digest(
        DigestAlgorithm::Sha256,
        effective.to_toml().expect("effective output").as_bytes(),
    )
    .try_into()
    .expect("SHA-256")
}

#[test]
fn the_first_publication_is_revision_one_of_its_profile() {
    // The identity names the profile, schema and revision, and digests exactly
    // the canonical effective settings the snapshot enforces.
    let configuration = tenants(500, 600);
    let store = PolicyStore::new(source(&configuration, "a")).expect("store");
    let snapshot = store.load();
    let identity = snapshot.identity().expect("identity");
    assert_eq!(identity.profile(), "a");
    assert_eq!(identity.schema_version(), xml_sec_config::SCHEMA_VERSION);
    assert_eq!(identity.revision(), 1);
    assert_eq!(identity.digest(), &expected_digest(&configuration, "a"));
    assert_eq!(nodes(&snapshot), 500);
}

#[test]
fn equal_effective_settings_have_equal_digests_whatever_their_layout() {
    // The digest identifies the enforced settings, not the file: inheritance
    // and explicit repetition of the same values digest alike, other values not.
    let inherited = tenants(500, 600);
    let flat = Configuration::from_str(
        "schema_version = 1\n[profiles.a]\nbase = 'Modern'\n\
         [profiles.a.verification.resources]\nmax_xml_nodes = 500\n",
        LoadLimits::default(),
    )
    .expect("flat configuration");
    let digest = |configuration: &Configuration| {
        *PolicyStore::new(source(configuration, "a"))
            .expect("store")
            .load()
            .identity()
            .expect("identity")
            .digest()
    };
    assert_eq!(digest(&inherited), digest(&flat));
    assert_ne!(digest(&inherited), digest(&tenants(501, 600)));
}

#[test]
fn a_replacement_is_the_next_revision_and_leaves_taken_snapshots_alone() {
    // An operation keeps the snapshot it took, so it never enforces two
    // revisions; the store hands the replacement to later operations only.
    let store = PolicyStore::new(source(&tenants(500, 600), "a")).expect("store");
    let taken = store.load();
    let security = XmlSecurity::new(&taken, default_provider()).expect("bound");
    let replacement = tenants(5000, 600);
    let published = store.replace(source(&replacement, "a")).expect("replaced");
    assert_eq!(revision(&published), 2);
    assert_eq!(nodes(&published), 5000);
    assert_eq!(revision(&store.load()), 2);
    assert_eq!(revision(&taken), 1);
    assert_eq!(nodes(&taken), 500);
    // 600 nodes fit the replacement but not the snapshot this binding took.
    let document = format!("<r>{}</r>", "<e/>".repeat(599));
    assert!(
        security
            .parse_document(document.as_str(), Operation::Verify)
            .is_err()
    );
    let current = store.load();
    let replaced = XmlSecurity::new(&current, default_provider()).expect("bound");
    assert!(replaced.parse_document(document, Operation::Verify).is_ok());
}

#[test]
fn a_refused_replacement_publishes_nothing() {
    // Validation and compilation finish before publication: an expired grant
    // or another profile leaves the current revision in force and unnumbered.
    let configuration = tenants(500, 600);
    let store = PolicyStore::new(source(&configuration, "a")).expect("store");
    let expired = PolicyValidity {
        authorization_id: "change-7".into(),
        authority: "security-officer".into(),
        reason: "migration window".into(),
        not_before: Instant::new(0, 0).expect("epoch"),
        expires_at: Instant::new(1, 0).expect("one second"),
    };
    let refused = store.replace(Source {
        authorization: Some(expired),
        ..source(&tenants(9000, 600), "a")
    });
    assert!(refused.is_err());
    assert!(store.replace(source(&configuration, "b")).is_err());
    let current = store.load();
    assert_eq!((revision(&current), nodes(&current)), (1, 500));
    let next = store
        .replace(source(&tenants(700, 600), "a"))
        .expect("replaced");
    assert_eq!(revision(&next), 2);
}

#[test]
fn tenants_publish_independently() {
    // A tenant's store only ever publishes its own profile; replacing one
    // tenant's policy changes nothing another tenant enforces.
    let configuration = tenants(500, 600);
    let a = PolicyStore::new(source(&configuration, "a")).expect("store a");
    let b = PolicyStore::new(source(&configuration, "b")).expect("store b");
    a.replace(source(&tenants(5000, 6000), "a"))
        .expect("replaced a");
    let (a, b) = (a.load(), b.load());
    assert_eq!((nodes(&a), revision(&a)), (5000, 2));
    assert_eq!((nodes(&b), revision(&b)), (600, 1));
    assert_eq!(b.identity().expect("identity").profile(), "b");
}

#[test]
fn concurrent_replacements_publish_every_revision_once_and_in_order() {
    // Under concurrent publication and loading every loaded snapshot is one
    // whole publication: its settings match its digest, each reader sees
    // revisions in increasing order, and the revisions are exactly 1..=N+1.
    const PUBLISHERS: usize = 4;
    const PER_PUBLISHER: usize = 25;
    const READERS: usize = 4;
    let limits: Vec<usize> = (0..PUBLISHERS).map(|index| 1000 + index).collect();
    let configurations: Vec<Configuration> =
        limits.iter().map(|&limit| tenants(limit, 600)).collect();
    let mut digests = BTreeMap::new();
    digests.insert(expected_digest(&tenants(500, 600), "a"), 500);
    for (configuration, &limit) in configurations.iter().zip(&limits) {
        digests.insert(expected_digest(configuration, "a"), limit);
    }
    let initial = tenants(500, 600);
    let store = PolicyStore::new(source(&initial, "a")).expect("store");
    let start = Barrier::new(PUBLISHERS + READERS);
    let published = std::thread::scope(|scope| {
        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    let mut last = 0;
                    for _ in 0..PUBLISHERS * PER_PUBLISHER {
                        let snapshot = store.load();
                        let identity = snapshot.identity().expect("identity");
                        assert_eq!(digests.get(identity.digest()), Some(&nodes(&snapshot)));
                        assert!(identity.revision() >= last, "revision went backwards");
                        last = identity.revision();
                    }
                })
            })
            .collect();
        let publishers: Vec<_> = configurations
            .iter()
            .map(|configuration| {
                scope.spawn(|| {
                    start.wait();
                    (0..PER_PUBLISHER)
                        .map(|_| {
                            revision(
                                &store
                                    .replace(source(configuration, "a"))
                                    .expect("published"),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for reader in readers {
            reader.join().expect("reader");
        }
        publishers
            .into_iter()
            .flat_map(|publisher| publisher.join().expect("publisher"))
            .collect::<Vec<_>>()
    });
    let mut revisions = published;
    revisions.sort_unstable();
    let expected: Vec<u64> = (2..=u64::try_from(PUBLISHERS * PER_PUBLISHER + 1).unwrap()).collect();
    assert_eq!(revisions, expected);
    assert_eq!(revision(&store.load()), *expected.last().unwrap());
}
