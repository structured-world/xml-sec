use super::{
    XMLENC_CORPORA, corpora_inventory, default_paths, donor_path, execute, import, normalize,
};
use std::path::Path;

fn write(path: &Path, text: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A donor tree and a fixture tree in one temporary directory.
struct Trees {
    _directory: tempfile::TempDir,
    donor: std::path::PathBuf,
    fixtures: std::path::PathBuf,
}

impl Trees {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let donor = directory.path().join("donor");
        let fixtures = directory.path().join("tests/fixtures");
        std::fs::create_dir_all(&donor).unwrap();
        std::fs::create_dir_all(&fixtures).unwrap();
        Self {
            _directory: directory,
            donor,
            fixtures,
        }
    }

    fn import(&self, args: &[&str]) -> Result<(), String> {
        execute(
            &self.donor,
            &self.fixtures,
            args.iter().map(|arg| (*arg).to_owned()).collect(),
        )
    }

    fn names(&self, relative: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.fixtures.join(relative))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

#[test]
fn a_complete_xmlenc_import_keeps_every_corpus_byte_and_pins_it() {
    // Corpus acceptance needs whole snapshots, nested key material and binary
    // payloads included, not a curated list of XML vectors.
    let trees = Trees::new();
    let payloads: [(&str, &[u8]); 3] = [
        ("vector.xml", b"<EncryptedData/>"),
        ("keys/private.der", &[0, 0xff, 1, 0x80]),
        ("unlisted extra.data", b"not in a curated vector list\r\n"),
    ];
    for corpus in XMLENC_CORPORA {
        let donor = corpus.strip_prefix("xmlenc/").unwrap();
        for (name, bytes) in payloads {
            write(&trees.donor.join(donor).join(name), bytes);
        }
        write(
            &trees.fixtures.join(corpus).join("obsolete.xml"),
            "obsolete",
        );
    }
    trees.import(&["--xmlenc-corpora"]).unwrap();
    for corpus in XMLENC_CORPORA {
        for (name, bytes) in payloads {
            assert_eq!(
                std::fs::read(trees.fixtures.join(corpus).join(name)).unwrap(),
                bytes,
                "{corpus}/{name}"
            );
        }
        assert!(!trees.fixtures.join(corpus).join("obsolete.xml").exists());
    }
    let manifest = std::fs::read_to_string(trees.fixtures.join("xmlenc/corpora.sha256")).unwrap();
    assert_eq!(
        manifest.lines().count(),
        XMLENC_CORPORA.len() * payloads.len()
    );
    for corpus in XMLENC_CORPORA {
        for (name, _) in payloads {
            assert!(
                manifest
                    .lines()
                    .any(|line| line.ends_with(&format!("  {corpus}/{name}")))
            );
        }
    }
    assert!(
        trees
            .import(&["--xmlenc-corpora", "xmlenc/nist-aesgcm"])
            .is_err()
    );
}

#[test]
fn rejected_paths_never_touch_a_fixture_tree() {
    // Traversal and aliases of a corpus root are refused before anything moves.
    let trees = Trees::new();
    write(&trees.donor.join("replacement.xml"), "<replacement/>");
    write(
        &trees.donor.join("../escape/replacement.xml"),
        "<replacement/>",
    );
    write(&trees.fixtures.join("xmlenc/sentinel.xml"), "<sentinel/>");
    write(&trees.fixtures.join("escape/sentinel.xml"), "<sentinel/>");
    for path in ["xmlenc/../escape", "xmlenc/.", "xmlenc//", "xmlenc/./"] {
        assert!(trees.import(&[path]).is_err(), "{path}");
        assert_eq!(trees.names("xmlenc"), ["sentinel.xml"], "{path}");
        assert_eq!(trees.names("escape"), ["sentinel.xml"], "{path}");
    }
}

#[test]
fn a_failed_copy_keeps_the_last_snapshot_without_partial_files() {
    // Staging failures happen beside the target; the known-good tree stays authoritative.
    use std::os::unix::fs::PermissionsExt as _;
    let trees = Trees::new();
    write(&trees.donor.join("corpus/current.xml"), "<current/>");
    let unreadable = trees.donor.join("corpus/unreadable.xml");
    write(&unreadable, "<secret/>");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    write(
        &trees.fixtures.join("xmlenc/corpus/sentinel.xml"),
        "<sentinel/>",
    );
    assert!(trees.import(&["xmlenc/corpus"]).is_err());
    assert_eq!(trees.names("xmlenc/corpus"), ["sentinel.xml"]);
    assert_eq!(trees.names("xmlenc"), ["corpus"]);
}

#[test]
fn a_file_import_replaces_a_directory_of_the_same_name() {
    // A donor path may change type upstream; no stale children survive.
    let trees = Trees::new();
    write(&trees.donor.join("corpus"), "current fixture");
    write(
        &trees.fixtures.join("xmlenc/corpus/obsolete.xml"),
        "<obsolete/>",
    );
    trees.import(&["xmlenc/corpus"]).unwrap();
    let target = trees.fixtures.join("xmlenc/corpus");
    assert!(target.is_file());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "current fixture");
}

#[test]
fn conflicting_merlin_hmac_names_keep_the_existing_snapshot() {
    // When upstream ships both names the importer chooses neither.
    let trees = Trees::new();
    for extension in ["tmpl", "xml"] {
        for length in ["40", "80"] {
            let name = format!(
                "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1-{length}.{extension}"
            );
            write(&trees.donor.join(name), length);
        }
    }
    write(
        &trees
            .fixtures
            .join("xmldsig/merlin-xmldsig-twenty-three/sentinel.xml"),
        "<sentinel/>",
    );
    assert!(
        trees
            .import(&["xmldsig/merlin-xmldsig-twenty-three"])
            .is_err()
    );
    assert_eq!(
        trees.names("xmldsig/merlin-xmldsig-twenty-three"),
        ["sentinel.xml"]
    );
    assert_eq!(trees.names("xmldsig"), ["merlin-xmldsig-twenty-three"]);
}

#[test]
fn fixture_paths_stay_inside_the_donor_and_fixture_trees() {
    // A path names one donor entry below xmldsig/ or xmlenc/, nothing else.
    assert_eq!(donor_path("xmldsig/keys/ml-kem").unwrap(), "keys/ml-kem");
    assert_eq!(donor_path("xmlenc/nist-aesgcm").unwrap(), "nist-aesgcm");
    for path in [
        "keys/ml-kem",
        "xmldsig/",
        "xmldsig/a//b",
        "xmldsig/./a",
        "xmlenc/../secret",
        "xmlenc//etc",
    ] {
        assert!(donor_path(path).is_err(), "{path}");
    }
}

#[test]
fn the_default_import_covers_every_rsa_pss_and_ml_kem_family_member() {
    // The upstream runners exercise complete families, so the import does too.
    let paths = default_paths();
    assert!(
        paths.contains(&"xmldsig/aleksey-xmldsig-01/enveloping-rsa-pss-sha3_512.tmpl".to_owned())
    );
    assert!(
        !paths
            .iter()
            .any(|path| path.contains("enveloped-sha1-rsa-pss-sha1"))
    );
    assert!(
        paths.contains(&"xmlenc/aleksey-xmlenc-01/enc-aes192gcm-em-ml-kem-768.data".to_owned())
    );
    assert_eq!(paths.len(), 23 + 9 * 2 + 8 * 2 + 3 * 5 + 3 * 3);
}

#[test]
fn the_phaos_readme_names_the_real_hmac_length_once_each() {
    // The donor calls 80-bit HMAC outputs 40-byte signatures; a changed
    // README stops the import instead of being rewritten blindly.
    let directory = tempfile::tempdir().unwrap();
    let readme = directory.path().join("README.txt");
    write(
        &readme,
        "a detached 40-byte SHA-1 HMAC signature here\nb detached 40 byte SHA-1 HMAC signature there\n",
    );
    normalize("xmldsig/phaos-xmldsig-three", directory.path()).unwrap();
    assert_eq!(
        std::fs::read_to_string(&readme).unwrap(),
        "a detached 80-bit SHA-1 HMAC signature here\nb detached 80-bit SHA-1 HMAC signature there\n"
    );
    assert!(normalize("xmldsig/phaos-xmldsig-three", directory.path()).is_err());
}

#[test]
fn merlin_hmac_fixtures_get_their_real_output_length_in_the_name() {
    // Only names change; a missing or already normalized fixture stops the import.
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path();
    write(&staging.join("Readme.txt"), "placeholders");
    for extension in ["tmpl", "xml"] {
        write(
            &staging.join(format!("signature-enveloping-hmac-sha1-40.{extension}")),
            extension,
        );
    }
    normalize("xmldsig/merlin-xmldsig-twenty-three", staging).unwrap();
    assert!(!staging.join("Readme.txt").exists());
    assert_eq!(
        std::fs::read_to_string(staging.join("signature-enveloping-hmac-sha1-80.xml")).unwrap(),
        "xml"
    );
    let error = normalize("xmldsig/merlin-xmldsig-twenty-three", staging).unwrap_err();
    assert!(error.contains("no longer provides"), "{error}");
    write(
        &staging.join("signature-enveloping-hmac-sha1-40.tmpl"),
        "again",
    );
    let error = normalize("xmldsig/merlin-xmldsig-twenty-three", staging).unwrap_err();
    assert!(error.contains("both historical and normalized"), "{error}");
}

#[test]
fn an_import_replaces_the_whole_target_or_leaves_it_untouched() {
    // Stale files disappear with a successful import; a failed one keeps the
    // last known-good snapshot.
    let directory = tempfile::tempdir().unwrap();
    let (donors, fixtures) = (
        directory.path().join("donors"),
        directory.path().join("fixtures"),
    );
    write(&donors.join("keys/ml-kem/key.pem"), "new");
    write(&fixtures.join("xmldsig/keys/ml-kem/stale.pem"), "old");
    import(&donors, &fixtures, "xmldsig/keys/ml-kem/").unwrap();
    assert_eq!(
        std::fs::read_to_string(fixtures.join("xmldsig/keys/ml-kem/key.pem")).unwrap(),
        "new"
    );
    assert!(!fixtures.join("xmldsig/keys/ml-kem/stale.pem").exists());
    write(&donors.join("single.xml"), "file");
    import(&donors, &fixtures, "xmlenc/single.xml").unwrap();
    assert_eq!(
        std::fs::read_to_string(fixtures.join("xmlenc/single.xml")).unwrap(),
        "file"
    );
    write(&donors.join("merlin-xmldsig-twenty-three/other.xml"), "x");
    write(
        &fixtures.join("xmldsig/merlin-xmldsig-twenty-three/kept.xml"),
        "kept",
    );
    assert!(import(&donors, &fixtures, "xmldsig/merlin-xmldsig-twenty-three").is_err());
    assert_eq!(
        std::fs::read_to_string(fixtures.join("xmldsig/merlin-xmldsig-twenty-three/kept.xml"))
            .unwrap(),
        "kept"
    );
    let leftovers: Vec<_> = std::fs::read_dir(fixtures.join("xmldsig"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with('.'))
        .collect();
    assert_eq!(leftovers, Vec::<String>::new());
}

#[test]
fn the_corpora_inventory_lists_every_file_in_byte_order() {
    // One line per imported byte stream, sorted the way `sort` sorts whole
    // paths in the C locale: "x-y/" comes before "x/", unlike a per-directory order.
    let directory = tempfile::tempdir().unwrap();
    write(&directory.path().join("xmlenc/x/a.xml"), "a");
    write(&directory.path().join("xmlenc/x-y/z.xml"), "z");
    let inventory = corpora_inventory(directory.path(), &["xmlenc/x", "xmlenc/x-y"]).unwrap();
    let paths: Vec<&str> = inventory
        .lines()
        .map(|line| line.split_once("  ").unwrap().1)
        .collect();
    assert_eq!(paths, ["xmlenc/x-y/z.xml", "xmlenc/x/a.xml"]);
}
