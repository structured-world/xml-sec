//! Checks byte-level donor provenance independently of executable coverage.

use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, path::Path};

pub fn verify() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let manifest = std::fs::read_to_string(root.join("xmlenc/corpora.sha256"))
        .expect("complete donor snapshot must have a committed checksum inventory");
    let mut expected = BTreeSet::new();
    for line in manifest.lines() {
        let (digest, name) = line.split_once("  ").expect("SHA-256 inventory format");
        assert_eq!(digest.len(), 64);
        assert!(
            expected.insert(name.to_owned()),
            "duplicate inventory entry: {name}"
        );
        let path = Path::new(name);
        assert!(
            path.components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        );
        let actual = Sha256::digest(std::fs::read(root.join(path)).unwrap());
        let pinned = (0..32)
            .map(|index| u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual.as_slice(), pinned, "donor bytes drifted: {name}");
    }
    let mut found = BTreeSet::new();
    let mut pending = [
        "xmlenc/merlin-xmlenc-five",
        "xmlenc/01-phaos-xmlenc-3",
        "xmlenc/aleksey-xmlenc-01",
        "xmlenc/keys/xdh",
        "xmlenc/keys/ec",
        "xmlenc/keys/dhx",
    ]
    .map(|name| root.join(name))
    .to_vec();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else {
                assert!(kind.is_file(), "snapshot must contain only regular files");
                assert!(
                    found.insert(
                        entry
                            .path()
                            .strip_prefix(&root)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned()
                    )
                );
            }
        }
    }
    assert_eq!(found, expected, "donor file inventory drifted");
}
