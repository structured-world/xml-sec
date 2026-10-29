use super::{Request, loader, native_paths, parse};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

#[test]
fn sample_counts_features_and_existing_output_are_checked_before_any_build() {
    // A typo must not start a long run or overwrite earlier evidence.
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("new");
    let path = output.display().to_string();
    for samples in ["0", "100001", "1234567", "99999999999999999999", "x", "-1"] {
        assert_eq!(
            parse(&args(&[&path, samples])).unwrap_err().code,
            2,
            "{samples}"
        );
    }
    assert_eq!(
        parse(&args(&[&path, "7", "aws-lc-fips"])).unwrap(),
        Request {
            output: output.clone(),
            samples: 7,
            features: "benchmark-internals,aws-lc-fips".into()
        }
    );
    assert_eq!(parse(&args(&[&path])).unwrap().samples, 1000);
    assert!(!output.exists());
    std::fs::create_dir(&output).unwrap();
    let existing = parse(&args(&[&path, "1"])).unwrap_err();
    assert_eq!(existing.code, 2);
    assert!(
        existing.message.contains("already exists"),
        "{}",
        existing.message
    );
}

#[test]
fn native_search_paths_come_from_build_script_messages_only() {
    // Only `native=` and `all=` link paths of executed build scripts, once each.
    let messages = [
        r#"{"reason":"build-script-executed","linked_paths":["native=/b/lib","dependency=/x","all=/a/lib"]}"#,
        r#"{"reason":"build-script-executed","linked_paths":["native=/b/lib"]}"#,
        r#"{"reason":"compiler-artifact","linked_paths":["native=/ignored"]}"#,
        "not json",
    ]
    .join("\n");
    assert_eq!(native_paths(&messages), "/a/lib:/b/lib");
}

#[test]
fn the_loader_prefix_restores_the_library_path_inside_the_child() {
    // Protected macOS time strips DYLD_*; an empty search path adds nothing.
    assert_eq!(
        loader("/a", "darwin", Some("/old")),
        ["/usr/bin/env", "DYLD_LIBRARY_PATH=/a:/old"]
    );
    assert_eq!(
        loader("/a", "linux", None),
        ["/usr/bin/env", "LD_LIBRARY_PATH=/a"]
    );
    assert_eq!(loader("", "linux", Some("/old")), Vec::<String>::new());
}
