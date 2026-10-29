use super::binding::{analyze_octets, binding_facts};
use super::check::{check_expectations, check_goldens, check_inventory};
use super::dss::profile_binding;
use super::package::{Evidence, baseline, workspace_manifest};
use super::{Corpus, DS, compare, debug_buffer, probe_executable, resolved_versions};
use base64::Engine as _;
use serde_json::{Map, Value, json};
use std::path::Path;

#[test]
fn the_archived_workspace_is_the_frozen_one_plus_the_runner() {
    // The archive is extracted over the baseline, whose workspace does not
    // know the runner; only the membership and the inherited lint table change.
    let frozen = "[package]\nname = \"xml-sec\"\n\n[workspace]\nmembers = [\n    \".\",\n    \"tools/xmlsec1\",\n]\nresolver = \"3\"\n\n[dependencies]\nbase64 = \"0.23\"\n";
    let manifest = workspace_manifest(frozen).unwrap();
    assert_eq!(
        manifest,
        "[package]\nname = \"xml-sec\"\n\n[workspace]\nmembers = [\n    \".\",\n    \"tools/xmlsec1\",\n    \"tools/xml-sec-tools\",\n]\nresolver = \"3\"\n\n[dependencies]\nbase64 = \"0.23\"\n\n[workspace.lints.rust]\n"
    );
    // A baseline that already registers the runner and its lints is used as
    // frozen; nothing is declared twice.
    assert_eq!(workspace_manifest(&manifest).unwrap(), manifest);
    assert!(workspace_manifest("[package]\nname = \"xml-sec\"\n").is_err());
}

#[test]
fn a_baseline_with_the_runner_but_no_lint_table_gets_only_the_table() {
    // The runner inherits workspace lints, so their table must exist.
    let frozen = "[workspace]\nmembers = [\n    \".\",\n    \"tools/xml-sec-tools\",\n]\n";
    assert_eq!(
        workspace_manifest(frozen).unwrap(),
        format!("{frozen}\n[workspace.lints.rust]\n")
    );
}

#[test]
fn the_baseline_commit_comes_from_the_corpus_readme() {
    // One recorded commit decides both the README and the archived manifest.
    let commit = "834c463798060dca613bb93dd78dcdc7f949c948";
    let readme = format!("- Repository: `structured-world/xml-sec`, commit `{commit}`.\n");
    assert_eq!(baseline(&readme).unwrap(), commit);
    assert!(baseline("- Repository: `structured-world/xml-sec`, commit `834c`.\n").is_err());
}

fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        panic!("not an object: {value}");
    };
    map
}

fn write(path: &Path, data: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

#[test]
fn report_statuses_use_the_public_english_vocabulary() {
    // Report labels are public text that later checks compare literally.
    assert_eq!(compare(b"same", b"same")["status"], "verified");
    assert_eq!(compare(b"same", b"different")["status"], "failed");
    assert_eq!(
        profile_binding("baseline-wrong-target", &Map::new()).unwrap()["status"],
        "not run or blocked"
    );
}

#[test]
fn a_comparison_names_the_first_difference_and_a_truncated_prefix() {
    // A changed byte and a matching but shorter vector are different failures.
    let changed = compare(b"abcd", b"abXd");
    assert_eq!(changed["first_different_byte"], 2);
    assert_eq!(changed["expected_context_hex"], "61626364");
    assert_eq!(compare(b"abcd", b"abc")["first_different_byte"], 3);
    let equal = compare(b"", b"");
    assert_eq!(equal["first_different_byte"], Value::Null);
    assert_eq!(equal["expected_context_hex"], Value::Null);
}

#[test]
fn distributed_prose_is_english() {
    // Prose and expected labels only; signed XML and oracle octets are data.
    let package = crate::repo::root().join("interop/xades");
    for name in [
        "README.md",
        "PROVENANCE.md",
        "COMMENT-DRAFT.md",
        "dss-investigation/README.md",
        "dss-evidence/expectations.json",
        "dss-investigation/expectations.json",
        "dss-investigation/strict-policy-expectations.json",
    ] {
        let text = std::fs::read_to_string(package.join(name)).unwrap();
        assert!(
            !text
                .chars()
                .any(|character| ('\u{0400}'..='\u{052f}').contains(&character)),
            "{name}"
        );
    }
}

#[test]
fn the_probe_is_the_one_example_cargo_reported() {
    // A stale default path is never guessed; library artifacts and build
    // script lines are allowed, but not zero or several example executables.
    let log = Path::new("/run/build");
    let artifact = json!({
        "reason": "compiler-artifact",
        "executable": "/custom-target/interop_probe",
        "target": { "name": "interop_probe", "kind": ["example"] },
    })
    .to_string();
    let library = json!({
        "reason": "compiler-artifact",
        "executable": null,
        "target": { "name": "xml_sec_xades", "kind": ["lib"] },
    })
    .to_string();
    let messages = format!("build-script diagnostic\n{library}\n{artifact}\n");
    assert_eq!(
        probe_executable(messages.as_bytes(), log).unwrap(),
        Path::new("/custom-target/interop_probe")
    );
    for messages in [library.clone(), format!("{artifact}\n{artifact}")] {
        let error = probe_executable(messages.as_bytes(), log).unwrap_err();
        assert!(
            error.contains("exactly one") && error.contains("build.stdout"),
            "{error}"
        );
    }
}

#[test]
fn the_inventory_rejects_changed_assets_and_tracked_run_outputs() {
    // Stale reference data and accidentally committed actual outputs both fail.
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let package = root.join("interop/xades");
    let fixture = package.join("fixtures/enveloped-control.xml");
    write(&fixture, "<synthetic/>");
    let cases = json!([{ "name": "enveloped-control", "file": "fixtures/enveloped-control.xml", "valid": true }]);
    write(&package.join("cases.json"), cases.to_string());
    write(
        &package.join("dss-investigation/expectations.json"),
        r#"{"cases":[]}"#,
    );
    let declared = [
        "interop/xades/cases.json",
        "interop/xades/dss-investigation/expectations.json",
        "interop/xades/fixtures/enveloped-control.xml",
    ];
    let files: Vec<_> = declared.iter().map(|path| root.join(path)).collect();
    let inventory = super::package::inventory(root, &files).unwrap();
    write(&package.join("SHA256SUMS"), inventory);
    let mut tracked: Vec<String> = declared.iter().map(|path| (*path).to_owned()).collect();
    tracked.push("interop/xades/SHA256SUMS".into());
    check_inventory(root, &package, &tracked).unwrap();
    write(&fixture, "<changed/>");
    let error = check_inventory(root, &package, &tracked).unwrap_err();
    assert!(error.contains("corpus checksum mismatch"), "{error}");
    tracked.push("interop/xades/results/enveloped-control/spec/reference-0.bin".into());
    let error = check_inventory(root, &package, &tracked).unwrap_err();
    assert!(
        error.contains("run artifact or undeclared corpus file tracked"),
        "{error}"
    );
}

#[test]
fn goldens_reject_changed_and_missing_live_octets() {
    // Fresh oracle octets must match the reference corpus, empty vectors included.
    let directory = tempfile::tempdir().unwrap();
    let (expected, actual) = (
        directory.path().join("expected"),
        directory.path().join("actual"),
    );
    write(&expected.join("expected-reference-0.bin"), b"");
    write(&actual.join("expected-reference-0.bin"), b"");
    assert_eq!(check_goldens(&expected, &actual).unwrap(), 1);
    write(&actual.join("expected-reference-0.bin"), b"x");
    let error = check_goldens(&expected, &actual).unwrap_err();
    assert!(
        error.contains("golden mismatch:") && error.contains("first_different_byte"),
        "{error}"
    );
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(actual.join("golden-comparison.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report[0]["first_different_byte"], 0);
    std::fs::remove_file(actual.join("expected-reference-0.bin")).unwrap();
    let error = check_goldens(&expected, &actual).unwrap_err();
    assert!(error.contains("golden inventory mismatch"), "{error}");
}

#[test]
fn dss_expectations_reject_changed_live_conclusions() {
    // A passing XML signature cannot hide a changed DSS profile finding.
    let directory = tempfile::tempdir().unwrap();
    let (expected, actual) = (
        directory.path().join("expected.json"),
        directory.path().join("actual.json"),
    );
    write(&expected, r#"{"ISC":"PASSED"}"#);
    write(&actual, r#"{"ISC":"INDETERMINATE"}"#);
    let error = check_expectations(&expected, &actual).unwrap_err();
    assert!(error.contains("DSS expectation mismatch"), "{error}");
    write(&actual, r#"{ "ISC": "PASSED" }"#);
    check_expectations(&expected, &actual).unwrap();
}

#[test]
fn binding_facts_keep_the_selected_signer_and_digest() {
    // The root-versus-signer evidence survives without the raw reports.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("binding-facts.txt");
    write(
        &path,
        "structural_policy=WARN\nselected_certificate=leaf\nselected_certificate_reference_null=true\n\
         reference.0.match=true\nreference.0.digest=YWJjZA==\n",
    );
    assert_eq!(
        Value::Object(binding_facts(&path).unwrap()),
        json!({
            "selected_certificate": "leaf",
            "selected_certificate_reference_null": "true",
            "reference.0.match": "true",
            "reference.0.digest": "YWJjZA==",
        })
    );
}

#[test]
fn the_bundle_carries_signature_evidence_but_no_workstation_logs() {
    // Run captures and actual outputs never enter the distributable corpus.
    let package = crate::repo::root().join("interop/xades");
    let evidence = Evidence::load(&package).unwrap();
    for name in [
        "checks/pr-validation.json",
        "checks/build.log",
        "generation/sign.command.json",
        "results/build.stdout",
        "results/versions/metadata.stdout",
        "case/run.stderr",
        "case/probe.command.json",
        "case/rust/result.txt",
        "case/diagnostic.xml",
        "case/detailed.xml",
        "case/simple.xml",
        "case/binding-facts.txt",
        "results/control/spec/reference-0.bin",
        "results/control/spec/replay-0.bin",
        "dss-investigation/control/rust/signature-0.bin",
        "results/summary.json",
        "results/versions.json",
        "dss-evidence/dependencies.json",
        "surprise.tmp",
    ] {
        assert!(!evidence.includes(&package.join(name)), "{name}");
    }
    for name in [
        "fixtures/enveloped-control.xml",
        "fixtures/signer.key",
        "results/enveloped-control/expected-reference-0.bin",
        "dss-evidence/expectations.json",
    ] {
        assert!(evidence.includes(&package.join(name)), "{name}");
    }
}

#[test]
fn dependency_versions_do_not_export_local_package_ids() {
    // Cargo metadata carries absolute package IDs; the public record must not.
    let identity = "path+file:///Users/example/private#sample@1.0.0";
    let metadata = json!({
        "packages": [{ "id": identity, "name": "sample", "version": "1.0.0" }],
        "resolve": { "nodes": [{ "id": identity, "features": ["std"] }] },
    });
    assert_eq!(
        resolved_versions(&metadata).unwrap(),
        json!([{ "name": "sample", "version": "1.0.0", "features": ["std"] }])
    );
}

#[test]
fn analysis_uses_retained_octets_without_raw_process_logs() {
    // Rechecking a run needs its octets, not its process captures.
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path();
    let case = output.join("case");
    let mut values = String::new();
    for (index, data) in [&b"first"[..], b"second"].into_iter().enumerate() {
        write(&case.join(format!("expected-reference-{index}.bin")), data);
        write(&case.join(format!("rust/reference-{index}.bin")), data);
        write(&case.join(format!("rust/replay-{index}.bin")), data);
        let digest = <sha2::Sha256 as sha2::Digest>::digest(data);
        let value = base64::engine::general_purpose::STANDARD.encode(digest);
        values.push_str("<Reference><DigestValue>");
        values.push_str(&value);
        values.push_str("</DigestValue></Reference>");
    }
    write(&case.join("expected-signedinfo.bin"), b"signedinfo");
    write(&case.join("rust/signature-0.bin"), b"signedinfo");
    write(
        &case.join("signed.xml"),
        format!(r#"<Signature xmlns="{DS}"><SignedInfo>{values}</SignedInfo></Signature>"#),
    );
    write(
        &output.join("summary.json"),
        json!({ "cases": [{ "name": "case" }] }).to_string(),
    );
    analyze_octets(output).unwrap();
    assert!(!case.join("libxmlsec.stdout").exists());
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(output.join("octet-comparison.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report[0]["signed_info"]["status"], "verified");
    assert_eq!(report[0]["references"][1]["digest_matches"], true);
}

#[test]
fn explicit_outputs_get_their_missing_parents_before_any_engine_runs() {
    // A clean checkout has no target directory; the first failure comes from
    // the engine, after the evidence directory exists.
    let directory = tempfile::tempdir().unwrap();
    let corpus = Corpus {
        root: directory.path().to_owned(),
        xmlsec: "/nonexistent/xmlsec1".into(),
    };
    let results = directory.path().join("missing-parent/evidence");
    assert!(super::corpus::run_all(&corpus, &results).is_err());
    assert!(results.is_dir());
    let output = directory.path().join("other-parent/evidence");
    let args = ["--output".to_owned(), output.display().to_string()];
    assert!(super::binding::run(&corpus, &args).is_err());
    assert!(output.is_dir());
}

#[test]
fn dss_conformance_labels_do_not_attest_target_binding() {
    // EN 319 102-1 §5.2.2 excludes profile conformance from base-format FC.
    let row =
        object(json!({ "conclusions": { "FC": "PASSED" }, "reported_format": "XAdES-BASELINE-B" }));
    assert_eq!(
        profile_binding("baseline-wrong-target", &row).unwrap()["status"],
        "not run or blocked"
    );
}

#[test]
fn a_root_certificate_digest_must_fail_signer_identification() {
    // EN 319 102-1 §5.2.3.4: the reference must match the actual signing certificate.
    let status = |row: Value| {
        profile_binding("baseline-certificate-digest-mismatch", &object(row)).unwrap()["status"]
            .clone()
    };
    assert_eq!(
        status(json!({ "conclusions": { "ISC": "PASSED" } })),
        "failed"
    );
    assert_eq!(
        status(json!({
            "conclusions": { "ISC": "INDETERMINATE" },
            "subindications": { "ISC": "NO_SIGNING_CERTIFICATE_FOUND" },
        })),
        "verified"
    );
    assert_eq!(
        status(json!({
            "conclusions": { "ISC": "INDETERMINATE" },
            "subindications": { "ISC": "CRYPTO_CONSTRAINTS_FAILURE" },
        })),
        "failed"
    );
}

#[test]
fn a_hex_dump_keeps_canonical_whitespace() {
    // DebugHexDump is hex, not XML text; a final LF and spaces are signed.
    let block =
        b"== PreDigest data - start buffer:\n3c612f3e20\n0a\n== PreDigest data - end buffer";
    assert_eq!(
        debug_buffer(block, "PreDigest").unwrap(),
        Some(b"<a/> \n".to_vec())
    );
}

#[test]
fn an_absent_buffer_is_never_an_implicit_empty_one() {
    // Missing debug output cannot pass a byte comparison as empty content.
    assert_eq!(debug_buffer(b"== Status: OK\n", "PreDigest").unwrap(), None);
}

#[test]
fn a_changed_dump_format_stops_extraction() {
    // Non-hex content fails instead of producing corrupted bytes.
    let block = b"== PreDigest data - start buffer:\n<XML/>\n== PreDigest data - end buffer";
    assert!(debug_buffer(block, "PreDigest").is_err());
}

#[test]
fn reference_blocks_follow_each_separator() {
    // Text before the first verification context is not a Reference.
    let pieces = super::corpus::after_each(b"head=Xa=Xb", b"=X");
    assert_eq!(pieces, [&b"a"[..], b"b"]);
    assert_eq!(
        super::corpus::after_each(b"none", b"=X"),
        Vec::<&[u8]>::new()
    );
}
