use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xmlsec1"))
}

#[test]
fn policy_commands_validate_print_and_compare_actual_files() {
    // Exercise the installed command boundary, not just library parsing.
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.toml");
    let new = dir.path().join("new.toml");
    std::fs::write(&old, "schema_version=1\n[profiles.team]\nbase='Modern'").unwrap();
    std::fs::write(&new, "schema_version=1\n[profiles.team]\nbase='Modern'\n[profiles.team.verification.resources]\nmax_xml_nodes=10").unwrap();
    let run = |action: &str| {
        let mut c = cli();
        c.args(["policy", action, "--file"])
            .arg(&old)
            .args(["--profile", "team"]);
        c
    };
    let check = run("check").output().unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert_eq!(check.stdout, b"policy team: valid\n");
    let effective = run("show-effective").output().unwrap();
    assert!(effective.status.success());
    let path = dir.path().join("effective.toml");
    std::fs::write(&path, &effective.stdout).unwrap();
    assert!(
        cli()
            .args(["policy", "check", "--file"])
            .arg(&path)
            .args(["--profile", "effective"])
            .status()
            .unwrap()
            .success()
    );
    let diff = run("diff")
        .arg("--other-file")
        .arg(&new)
        .args(["--other-profile", "team"])
        .output()
        .unwrap();
    assert!(diff.status.success());
    let text = String::from_utf8(diff.stdout).unwrap();
    assert!(
        text.contains("Restrictive: verification.resources.max_xml_nodes"),
        "{text}"
    );
    assert!(!text.contains("Relaxing:"), "{text}");
}

/// Recompile `effective` output and require the grant to survive verbatim.
fn assert_effective_validity(effective: &str, grant: &xml_sec::policy::PolicyValidity) {
    use xml_sec::{policy::PolicyCompileContext, provider::default_provider};
    use xml_sec_config::{Configuration, LoadLimits};
    let restored = Configuration::from_str(effective, LoadLimits::default())
        .unwrap()
        .compile(
            "effective",
            default_provider(),
            &PolicyCompileContext {
                external_resources: false,
                target_evidence: false,
            },
            Some(grant.clone()),
        )
        .unwrap();
    assert_eq!(
        restored
            .compiled()
            .verification()
            .unwrap()
            .validity
            .as_ref(),
        Some(grant)
    );
}

#[test]
fn policy_commands_accept_pre_epoch_authorization() {
    // The native boundary must accept a currently valid grant whose lower
    // bound precedes epoch, preserve it exactly, and still reject expired grants.
    use std::time::{SystemTime, UNIX_EPOCH};
    use xml_sec::policy::{Instant, PolicyValidity};
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy.toml");
    std::fs::write(&file, "schema_version=1\n[profiles.team]\nbase='Modern'").unwrap();
    let expires = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600)
        .to_string();
    let run = |action: &str, not_before: &str, expires: &str| {
        let mut command = cli();
        command.args(["policy", action, "--file"]).arg(&file).args([
            "--profile",
            "team",
            "--authorization-id",
            "test-grant",
            "--authority",
            "test-application",
            "--reason",
            "historical start",
            "--not-before",
            not_before,
            "--expires-at",
            expires,
        ]);
        command
    };
    let check = run("check", "-1", &expires).output().unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert_eq!(check.stdout, b"policy team: valid\n");
    let shown = run("show-effective", "-1", &expires).output().unwrap();
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let output = String::from_utf8(shown.stdout).unwrap();
    let grant = PolicyValidity {
        authorization_id: "test-grant".into(),
        authority: "test-application".into(),
        reason: "historical start".into(),
        not_before: Instant::new(-1, 0).unwrap(),
        expires_at: Instant::new(expires.parse().unwrap(), 0).unwrap(),
    };
    assert_effective_validity(&output, &grant);
    let diff = run("diff", "-1", &expires)
        .arg("--other-file")
        .arg(&file)
        .args(["--other-profile", "team"])
        .output()
        .unwrap();
    assert!(
        diff.status.success(),
        "{}",
        String::from_utf8_lossy(&diff.stderr)
    );
    assert_eq!(diff.stdout, b"neutral: effective policies are identical\n");
    let lapsed = run("check", "-2", "-1").output().unwrap();
    assert!(!lapsed.status.success());
    assert_eq!(lapsed.stdout, b"");
    assert!(
        String::from_utf8_lossy(&lapsed.stderr)
            .contains("policy authorization is outside its validity interval")
    );
    // Neither malformed text nor an out-of-i64-range value can wrap into a
    // valid interval. Both timestamp flags use the same parsing boundary.
    for value in ["not-a-time", "9223372036854775808", "-9223372036854775809"] {
        for (start, end, field) in [
            (value, expires.as_str(), "--not-before"),
            ("-1", value, "--expires-at"),
        ] {
            let rejected = run("check", start, end).output().unwrap();
            assert!(!rejected.status.success());
            assert_eq!(rejected.stdout, b"");
            assert!(
                String::from_utf8_lossy(&rejected.stderr)
                    .contains(&format!("{field} requires signed Unix seconds"))
            );
        }
    }
}

#[test]
fn malformed_cli_configuration_fails_without_stdout_or_xml_work() {
    // Unknown fields/options, incomplete authorization and unreadable paths
    // cannot become successful operator checks.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("bad.toml");
    std::fs::write(
        &file,
        "schema_version=1\n[profiles.team]\nbase='Modern'\nunknown=true",
    )
    .unwrap();
    let output = cli()
        .args(["policy", "check", "--file"])
        .arg(&file)
        .args(["--profile", "team"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(output.stdout, b"");
    for args in [
        vec!["policy", "bogus"],
        vec!["policy", "check", "--unknown"],
        vec!["policy", "check", "--file"],
        vec!["policy", "check", "--authority", "admin"],
    ] {
        let output = cli().args(args).output().unwrap();
        assert!(!output.status.success());
        assert_eq!(output.stdout, b"");
    }
}

#[test]
fn policy_diff_reports_specialized_constraints_as_narrowing() {
    // The operator-facing command must report the same constraint ordering as
    // the typed compiler, in both rollout directions and for both operations.
    let dir = tempfile::tempdir().unwrap();
    let general = dir.path().join("general.toml");
    let specialized = dir.path().join("specialized.toml");
    let source = |kind| {
        format!(
            "schema_version=1\n[profiles.team]\nbase='Modern'\n[profiles.team.verification]\nsignature_constraints='{kind}'\n[profiles.team.verification.key_trust]\nmode='RequireTrustedKey'\n[profiles.team.signing]\nsignature_constraints='{kind}'"
        )
    };
    std::fs::write(&general, source("General")).unwrap();
    for kind in ["Saml", "WsSecurity", "Xades"] {
        std::fs::write(&specialized, source(kind)).unwrap();
        for (old, next, direction) in [
            (&general, &specialized, "Restrictive"),
            (&specialized, &general, "Relaxing"),
        ] {
            let result = cli()
                .args(["policy", "diff", "--file"])
                .arg(old)
                .args(["--profile", "team", "--other-file"])
                .arg(next)
                .args(["--other-profile", "team", "--target-evidence"])
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let output = String::from_utf8(result.stdout).unwrap();
            let lines: Vec<_> = output.lines().collect();
            assert_eq!(lines.len(), 2, "{output}");
            for (line, operation) in lines.iter().zip(["signing", "verification"]) {
                assert!(
                    line.starts_with(&format!("{direction}: {operation}.signature_constraints:")),
                    "{output}"
                );
            }
        }
    }
}
