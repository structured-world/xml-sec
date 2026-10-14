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
    assert!(output.stdout.is_empty());
    for args in [
        vec!["policy", "bogus"],
        vec!["policy", "check", "--unknown"],
        vec!["policy", "check", "--file"],
        vec!["policy", "check", "--authority", "admin"],
    ] {
        let output = cli().args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
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
