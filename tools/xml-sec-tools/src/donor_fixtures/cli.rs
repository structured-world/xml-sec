//! `donor-fixtures --cli [--check]`: the upstream runner scripts and vectors
//! the native CLI's integration suite executes unmodified, copied from the
//! committed state of an upstream checkout. The run prints the commit it
//! copied or compared; none is stored, so CI checks the snapshot against the
//! checkout it makes: the pinned oracle commit in the required jobs, upstream
//! master's head in the advisory one.

use super::{beside, install, replace};
use crate::libxslt_fixtures::differences;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(test)]
mod tests;

/// The donor files the snapshot holds, relative to the donor `tests` tree.
pub(crate) const ASSETS: [&str; 12] = [
    "testrun.sh",
    "testDSig.sh",
    "testEnc.sh",
    "testKeys.sh",
    "aleksey-xmldsig-01/enveloping-sha256-rsa-sha256-relationship.tmpl",
    "aleksey-xmldsig-01/relationship/xml-base-input.xml",
    "phaos-xmldsig-three/signature-rsa-enveloped-bad-digest-val.xml",
    "phaos-xmldsig-three/certs/rsa-ca-cert.der",
    "xmlenc11-interop-2012/xenc11-example-AES128-GCM.xml",
    "xmlenc11-interop-2012/xenc11-example-AES128-GCM.tmpl",
    "xmlenc11-interop-2012/xenc11-example-AES128-GCM.data",
    "xmlenc11-interop-2012/xenc11-example-AES128-GCM.key",
];

/// A Git query in `directory`; its trimmed output, or `None` when Git refuses.
fn git(directory: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .map_err(|error| format!("git: {error}"))?;
    Ok(output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned()))
}

/// Copies every asset of the donor checkout into `staging`, refusing any
/// asset whose bytes differ from the checkout's commit; returns that commit.
fn stage(donor_tests: &Path, staging: &Path) -> Result<String, String> {
    let not_checkout = || {
        format!(
            "donor tests must belong to a Git checkout: {}",
            donor_tests.display()
        )
    };
    let repository = PathBuf::from(
        git(donor_tests, &["rev-parse", "--show-toplevel"])?.ok_or_else(not_checkout)?,
    );
    let commit = git(donor_tests, &["rev-parse", "HEAD"])?.ok_or_else(not_checkout)?;
    let canonical = |path: &Path| {
        path.canonicalize()
            .map_err(|error| format!("{}: {error}", path.display()))
    };
    if canonical(donor_tests)? != canonical(&repository.join("tests"))? {
        return Err(format!(
            "donor root must be the tests directory of its Git checkout: {}",
            donor_tests.display()
        ));
    }
    for asset in ASSETS {
        let source = donor_tests.join(asset);
        if !source.is_file() {
            return Err(format!("donor asset is missing: {}", source.display()));
        }
        let tracked = format!("tests/{asset}");
        let pristine = git(&repository, &["ls-files", "--error-unmatch", &tracked])?.is_some()
            && git(&repository, &["diff", "--quiet", &commit, "--", &tracked])?.is_some();
        if !pristine {
            return Err(format!(
                "donor asset has uncommitted changes: {}",
                source.display()
            ));
        }
        let target = staging.join(asset);
        install(&source, &target)?;
        #[cfg(unix)]
        if Path::new(asset)
            .extension()
            .is_some_and(|extension| extension == "sh")
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(commit)
}

/// Imports the snapshot into `target`, or with `check` reports how it differs
/// and leaves it untouched; returns the upstream commit it was taken from.
pub(crate) fn execute(donor_tests: &Path, target: &Path, check: bool) -> Result<String, String> {
    let parent = target.parent().ok_or("the snapshot target has a parent")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let staging = beside(target, "import")?;
    std::fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    let staged = stage(donor_tests, &staging);
    let checked = staged.and_then(|commit| {
        if check {
            differences(target, &staging).map(|found| (commit, found))
        } else {
            Ok((commit, Vec::new()))
        }
    });
    if check || checked.is_err() {
        std::fs::remove_dir_all(&staging).map_err(|error| error.to_string())?;
    }
    let (commit, found) = checked?;
    if check {
        return if found.is_empty() {
            Ok(commit)
        } else {
            Err(format!(
                "the CLI fixture snapshot differs from upstream {commit}:\n{}\n\
                 run `cargo run -p xml-sec-tools -- donor-fixtures --cli` and review the diff",
                found.join("\n")
            ))
        };
    }
    replace(&staging, target)?;
    Ok(commit)
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let check = match args {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => return Err("usage: donor-fixtures --cli [--check]".into()),
    };
    let root = crate::repo::root();
    let variable = |name: &str| {
        std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    let donor = variable("XMLSEC_DONOR_ROOT").unwrap_or_else(|| root.join("donors/xmlsec/tests"));
    let target = variable("XMLSEC_FIXTURE_TARGET")
        .unwrap_or_else(|| root.join("tools/xmlsec1/tests/fixtures/upstream"));
    let commit = execute(&donor, &target, check)?;
    let action = if check { "matches" } else { "copied from" };
    println!("CLI fixture snapshot {action} upstream {commit}");
    Ok(())
}
