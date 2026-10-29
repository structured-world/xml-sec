//! `donor-fixtures --cli [--check]`: the upstream runner scripts and vectors
//! the native CLI's integration suite executes unmodified, copied from the
//! pinned donor commit together with that commit.

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

/// The pinned donor commit; a missing, empty or malformed pin is no provenance.
pub(crate) fn pinned(pin: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(pin).map_err(|error| {
        format!(
            "donor commit pin is missing or empty: {}: {error}",
            pin.display()
        )
    })?;
    let commit = text.strip_suffix('\n').unwrap_or(&text);
    if commit.is_empty() {
        return Err(format!(
            "donor commit pin is missing or empty: {}",
            pin.display()
        ));
    }
    let object_id = (commit.len() == 40 || commit.len() == 64)
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !object_id {
        return Err(format!(
            "donor commit pin is not a Git object ID: {}",
            pin.display()
        ));
    }
    Ok(commit.to_owned())
}

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

/// Copies every asset of the donor checkout at `commit` into `staging`.
fn stage(donor_tests: &Path, commit: &str, staging: &Path) -> Result<(), String> {
    let not_checkout = || {
        format!(
            "donor tests must belong to a Git checkout: {}",
            donor_tests.display()
        )
    };
    let repository = PathBuf::from(
        git(donor_tests, &["rev-parse", "--show-toplevel"])?.ok_or_else(not_checkout)?,
    );
    let head = git(donor_tests, &["rev-parse", "HEAD"])?.ok_or_else(not_checkout)?;
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
    if head != commit {
        return Err(format!(
            "donor checkout revision {head} does not match pin {commit}"
        ));
    }
    for asset in ASSETS {
        let source = donor_tests.join(asset);
        if !source.is_file() {
            return Err(format!(
                "pinned donor asset is missing: {}",
                source.display()
            ));
        }
        let tracked = format!("tests/{asset}");
        let pristine = git(&repository, &["ls-files", "--error-unmatch", &tracked])?.is_some()
            && git(&repository, &["diff", "--quiet", commit, "--", &tracked])?.is_some();
        if !pristine {
            return Err(format!(
                "pinned donor asset has uncommitted changes: {}",
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
    std::fs::write(staging.join("DONOR_COMMIT"), format!("{commit}\n"))
        .map_err(|error| error.to_string())
}

/// Imports the snapshot into `target`, or with `check` reports how it differs
/// and leaves it untouched.
pub(crate) fn execute(
    donor_tests: &Path,
    target: &Path,
    pin: &Path,
    check: bool,
) -> Result<(), String> {
    let commit = pinned(pin)?;
    let parent = target.parent().ok_or("the snapshot target has a parent")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let staging = beside(target, "import")?;
    std::fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    let staged = stage(donor_tests, &commit, &staging);
    let checked = staged.and_then(|()| {
        if check {
            differences(target, &staging)
        } else {
            Ok(Vec::new())
        }
    });
    if check || checked.is_err() {
        std::fs::remove_dir_all(&staging).map_err(|error| error.to_string())?;
    }
    let found = checked?;
    if check {
        return if found.is_empty() {
            Ok(())
        } else {
            Err(found.join("\n"))
        };
    }
    replace(&staging, target)
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
    execute(
        &donor,
        &target,
        &root.join("compatibility/libxmlsec1-1.3.13-donor-commit.txt"),
        check,
    )
}
