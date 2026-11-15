use super::{Request, installed_commit, parse};
use crate::install_xmlsec1::{MARKER, Source};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

#[test]
fn the_libxmlsec1_identity_is_the_commit_the_installation_was_built_from() {
    // The measured libxmlsec1 is whatever the installer built, so the evidence
    // names that commit; an installation without a marker cannot be measured.
    let directory = tempfile::tempdir().unwrap();
    assert!(installed_commit(directory.path()).is_err());
    let source = Source {
        commit: "90b3d51a25c734c667d5d37896586d3d60b862ff".to_owned(),
        version: "1.3.14".to_owned(),
    };
    std::fs::write(directory.path().join(MARKER), source.marker()).unwrap();
    assert_eq!(installed_commit(directory.path()).unwrap(), source.commit);
}

#[test]
fn invalid_runner_arguments_never_build_or_overwrite_evidence() {
    // Arguments are refused before donor, network or build work, and earlier results stay.
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("new");
    let path = output.display().to_string();
    for samples in [
        "0",
        "-1",
        "1001",
        "99999999999999999999",
        "invalid",
        "01000",
    ] {
        assert_eq!(
            parse(&args(&[&path, samples])).unwrap_err().code,
            2,
            "{samples}"
        );
    }
    assert_eq!(
        parse(&args(&[&path, "1", "--unknown"])).unwrap_err().code,
        2
    );
    assert_eq!(
        parse(&args(&[&path, "1", "--heap"])).unwrap(),
        Request {
            output: output.clone(),
            samples: 1,
            heap: true
        }
    );
    std::fs::create_dir(&output).unwrap();
    std::fs::write(output.join("evidence"), "preserved").unwrap();
    assert_eq!(
        parse(&args(&[&path, "1"])).unwrap_err().message,
        "Output already exists"
    );
    assert_eq!(
        std::fs::read_to_string(output.join("evidence")).unwrap(),
        "preserved"
    );
}
