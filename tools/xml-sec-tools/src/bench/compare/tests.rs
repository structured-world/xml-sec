use super::{Request, parse};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
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
