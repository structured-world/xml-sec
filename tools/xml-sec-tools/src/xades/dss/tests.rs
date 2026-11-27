use super::{fetch, newest_release_of};

#[test]
fn a_fetch_waits_out_a_burst_of_maven_central_rate_limits() {
    // CI met six 429 answers within 31 seconds: curl's backoff of 1, 2, 4, 8
    // and 16 seconds without Retry-After. The retries must keep trying for
    // minutes, bounded by an overall ceiling, before the run fails.
    let args: Vec<String> = fetch("https://example.invalid/metadata.xml", "out.xml".as_ref())
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let value = |flag: &str| {
        args.iter()
            .position(|arg| arg == flag)
            .and_then(|index| args.get(index + 1))
            .and_then(|value| value.parse::<u64>().ok())
    };
    let retries = value("--retry").expect("a retry count");
    // Exponential backoff from one second waits 2^n - 1 seconds over n
    // retries; at least 240 of them.
    assert!(
        (1_u64 << retries) > 240,
        "{retries} retries wait too briefly"
    );
    assert!(value("--retry-max-time").is_some_and(|ceiling| ceiling >= 300));
}

/// The newest release of any major version.
fn newest_release(metadata: &str) -> Result<String, String> {
    newest_release_of(metadata, None)
}

fn metadata(versions: &[&str]) -> String {
    let listed = versions.iter().fold(String::new(), |mut listed, version| {
        listed.push_str("<version>");
        listed.push_str(version);
        listed.push_str("</version>");
        listed
    });
    format!(
        "<metadata><versioning><release>{}</release><versions>{listed}</versions></versioning></metadata>",
        versions.last().copied().unwrap_or_default()
    )
}

#[test]
fn the_newest_release_skips_every_pre_release_form() {
    // Maven Central's own `release` element names 4.0.0-rc-7 for Maven, a
    // release candidate; the harness must take the highest stable version.
    let maven = metadata(&[
        "3.9.12",
        "3.10.0-rc-1",
        "3.10.2",
        "4.0.0-alpha-2",
        "4.0.0-rc-7",
    ]);
    assert_eq!(newest_release(&maven).as_deref(), Ok("3.10.2"));
    // DSS marks candidates with a dotted `RC` part.
    let dss = metadata(&["6.4", "6.5.RC1", "6.5", "6.5.1", "6.6.RC1"]);
    assert_eq!(newest_release(&dss).as_deref(), Ok("6.5.1"));
}

#[test]
fn versions_compare_by_number_not_by_text() {
    // As text "6.10" sorts before "6.9" and "6.5" after "6.10.1".
    let listed = metadata(&["6.9", "6.10", "6.5.1", "6.10.1", "6.5"]);
    assert_eq!(newest_release(&listed).as_deref(), Ok("6.10.1"));
}

#[test]
fn the_maven_build_takes_the_newest_maven_3_release() {
    // The DSS build runs on the current Maven 3 distribution; a stable Maven
    // 4 listed beside it is another line, not a newer Maven 3.
    let maven = metadata(&["3.9.11", "3.9.12", "4.0.0", "4.0.1", "4.1.0-rc-1"]);
    assert_eq!(newest_release_of(&maven, Some(3)).as_deref(), Ok("3.9.12"));
    assert_eq!(newest_release_of(&maven, None).as_deref(), Ok("4.0.1"));
    assert!(newest_release_of(&metadata(&["4.0.0"]), Some(3)).is_err());
}

#[test]
fn metadata_without_a_release_is_refused() {
    let candidates = metadata(&["4.0.0-rc-1", "4.0.0-rc-2"]);
    assert_eq!(
        newest_release(&candidates),
        Err("Maven metadata lists no release".to_owned())
    );
    assert!(newest_release("<html>Not Found</html>").is_err());
}
