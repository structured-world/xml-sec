use super::newest_release;

fn metadata(versions: &[&str]) -> String {
    let listed: String = versions
        .iter()
        .map(|version| format!("<version>{version}</version>"))
        .collect();
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
fn metadata_without_a_release_is_refused() {
    let candidates = metadata(&["4.0.0-rc-1", "4.0.0-rc-2"]);
    assert_eq!(
        newest_release(&candidates),
        Err("Maven metadata lists no release".to_owned())
    );
    assert!(newest_release("<html>Not Found</html>").is_err());
}
