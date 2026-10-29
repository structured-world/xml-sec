use super::{ATTEMPTS, execute, version};
use crate::repo::{Run, Step};
use serde_json::json;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

/// A registry that shows the version from the `visible_from`-th lookup on.
struct Registry {
    visible_from: Option<u32>,
    publish_succeeds: bool,
    lookups: u32,
    publishes: u32,
}

impl Registry {
    fn new(visible_from: Option<u32>, publish_succeeds: bool) -> Self {
        Self {
            visible_from,
            publish_succeeds,
            lookups: 0,
            publishes: 0,
        }
    }
}

fn exit(success: bool) -> ExitStatus {
    ExitStatus::from_raw(if success { 0 } else { 101 << 8 })
}

impl Run for Registry {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        assert_eq!(step.args, ["publish", "-p", "xml-sec"]);
        self.publishes += 1;
        Ok(exit(self.publish_succeeds))
    }

    fn stdout(&mut self, _: &Step) -> Result<(ExitStatus, String), String> {
        let metadata = json!({ "packages": [{ "name": "xml-sec", "version": "0.3.0" }] });
        Ok((exit(true), metadata.to_string()))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        // The lookup names the registry, so the workspace copy cannot answer it.
        assert_eq!(
            step.args,
            ["info", "--registry", "crates-io", "xml-sec@0.3.0"]
        );
        self.lookups += 1;
        Ok((
            exit(self.visible_from.is_some_and(|from| self.lookups >= from)),
            String::new(),
        ))
    }
}

#[test]
fn an_already_published_version_is_never_uploaded_again() {
    // A rerun of the release after a successful upload does nothing.
    let mut registry = Registry::new(Some(1), true);
    execute(&mut registry, "xml-sec", || {}).unwrap();
    assert_eq!(registry.publishes, 0);
}

#[test]
fn a_publish_succeeds_once_the_index_shows_it() {
    // Visibility, not the command alone, completes the release.
    let mut registry = Registry::new(Some(4), true);
    let mut waits = 0;
    execute(&mut registry, "xml-sec", || waits += 1).unwrap();
    assert_eq!((registry.publishes, waits), (1, 2));
}

#[test]
fn a_failed_command_with_an_accepted_upload_still_succeeds() {
    // crates.io may accept the upload before Cargo's index wait times out.
    let mut registry = Registry::new(Some(2), false);
    execute(&mut registry, "xml-sec", || {}).unwrap();
    assert_eq!(registry.publishes, 1);
}

#[test]
fn a_version_that_never_appears_fails_after_every_attempt() {
    // A real publish failure is reported, not mistaken for a slow index.
    let mut registry = Registry::new(None, true);
    let mut waits = 0;
    let failure = execute(&mut registry, "xml-sec", || waits += 1).unwrap_err();
    assert_eq!(failure.message, "xml-sec 0.3.0 was not published");
    assert_eq!(waits, ATTEMPTS);
}

#[test]
fn only_a_workspace_package_has_a_version() {
    // An unknown name stops before any registry lookup.
    let metadata = json!({ "packages": [{ "name": "xml-sec", "version": "0.3.0" }] });
    assert_eq!(version(&metadata, "xml-sec").as_deref(), Some("0.3.0"));
    assert_eq!(version(&metadata, "xml-sec-cli"), None);
    let mut registry = Registry::new(Some(1), true);
    let failure = execute(&mut registry, "xml-sec-cli", || {}).unwrap_err();
    assert_eq!(
        failure.message,
        "workspace package xml-sec-cli was not found"
    );
    assert_eq!(registry.lookups, 0);
}
