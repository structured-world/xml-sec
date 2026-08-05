use std::ffi::OsString;
use std::process::Command;

pub const REQUIRED_VERSION: (u16, u16, u16) = (1, 3, 13);

pub fn command() -> Command {
    let binary = std::env::var_os("XMLSEC1_BIN").unwrap_or_else(|| OsString::from("xmlsec1"));
    Command::new(binary)
}

pub fn version_supports_interop(version: &str) -> bool {
    let mut tokens = version.split_whitespace();
    if tokens.next() != Some("xmlsec1") {
        return false;
    }
    let Some(version) = tokens.next() else {
        return false;
    };
    let mut components = version.split('.');
    let parsed = (
        components
            .next()
            .and_then(|value| value.parse::<u16>().ok()),
        components
            .next()
            .and_then(|value| value.parse::<u16>().ok()),
        components
            .next()
            .and_then(|value| value.parse::<u16>().ok()),
    );
    match parsed {
        (Some(major), Some(minor), Some(patch)) if components.next().is_none() => {
            (major, minor, patch) >= REQUIRED_VERSION
        }
        _ => false,
    }
}

pub fn is_available() -> bool {
    let Ok(output) = command().arg("--version").output() else {
        return false;
    };
    output.status.success()
        && std::str::from_utf8(&output.stdout).is_ok_and(version_supports_interop)
}
