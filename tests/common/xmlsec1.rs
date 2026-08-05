use std::ffi::OsString;
use std::process::Command;

pub const REQUIRED_VERSION: (u16, u16, u16) = (1, 3, 13);

pub fn command() -> Command {
    let binary = std::env::var_os("XMLSEC1_BIN").unwrap_or_else(|| OsString::from("xmlsec1"));
    Command::new(binary)
}

pub fn version_supports_interop(version: &str) -> bool {
    version
        .split_whitespace()
        .find_map(|token| {
            let mut components = token.split('.');
            Some((
                components.next()?.parse::<u16>().ok()?,
                components.next()?.parse::<u16>().ok()?,
                components.next()?.parse::<u16>().ok()?,
            ))
        })
        .is_some_and(|version| version >= REQUIRED_VERSION)
}

pub fn is_available() -> bool {
    let Ok(output) = command().arg("--version").output() else {
        return false;
    };
    output.status.success()
        && std::str::from_utf8(&output.stdout).is_ok_and(version_supports_interop)
}
