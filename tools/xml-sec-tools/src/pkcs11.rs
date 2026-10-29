//! `pkcs11-tests MODULE [--workspace] ARGS...`: runs the token tests against
//! an explicit module, initializing tokens only inside a disposable store.

use crate::repo::{Failure, Step, command};

#[cfg(test)]
mod tests;

/// The nextest invocation: every workspace test, or only the token target.
pub(crate) fn nextest(args: &[String]) -> Step {
    let mut step = Step::new("pkcs11 tests", "cargo", &["nextest", "run"]);
    if let Some(rest) = args.strip_prefix(&["--workspace".to_owned()]) {
        step.args
            .extend(["--workspace", "--features", "pkcs11"].map(String::from));
        step.args.extend_from_slice(rest);
    } else {
        step.args
            .extend(["--features", "pkcs11", "--test", "pkcs11"].map(String::from));
        step.args.extend_from_slice(args);
        step.args.push("--no-capture".into());
    }
    step
}

/// The `SoftHSM` configuration that confines tokens to `store`.
pub(crate) fn config(store: &std::path::Path) -> String {
    format!(
        "directories.tokendir = {}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n",
        store.display()
    )
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let module = args
        .next()
        .filter(|module| !module.is_empty())
        .ok_or("pass the explicit SoftHSM module path")?;
    let rest: Vec<String> = args.collect();
    run_tests(&module, &rest, &[])
}

/// Runs the token tests of `args` in a fresh disposable store, with `env`
/// added to the test environment.
pub(crate) fn run_tests(
    module: &str,
    args: &[String],
    env: &[(String, String)],
) -> Result<(), Failure> {
    // Removed when dropped, on success and on failure alike.
    let store = tempfile::Builder::new()
        .prefix("xml-sec-pkcs11.")
        .tempdir()
        .map_err(|error| format!("create token store: {error}"))?;
    std::fs::create_dir(store.path().join("tokens"))
        .map_err(|error| format!("create token directory: {error}"))?;
    let conf = store.path().join("softhsm.conf");
    std::fs::write(&conf, config(store.path()))
        .map_err(|error| format!("write token configuration: {error}"))?;
    let status = command(&nextest(args))
        .envs(env.iter().map(|(key, value)| (key, value)))
        .env("SOFTHSM2_CONF", &conf)
        .env("XML_SEC_PKCS11_TEST_MODULE", module)
        .env("XML_SEC_PKCS11_TEST_STORE", store.path())
        .status()
        .map_err(|error| format!("cargo nextest: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::of(status))
    }
}
