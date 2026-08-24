//! Contract tests for the generated libxmlsec1 behavioral compatibility map.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct ProbeDirectory(PathBuf);

impl ProbeDirectory {
    fn create() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must follow Unix epoch")
            .as_nanos();
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "xml-sec-behavior-probe-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("temporary probe directory must be created");
        Self(path)
    }
}

impl Drop for ProbeDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ledger() -> Value {
    serde_json::from_str(include_str!(
        "../compatibility/libxmlsec1-1.3.13-behavior.json"
    ))
    .expect("generated behavioral ledger must be valid JSON")
}

fn c_boundary_behaviors(value: &Value) -> Vec<&Value> {
    value["behaviors"]
        .as_array()
        .expect("behavior list")
        .iter()
        .filter(|behavior| {
            matches!(
                behavior["category"].as_str(),
                Some("context-after-failure" | "callback-ordering" | "dom-mutation")
            )
        })
        .collect()
}

#[test]
fn c_boundary_behaviors_are_explicitly_planned() {
    // These observable donor contracts require C object identity and mutable
    // libxml2 nodes. Naming them prevents a missing native analogue from being
    // mistaken for an unmeasured or forgotten behavior.
    let ledger = ledger();
    let behaviors = c_boundary_behaviors(&ledger);
    assert_eq!(behaviors.len(), 3);
    assert!(behaviors.iter().all(|behavior| {
        behavior["classification"] == "planned-c-compatibility-boundary"
            && behavior["control"]["boundary"]
                .as_str()
                .is_some_and(|boundary| boundary.contains("C ") || boundary.contains("libxml2"))
    }));
}

#[test]
fn c_boundary_behaviors_are_not_claimed_as_native() {
    // Native contexts return owned results and leave input XML untouched.
    // A generated-ledger change must not silently advertise C lifecycle parity.
    let ledger = ledger();
    assert!(c_boundary_behaviors(&ledger).iter().all(|behavior| {
        behavior["classification"] != "native"
            && behavior["control"]["default"]
                .as_str()
                .is_some_and(|default| default.contains("native") || default.contains("Rust"))
    }));
}

#[test]
fn every_behavior_names_control_and_bidirectional_evidence() {
    // Each quirk must identify its trusted control boundary and both the
    // accepted and rejected side of the contract.
    let ledger = ledger();
    let evidence = ledger["evidence"].as_object().expect("evidence map");
    for behavior in ledger["behaviors"].as_array().expect("behavior list") {
        for field in ["boundary", "setting", "default"] {
            assert!(
                behavior["control"][field]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
                "{} has incomplete control field {field}",
                behavior["id"]
            );
        }
        let evidence_id = behavior["evidence"].as_str().expect("evidence id");
        let item = evidence.get(evidence_id).expect("referenced evidence");
        assert!(
            !item["positive"]
                .as_array()
                .expect("positive tests")
                .is_empty()
        );
        assert!(
            !item["negative"]
                .as_array()
                .expect("negative tests")
                .is_empty()
        );
    }
}

fn xmlsec1_prefix() -> Option<PathBuf> {
    std::env::var_os("XMLSEC1_PREFIX")
        .map(PathBuf::from)
        .or_else(|| {
            let binary = PathBuf::from(std::env::var_os("XMLSEC1_BIN")?);
            binary.parent()?.parent().map(Path::to_path_buf)
        })
}

#[test]
fn pinned_c_oracle_reports_context_callback_and_dom_contracts() {
    // This probe is test-only: it measures the donor C contract without
    // introducing libxmlsec1 into the native Rust runtime path.
    let Some(prefix) = xmlsec1_prefix() else {
        eprintln!("skipping C behavior oracle: XMLSEC1_PREFIX/XMLSEC1_BIN is not configured");
        return;
    };
    let config = prefix.join("bin/xmlsec1-config");
    let flags = Command::new(&config)
        .args(["--cflags", "--libs"])
        .output()
        .expect("pinned xmlsec1-config must run");
    assert!(
        flags.status.success(),
        "{}",
        String::from_utf8_lossy(&flags.stderr)
    );
    let flags = String::from_utf8(flags.stdout).expect("xmlsec1-config output must be UTF-8");
    let temporary = ProbeDirectory::create();
    let probe = temporary.0.join("xmlsec1-behavior-probe");
    let compile = Command::new("cc")
        .arg("tests/fixtures/compatibility/xmlsec1_behavior_probe.c")
        .args(flags.split_whitespace())
        .arg("-o")
        .arg(&probe)
        .output()
        .expect("C compiler must run");
    assert!(
        compile.status.success(),
        "probe compile failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let library_path = prefix.join("lib");
    let run = Command::new(&probe)
        .env("LD_LIBRARY_PATH", &library_path)
        .env("DYLD_LIBRARY_PATH", &library_path)
        .env("LTDL_LIBRARY_PATH", &library_path)
        .args([
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
            "tests/fixtures/keys/rsa/rsa-2048-pubkey.pem",
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl",
            "tests/fixtures/keys/rsa/rsa-2048-key.pem",
        ])
        .output()
        .expect("compiled behavior probe must run");
    assert!(
        run.status.success(),
        "probe failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let output = String::from_utf8(run.stdout).expect("probe output must be UTF-8");
    let lines = output.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "unexpected probe output: {output}");
    assert_eq!(lines[0], "valid=0,OK,UNKNOWN,1", "{output}");
    assert_eq!(lines[1], "invalid=0,FAILED,REFERENCE,1", "{output}");
    assert_eq!(lines[2], "abort=-1,ERROR,UNKNOWN,1", "{output}");
    assert_eq!(lines[3], "sign=0,1,1", "{output}");
}
