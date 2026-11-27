//! `xades dss [--results DIR] [--summarize]`: builds a local EU DSS probe
//! against the current DSS release and keeps its independent profile reports.
//! Maven downloads public build dependencies; validation reads only local
//! corpus inputs.

use super::{Corpus, absolute, line, read, write_json, xml};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// Maven Central's version list of DSS's `XAdES` module.
const DSS_METADATA: &str =
    "https://repo.maven.apache.org/maven2/eu/europa/ec/joinup/sd-dss/dss-xades/maven-metadata.xml";
/// Maven Central's version list of the Maven distribution.
const MAVEN_METADATA: &str =
    "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/maven-metadata.xml";
/// Maven Central's version list of the logging binding DSS's reports go through.
const SLF4J_METADATA: &str =
    "https://repo.maven.apache.org/maven2/org/slf4j/slf4j-simple/maven-metadata.xml";
/// Maven Central's version list of the plugin that writes the classpath and
/// the dependency tree. No lifecycle phase binds it, so its version is
/// resolved here and named in each call, as the others are.
const DEPENDENCY_PLUGIN_METADATA: &str = "https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-dependency-plugin/maven-metadata.xml";
/// The Maven line the build runs on.
const MAVEN_MAJOR: u64 = 3;

/// The DSS, Maven, slf4j and dependency-plugin releases one run builds
/// against, resolved from Maven Central when it starts: nothing in the
/// repository fixes any of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Release {
    pub(crate) dss: String,
    pub(crate) maven: String,
    pub(crate) slf4j: String,
    pub(crate) dependency_plugin: String,
}

impl Release {
    /// The versions as the run records them.
    pub(crate) fn json(&self) -> Value {
        json!({
            "dss": self.dss,
            "maven": self.maven,
            "slf4j": self.slf4j,
            "maven-dependency-plugin": self.dependency_plugin,
        })
    }

    /// The dependency plugin's `goal`, at the resolved version.
    fn dependency(&self, goal: &str) -> String {
        format!(
            "org.apache.maven.plugins:maven-dependency-plugin:{}:{goal}",
            self.dependency_plugin
        )
    }
}

/// The highest release a Maven `metadata` document lists, among those of the
/// major version `major` when one is named: a version whose every
/// dot-separated part is a number. A pre-release (`6.5.RC1`, `4.0.0-rc-7`,
/// `3.0-alpha-2`) is not a release.
pub(crate) fn newest_release_of(metadata: &str, major: Option<u64>) -> Result<String, String> {
    let document = xml::parse(metadata, "Maven metadata")?;
    let parts = |version: &str| -> Option<Vec<u64>> {
        version.split('.').map(|part| part.parse().ok()).collect()
    };
    xml::below(document.root_element(), "version", None)
        .filter_map(|node| {
            let version = node.text()?.trim();
            Some((parts(version)?, version.to_owned()))
        })
        .filter(|(parts, _)| major.is_none_or(|major| parts.first() == Some(&major)))
        .max()
        .map(|(_, version)| version)
        .ok_or_else(|| "Maven metadata lists no release".to_owned())
}

/// The cases DSS validates. The deliberate external-URI fixtures are never
/// given to another validator.
pub(crate) const CASES: [&str; 9] = [
    "enveloped-control",
    "filter2-subtract",
    "filter2-sequence",
    "c14n11-reference",
    "c14n11-signedinfo",
    "empty-result",
    "baseline-wrong-target",
    "baseline-untyped-signed-properties",
    "baseline-certificate-digest-mismatch",
];

/// The Maven distributions and their repository, outside the corpus.
pub(crate) fn tools(corpus: &Corpus) -> PathBuf {
    corpus.root.join(".tools/xades-dss")
}

/// The `mvn` of the Maven release `version`.
pub(crate) fn maven(corpus: &Corpus, version: &str) -> PathBuf {
    tools(corpus).join(format!("apache-maven-{version}/bin/mvn"))
}

/// `curl` arguments that fetch `url` into `output`. Maven Central answers
/// shared CI addresses with 429 under load, often without Retry-After, for
/// longer than curl's default retries last: eight retries back off for 255
/// seconds in all, within a ten-minute ceiling. A retry rewrites `output` from
/// its start.
pub(crate) fn fetch(url: &str, output: &Path) -> Vec<std::ffi::OsString> {
    line(&[
        &"curl",
        &"--fail",
        &"--silent",
        &"--show-error",
        &"--retry",
        &"8",
        &"--retry-max-time",
        &"600",
        &"--output",
        &output,
        &url,
    ])
}

/// The current DSS, Maven 3, slf4j and dependency-plugin releases, read from
/// Maven Central into `logs`.
pub(crate) fn resolve(corpus: &Corpus, logs: &Path) -> Result<Release, String> {
    let newest = |url: &str, name: &str, major: Option<u64>| -> Result<String, String> {
        let file = logs.join(format!("{name}-metadata.xml"));
        corpus.require(&fetch(url, &file), &logs.join(format!("{name}-metadata")))?;
        newest_release_of(&xml::read(&file)?, major)
    };
    Ok(Release {
        dss: newest(DSS_METADATA, "dss", None)?,
        maven: newest(MAVEN_METADATA, "maven", Some(MAVEN_MAJOR))?,
        slf4j: newest(SLF4J_METADATA, "slf4j", None)?,
        dependency_plugin: newest(DEPENDENCY_PLUGIN_METADATA, "maven-dependency-plugin", None)?,
    })
}

/// A completed probe build: the release it resolved and the classpath its
/// own dependency resolution wrote, so the run launches with the JARs it
/// reports, whatever another run in the checkout resolved since.
pub(crate) struct Built {
    pub(crate) release: Release,
    pub(crate) classpath: String,
}

/// What a DSS report shows about `XAdES` profile binding. EN 319 102-1 V1.4.1
/// §§5.2.2, 5.2.3.4: base-format FC does not attest `XAdES` profile
/// conformance, and ISC must match the actual signer.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>
pub(crate) fn profile_binding(name: &str, row: &Map<String, Value>) -> Option<Value> {
    let verdict = |ok: bool| if ok { "verified" } else { "failed" };
    let row = |field: &str| row.get(field).unwrap_or(&Value::Null);
    match name {
        "baseline-wrong-target" => Some(json!({
            "status": "not run or blocked",
            "reason": "FC and format labels do not attest Target binding; see dss-investigation",
        })),
        "baseline-certificate-digest-mismatch" => {
            let refused = row("conclusions")["ISC"] == "INDETERMINATE"
                && row("subindications")["ISC"] == "NO_SIGNING_CERTIFICATE_FOUND";
            Some(json!({
                "status": verdict(refused),
                "reason": "root-only CertDigest must not identify the leaf signing certificate",
            }))
        }
        "baseline-untyped-signed-properties" => Some(json!({
            "status": verdict(*row("reported_format") == "XAdES-BES"),
            "reason": "format classification only; not full profile validation",
        })),
        _ => None,
    }
}

fn optional(text: Option<String>) -> Value {
    text.map_or(Value::Null, Value::from)
}

/// The conclusions DSS reached for one case.
fn summary_row(logs: &Path, name: &str) -> Result<Value, String> {
    let folder = logs.join(name);
    let simple_text = xml::read(&folder.join("simple.xml"))?;
    let diagnostic_text = xml::read(&folder.join("diagnostic.xml"))?;
    let detailed_text = xml::read(&folder.join("detailed.xml"))?;
    let simple_document = xml::parse(&simple_text, "simple report")?;
    let diagnostic_document = xml::parse(&diagnostic_text, "diagnostic report")?;
    let detailed_document = xml::parse(&detailed_text, "detailed report")?;
    let simple = xml::child(simple_document.root_element(), "Signature")
        .ok_or("simple report without a Signature")?;
    let signature = xml::find(
        diagnostic_document.root_element(),
        "Signatures",
        "Signature",
    )
    .ok_or("diagnostic report without a Signature")?;
    let blocks = xml::signature_blocks(detailed_document.root_element())
        .ok_or("detailed report without signature building blocks")?;
    let matchers: Vec<Value> = xml::elements(signature)
        .filter(|node| node.tag_name().name() == "DigestMatchers")
        .flat_map(xml::elements)
        .filter(|node| node.tag_name().name() == "DigestMatcher")
        .map(|matcher| {
            json!({
                "uri": matcher.attribute("uri"),
                "found": optional(xml::text_at(matcher, &["DataFound"])),
                "intact": optional(xml::text_at(matcher, &["DataIntact"])),
            })
        })
        .collect();
    let mut row = Map::new();
    row.insert("name".into(), name.into());
    row.insert(
        "reported_format".into(),
        simple.attribute("SignatureFormat").into(),
    );
    row.insert(
        "indication".into(),
        optional(xml::text_at(simple, &["Indication"])),
    );
    row.insert(
        "subindication".into(),
        optional(xml::text_at(simple, &["SubIndication"])),
    );
    row.insert(
        "signature_intact".into(),
        optional(xml::text_at(
            signature,
            &["BasicSignature", "SignatureIntact"],
        )),
    );
    let intact = row["signature_intact"] == "true"
        && matchers.len() == 2
        && matchers.iter().all(|matcher| matcher["intact"] == "true");
    row.insert("digest_matchers".into(), Value::Array(matchers));
    row.insert(
        "conclusions".into(),
        Value::Object(xml::conclusions(blocks, "Indication")),
    );
    row.insert(
        "subindications".into(),
        Value::Object(xml::conclusions(blocks, "SubIndication")),
    );
    row.insert(
        "crypto_status".into(),
        if intact { "verified" } else { "failed" }.into(),
    );
    if let Some(observation) = profile_binding(name, &row) {
        row.insert("profile_binding".into(), observation);
    }
    Ok(Value::Object(row))
}

/// Reads the retained reports of every case into `summary.json`.
pub(crate) fn summarize(logs: &Path) -> Result<Vec<Value>, String> {
    let summary = CASES
        .iter()
        .map(|name| summary_row(logs, name))
        .collect::<Result<Vec<Value>, String>>()?;
    write_json(&logs.join("summary.json"), &Value::Array(summary.clone()))?;
    Ok(summary)
}

/// Downloads and checks the Maven distribution `version` once.
fn bootstrap(corpus: &Corpus, version: &str, logs: &Path) -> Result<(), String> {
    use sha2::Digest as _;
    let tools = tools(corpus);
    let archive = tools.join("maven.tar.gz");
    let url = format!(
        "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{version}/apache-maven-{version}-bin.tar.gz"
    );
    corpus.require(&fetch(&url, &archive), &logs.join("download"))?;
    // The checksum goes to a file, not captured stdout, so a retry replaces it.
    let checksum = tools.join("maven.tar.gz.sha512");
    corpus.require(
        &fetch(&format!("{url}.sha512"), &checksum),
        &logs.join("download-sha512"),
    )?;
    let published = read(&checksum)?;
    let published = String::from_utf8_lossy(&published);
    let expected = published.split_whitespace().next().unwrap_or_default();
    if super::hex(&sha2::Sha512::digest(read(&archive)?)) != expected {
        return Err("Maven distribution SHA-512 mismatch".into());
    }
    let file = std::fs::File::open(&archive).map_err(|error| error.to_string())?;
    // Unpacking refuses entries that would land outside `tools`.
    tar::Archive::new(flate2::read::GzDecoder::new(file))
        .unpack(&tools)
        .map_err(|error| format!("unpack Maven: {error}"))
}

/// Builds the probes against the current DSS release with the current Maven,
/// bootstrapping that Maven once, and records both versions and the resolved
/// classpath in `logs`.
pub(crate) fn build(corpus: &Corpus, logs: &Path) -> Result<Built, String> {
    let tools = tools(corpus);
    std::fs::create_dir_all(&tools).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(logs).map_err(|error| error.to_string())?;
    let release = resolve(corpus, logs)?;
    let mvn = maven(corpus, &release.maven);
    if !mvn.exists() {
        bootstrap(corpus, &release.maven, logs)?;
    }
    let package = corpus.package();
    // Build output stays under target, so the repository's cargo clean removes it.
    let mut maven = line(&[
        &mvn,
        &"-B",
        &"-f",
        &package.join("dss/pom.xml"),
        &format!("-Dmaven.repo.local={}", tools.join("repository").display()),
        &format!("-Ddss.version={}", release.dss),
        &format!("-Dslf4j.version={}", release.slf4j),
    ]);
    let resolved = logs.join("classpath.txt");
    let mut build = maven.clone();
    build.extend(line(&[
        &"compile",
        &release.dependency("build-classpath"),
        &format!("-Dmdep.outputFile={}", resolved.display()),
    ]));
    corpus.require(&build, &logs.join("build"))?;
    corpus.require(&line(&[&mvn, &"-v"]), &logs.join("versions"))?;
    maven.extend(line(&[
        &release.dependency("tree"),
        &"-DoutputType=json",
        &format!("-DoutputFile={}", logs.join("dependencies.json").display()),
    ]));
    corpus.require(&maven, &logs.join("dependencies"))?;
    write_json(&logs.join("versions.json"), &release.json())?;
    let classpath = format!(
        "{}:{}",
        corpus.root.join("target/xades-dss/classes").display(),
        xml::read(&resolved)?.trim()
    );
    Ok(Built { release, classpath })
}

/// The command that runs the DSS probe `class` on `classpath` with
/// `arguments`.
pub(crate) fn java(
    classpath: &str,
    class: &str,
    arguments: &[&dyn AsRef<std::ffi::OsStr>],
) -> Vec<std::ffi::OsString> {
    let mut command = line(&[&"java", &"-cp", &classpath, &class]);
    command.extend(
        arguments
            .iter()
            .map(|argument| argument.as_ref().to_owned()),
    );
    command
}

/// Builds the probe and validates every case with DSS.
pub(crate) fn execute(corpus: &Corpus, logs: &Path) -> Result<(), String> {
    if logs.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    let Built { release, classpath } = build(corpus, logs)?;
    let package = corpus.package();
    let cases: Value = serde_json::from_str(&xml::read(&package.join("cases.json"))?)
        .map_err(|error| error.to_string())?;
    for name in CASES {
        let file = cases
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| case["name"] == name)
            .and_then(|case| case["file"].as_str())
            .ok_or_else(|| format!("no corpus case {name}"))?;
        let probe = java(
            &classpath,
            "Probe",
            &[
                &package.join(file),
                &package.join("fixtures/baseline/root.der"),
                &logs.join(name),
            ],
        );
        corpus.require(&probe, &logs.join(format!("{name}-run")))?;
    }
    if summarize(logs)?
        .iter()
        .any(|row| row["crypto_status"] != "verified")
    {
        return Err("DSS cryptographic control failed; inspect retained reports".into());
    }
    println!(
        "EU DSS {}: {} local profile reports saved to {}",
        release.dss,
        CASES.len(),
        logs.display()
    );
    Ok(())
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut logs = corpus.root.join("target/xades-dss-results");
    let mut only_summarize = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--summarize" => only_summarize = true,
            "--results" => logs = absolute(args.next().ok_or("--results needs a directory")?)?,
            _ => return Err("usage: xades dss [--results DIR] [--summarize]".into()),
        }
    }
    if only_summarize {
        summarize(&logs)?;
        return Ok(());
    }
    Ok(execute(corpus, &logs)?)
}
