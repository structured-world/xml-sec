//! `xades corpus [--generate] [--results DIR]`: verifies every synthetic signed
//! input with libxmlsec1 and the Rust probe in both `here()` modes, and keeps
//! commands, streams, versions, octet comparisons and hashes. `--generate`
//! explicitly signs new inputs; ordinary runs never change them.

use super::{
    C11, Corpus, DS, EXC, F2, absolute, compare, debug_buffer, digest, line, read, write,
    write_json, xml,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Decodes base64 text, ignoring the whitespace XML allows inside it.
pub(crate) fn base64(text: &str) -> Result<Vec<u8>, String> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    STANDARD
        .decode(compact)
        .map_err(|error| format!("invalid base64: {error}"))
}

/// The pieces of `data` after each `separator`, as Python's `split()[1:]`.
pub(crate) fn after_each<'a>(data: &'a [u8], separator: &[u8]) -> Vec<&'a [u8]> {
    let mut pieces = Vec::new();
    let mut rest = data;
    let mut started = false;
    while let Some(index) = rest
        .windows(separator.len())
        .position(|window| window == separator)
    {
        if started {
            pieces.push(&rest[..index]);
        }
        started = true;
        rest = &rest[index + separator.len()..];
    }
    if started {
        pieces.push(rest);
    }
    pieces
}

/// The variant transform, Reference and `SignedInfo` canonicalization, and
/// whether the Reference keeps comments.
struct Variant {
    name: &'static str,
    transform: String,
    reference: String,
    signed_info: &'static str,
    comments: bool,
}

fn filters(operations: &[(&str, &str)]) -> String {
    let mut transform = format!(r#"<ds:Transform Algorithm="{F2}">"#);
    for (operation, expression) in operations {
        transform.push_str(r#"<f:XPath xmlns:f=""#);
        transform.push_str(F2);
        transform.push_str(r#"" Filter=""#);
        transform.push_str(operation);
        transform.push_str(r#"">"#);
        transform.push_str(expression);
        transform.push_str("</f:XPath>");
    }
    transform.push_str("</ds:Transform>");
    transform
}

fn variants(enveloped: &str) -> Vec<Variant> {
    let subtract = filters(&[("subtract", "/descendant::ds:Signature")]);
    let sequence = [
        ("intersect", "/Document/Box/Data"),
        ("subtract", "/Document/Box/Data/Excluded"),
        ("union", "/Document/Outside"),
    ];
    let mut restored = sequence.to_vec();
    restored.push(("union", "/Document/Box/Data/Excluded"));
    let data = filters(&[("intersect", "/Document/Box/Data")]);
    let variant = |name, transform: &str, reference: &str, signed_info, comments| Variant {
        name,
        transform: transform.to_owned(),
        reference: reference.to_owned(),
        signed_info,
        comments,
    };
    let here = r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature) and count(here()/ds:XPath) = 1</ds:XPath></ds:Transform>"#;
    vec![
        variant("enveloped-control", enveloped, EXC, EXC, false),
        variant("id-reference", enveloped, EXC, EXC, false),
        variant("wrong-properties-type", enveloped, EXC, EXC, false),
        variant("filter2-subtract", &subtract, EXC, EXC, false),
        variant("filter2-sequence", &filters(&sequence), EXC, EXC, false),
        variant("filter2-restored", &filters(&restored), EXC, EXC, false),
        variant("c14n11-reference", &data, C11, EXC, false),
        variant("c14n11-signedinfo", &subtract, EXC, C11, false),
        variant(
            "c14n11-comments",
            &data,
            &format!("{C11}#WithComments"),
            C11,
            true,
        ),
        variant(
            "empty-result",
            &filters(&[("intersect", "/no-such-element")]),
            EXC,
            EXC,
            false,
        ),
        variant(
            "axis-subset",
            &filters(&[(
                "intersect",
                "/Document/Box/Data/@b | /Document/Box/Data/namespace::q",
            )]),
            EXC,
            EXC,
            false,
        ),
        variant("here-legacy", here, EXC, EXC, false),
    ]
}

const PAYLOAD: &str = concat!(
    r#"<Document xmlns:q="urn:test:attributes" xml:id="document" "#,
    r#"xml:base="https://example.invalid/a/" xml:lang="en">"#,
    r#"<Box xml:id="box" xml:base="b/"><Data Id="payload" xml:id="business" "#,
    r#"b="2" a="1" q:flag="yes">Synthetic invoice 123<!--covered comment-->"#,
    r#"<Keep>signed</Keep><Excluded>mutable</Excluded></Data></Box>"#,
    r#"<Outside Id="wrong">unrelated object</Outside>"#,
);

/// The baseline template; new test credentials only when none are retained.
fn template(corpus: &Corpus, fixtures: &Path, work: &Path) -> Result<String, String> {
    let retained = fixtures.join("enveloped-control.template.xml");
    if retained.exists() {
        return xml::read(&retained);
    }
    let env = [
        ("XADES_FIXTURE_WORK".to_owned(), work.display().to_string()),
        (
            "XADES_FIXTURE_OUTPUT".to_owned(),
            fixtures.join("baseline").display().to_string(),
        ),
        (
            "XMLSEC1_BIN".to_owned(),
            corpus.xmlsec.to_string_lossy().into_owned(),
        ),
    ];
    let script = corpus.root.join("scripts/generate-xades-fixtures.sh");
    let log = corpus.package().join("generation/baseline");
    let run = super::process::run(
        &line(&[&"bash", &script]),
        &log,
        &corpus.root,
        &env,
        super::process::DEADLINE,
    )?;
    if !run.success() {
        return Err("baseline generator failed; inspect generation/baseline.stderr".into());
    }
    for name in ["signer.key", "signer.pem", "intermediate.pem"] {
        std::fs::copy(work.join(name), fixtures.join(name))
            .map_err(|error| format!("copy {name}: {error}"))?;
    }
    xml::read(&work.join("enveloped.template.xml"))
}

/// One retained signed input and whether XML signature verification must accept it.
fn case(name: &str, file: &str, valid: bool) -> Value {
    json!({ "name": name, "file": file, "valid": valid })
}

/// Signs new synthetic variants and their mutations with the native oracle.
pub(crate) fn generate(corpus: &Corpus) -> Result<(), String> {
    let package = corpus.package();
    let fixtures = package.join("fixtures");
    std::fs::create_dir_all(&fixtures).map_err(|error| error.to_string())?;
    let work = tempfile::Builder::new()
        .prefix("xades-interop-")
        .tempdir()
        .map_err(|error| error.to_string())?;
    let template = template(corpus, &fixtures, work.path())?.replacen(
        r#"<Document><Data Id="payload">Enveloped baseline payload</Data>"#,
        PAYLOAD,
        1,
    );
    let enveloped = format!(r#"<ds:Transform Algorithm="{DS}enveloped-signature"/>"#);
    let mut manifest = Vec::new();
    for variant in variants(&enveloped) {
        let mut text = template.replacen(&enveloped, &variant.transform, 1);
        text = text.replacen(
            &format!(r#"<ds:CanonicalizationMethod Algorithm="{EXC}"/>"#),
            &format!(
                r#"<ds:CanonicalizationMethod Algorithm="{}"/>"#,
                variant.signed_info
            ),
            1,
        );
        text = text.replacen(
            &format!(
                "{}\n        <ds:Transform Algorithm=\"{EXC}\"/>",
                variant.transform
            ),
            &format!(
                "{}\n        <ds:Transform Algorithm=\"{}\"/>",
                variant.transform, variant.reference
            ),
            1,
        );
        if variant.comments {
            text = text.replacen(
                r#"Id="sig-data" URI="""#,
                r##"Id="sig-data" URI="#xpointer(/)""##,
                1,
            );
        }
        if variant.name == "id-reference" {
            text = text.replacen(
                r#"Id="sig-data" URI="""#,
                r##"Id="sig-data" URI="#payload""##,
                1,
            );
        }
        if variant.name == "wrong-properties-type" {
            text = text.replacen(
                r#"Type="http://uri.etsi.org/01903#SignedProperties""#,
                r#"Type="urn:test:wrong-properties""#,
                1,
            );
        }
        let source = fixtures.join(format!("{}.template.xml", variant.name));
        write(&source, &text)?;
        let target = fixtures.join(format!("{}.xml", variant.name));
        let credentials = ["signer.key", "signer.pem", "intermediate.pem"]
            .map(|name| fixtures.join(name).display().to_string())
            .join(",");
        let mut args = corpus.oracle_args("--sign");
        args.extend(line(&[
            &"--lax-key-search",
            &"--privkey-pem",
            &credentials,
            &"--output",
            &target,
            &source,
        ]));
        if !corpus
            .command(&args, &package.join("generation").join(variant.name))?
            .success()
        {
            return Err(format!("independent signing failed: {}", variant.name));
        }
        manifest.push(case(
            variant.name,
            &format!("fixtures/{}.xml", variant.name),
            true,
        ));
    }
    mutations(&fixtures, &mut manifest)?;
    for name in [
        "enveloped",
        "wrong-target",
        "untyped-signed-properties",
        "certificate-digest-mismatch",
    ] {
        manifest.push(case(
            &format!("baseline-{name}"),
            &format!("fixtures/baseline/{name}.xml"),
            true,
        ));
    }
    write_json(&package.join("cases.json"), &Value::Array(manifest))
}

/// A changed copy of a signed variant: name, original, the first occurrence
/// replaced, its replacement and whether verification must accept it.
type Mutation<'a> = (&'a str, &'a str, &'a str, &'a str, bool);

fn mutate(
    fixtures: &Path,
    manifest: &mut Vec<Value>,
    mutations: &[Mutation<'_>],
) -> Result<(), String> {
    for &(name, original, before, after, valid) in mutations {
        let text = xml::read(&fixtures.join(format!("{original}.xml")))?;
        if !text.contains(before) {
            return Err(format!("mutation did not match: {name}"));
        }
        write(
            &fixtures.join(format!("{name}.xml")),
            text.replacen(before, after, 1),
        )?;
        manifest.push(case(name, &format!("fixtures/{name}.xml"), valid));
    }
    Ok(())
}

/// Changed copies of signed variants, each with its required verdict.
fn mutations(fixtures: &Path, manifest: &mut Vec<Value>) -> Result<(), String> {
    mutate(fixtures, manifest, &CONTENT_MUTATIONS)?;
    signature_mutations(fixtures, manifest)?;
    wrapped_object(fixtures, manifest)
}

/// Changes to signed content, comments, attributes and namespaces.
const CONTENT_MUTATIONS: [Mutation<'static>; 9] = [
    (
        "tampered-content",
        "filter2-subtract",
        "Synthetic invoice 123",
        "Synthetic invoice 999",
        false,
    ),
    (
        "excluded-signature-object",
        "filter2-subtract",
        "</ds:Signature>",
        "<ds:Object>unsigned note</ds:Object></ds:Signature>",
        true,
    ),
    (
        "excluded-subtree",
        "filter2-sequence",
        ">mutable<",
        ">changed<",
        true,
    ),
    (
        "comment-omitted",
        "filter2-subtract",
        "covered comment",
        "changed comment",
        true,
    ),
    (
        "comment-covered",
        "c14n11-comments",
        "covered comment",
        "changed comment",
        false,
    ),
    (
        "attribute-covered",
        "c14n11-reference",
        r#"q:flag="yes""#,
        r#"q:flag="no""#,
        false,
    ),
    (
        "namespace-covered",
        "c14n11-reference",
        "urn:test:attributes",
        "urn:test:changed",
        false,
    ),
    (
        "xmlbase-covered",
        "c14n11-reference",
        r#"xml:base="b/""#,
        r#"xml:base="changed/""#,
        false,
    ),
    (
        "xmlid-covered",
        "c14n11-reference",
        r#"xml:id="business""#,
        r#"xml:id="changed""#,
        false,
    ),
];

/// Changes to key data, signature value, algorithms, URIs and IDs.
fn signature_mutations(fixtures: &Path, manifest: &mut Vec<Value>) -> Result<(), String> {
    let signed = xml::read(&fixtures.join("filter2-subtract.xml"))?;
    let first = |pattern: &str| -> Result<String, String> {
        regex::Regex::new(pattern)
            .map_err(|error| error.to_string())?
            .captures(&signed)
            .map(|found| found[1].to_owned())
            .ok_or_else(|| format!("no match for {pattern}"))
    };
    let certificate = first("<ds:X509Certificate>([^<]+)")?;
    let root = STANDARD.encode(read(&fixtures.join("baseline/root.der"))?);
    write(
        &fixtures.join("keyinfo-certificate-substituted.xml"),
        signed.replacen(&certificate, &root, 1),
    )?;
    manifest.push(case(
        "keyinfo-certificate-substituted",
        "fixtures/keyinfo-certificate-substituted.xml",
        false,
    ));
    let algorithm = format!("{F2}\"");
    mutate(
        fixtures,
        manifest,
        &[
            (
                "union-tampered",
                "filter2-sequence",
                ">unrelated object<",
                ">changed<",
                false,
            ),
            (
                "unknown-algorithm",
                "filter2-subtract",
                &algorithm,
                "urn:test:unsupported\"",
                false,
            ),
            (
                "malformed-xpath",
                "filter2-subtract",
                "/descendant::ds:Signature",
                "[",
                false,
            ),
            (
                "external-http",
                "filter2-subtract",
                r#"Id="sig-data" URI="""#,
                r#"Id="sig-data" URI="https://example.invalid/never-fetch""#,
                false,
            ),
            (
                "external-file",
                "filter2-subtract",
                r#"Id="sig-data" URI="""#,
                r#"Id="sig-data" URI="file:///never-read""#,
                false,
            ),
            (
                "duplicate-id",
                "id-reference",
                r#"<Outside Id="wrong">"#,
                r#"<Outside Id="payload">"#,
                false,
            ),
        ],
    )?;
    let value = first(r"<ds:SignatureValue[^>]*>([^<]+)")?;
    let changed = if value.starts_with('A') { "B" } else { "A" }.to_owned() + &value[1..];
    write(
        &fixtures.join("signature-value-tampered.xml"),
        signed.replacen(&value, &changed, 1),
    )?;
    manifest.push(case(
        "signature-value-tampered",
        "fixtures/signature-value-tampered.xml",
        false,
    ));
    Ok(())
}

/// XML Signature 1.1 §8.1.1: valid crypto covers transformed data, not a same-name
/// replacement chosen by the application. Keeps the signed Data, but puts
/// another Data in its business position.
fn wrapped_object(fixtures: &Path, manifest: &mut Vec<Value>) -> Result<(), String> {
    let signed = xml::read(&fixtures.join("id-reference.xml"))?;
    let data = regex::Regex::new(r#"<Data Id="payload".*?</Data>"#)
        .map_err(|error| error.to_string())?
        .find(&signed)
        .ok_or("no signed Data")?
        .as_str()
        .to_owned();
    let wrapped = signed.replacen(
        &data,
        &format!(r#"<Data Id="replacement">attacker invoice</Data><Wrapper>{data}</Wrapper>"#),
        1,
    );
    write(&fixtures.join("wrapped-object.xml"), wrapped)?;
    manifest.push(case("wrapped-object", "fixtures/wrapped-object.xml", true));
    Ok(())
}

/// `program` as named, or found on `PATH`.
pub(crate) fn which(program: &std::ffi::OsStr) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.components().count() > 1 {
        return Some(path.to_owned());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

/// Tool and dependency versions of this run.
fn versions(corpus: &Corpus, results: &Path) -> Result<Map<String, Value>, String> {
    let log = |name: &str| results.join("versions").join(name);
    let oracle = corpus.command(&line(&[&corpus.xmlsec, &"--version"]), &log("xmlsec1"))?;
    if !oracle.success() {
        return Err("oracle version query failed; inspect versions/xmlsec1.stderr".into());
    }
    let oracle_version = text(&oracle.stdout).trim().to_owned();
    if !["xmlsec1 1.3.12 (openssl)", "xmlsec1 1.3.13 (openssl)"].contains(&oracle_version.as_str())
    {
        return Err(format!(
            "byte-dump parser requires qualified native xmlsec1 1.3.12/1.3.13 (openssl), got: {oracle_version}"
        ));
    }
    let commit = corpus.command(&line(&[&"git", &"rev-parse", &"HEAD"]), &log("commit"))?;
    if !commit.success() {
        return Err("commit query failed; inspect versions/commit.stderr".into());
    }
    let mut versions = Map::new();
    versions.insert("commit".into(), text(&commit.stdout).trim().into());
    versions.insert(
        "xmlsec1".into(),
        (text(&oracle.stdout) + &text(&oracle.stderr)).into(),
    );
    let executable = which(&corpus.xmlsec)
        .ok_or("the native oracle is not on PATH")?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    versions.insert(
        "oracle_binary".into(),
        json!({
            "name": executable.file_name().map(|name| name.to_string_lossy().into_owned()),
            "sha256": digest(&read(&executable)?),
        }),
    );
    let tools: [(&str, &[&str]); 3] = [
        ("rustc", &["rustc", "-Vv"]),
        ("cargo", &["cargo", "-V"]),
        ("openssl", &["openssl", "version"]),
    ];
    for (name, args) in tools {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let result = corpus.command(&args, &log(name))?;
        versions.insert(
            name.into(),
            (text(&result.stdout) + &text(&result.stderr)).into(),
        );
    }
    // Diagnostic records only: their exit status does not change the run.
    let linkage = if std::env::consts::OS == "macos" {
        "otool -L"
    } else {
        "ldd"
    };
    let mut args: Vec<OsString> = linkage.split(' ').map(OsString::from).collect();
    args.push(executable.into());
    corpus.command(&args, &log("oracle-linkage"))?;
    corpus.command(
        &line(&[
            &"cargo",
            &"tree",
            &"-p",
            &"xml-sec-xades",
            &"-e",
            &"features",
        ]),
        &log("features"),
    )?;
    let metadata = corpus.command(
        &line(&[&"cargo", &"metadata", &"--format-version", &"1"]),
        &log("metadata"),
    )?;
    if !metadata.success() {
        return Err("cargo metadata failed".into());
    }
    let metadata: Value =
        serde_json::from_slice(&metadata.stdout).map_err(|error| error.to_string())?;
    versions.insert(
        "resolved_dependencies".into(),
        super::resolved_versions(&metadata)?,
    );
    Ok(versions)
}

/// The oracle's Reference and `SignedInfo` octets. libxmlsec1's `--store-*`
/// wraps the exact bytes in diagnostic markers; a Reference without a buffer
/// counts as empty only after successful processing of a signed SHA-256(empty).
fn oracle_octets(stdout: &[u8], succeeded: bool, values: &[String]) -> Result<Octets, String> {
    let mut references = Vec::new();
    for (index, block) in after_each(stdout, b"= REFERENCE VERIFICATION CONTEXT\n")
        .into_iter()
        .enumerate()
    {
        if let Some(data) = debug_buffer(block, "PreDigest")? {
            references.push(data);
            continue;
        }
        let empty_digest = values
            .get(index)
            .map(|value| base64(value))
            .transpose()?
            .is_some_and(|written| written == sha2_empty());
        let processed = block.windows(14).any(|window| window == b"== Status: OK\n");
        if !(succeeded && processed && empty_digest) {
            // Fail-fast processing never produced these bytes.
            break;
        }
        references.push(Vec::new());
    }
    Ok(Octets {
        references,
        signed_info: debug_buffer(stdout, "PreSigned")?,
    })
}

/// The canonical octets the native oracle printed for one case.
struct Octets {
    references: Vec<Vec<u8>>,
    signed_info: Option<Vec<u8>>,
}

fn sha2_empty() -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha256::digest([]).to_vec()
}

const SIGNATURE_LEVEL: [&str; 6] = [
    "signature-value-tampered",
    "keyinfo-certificate-substituted",
    "unknown-algorithm",
    "malformed-xpath",
    "external-http",
    "external-file",
];

/// Whether the probe's `XAdES` outcome is the normative one. EN 319 132-1
/// V1.3.1 §§4.3.1 (Target), 4.4.2 (Type), 5.2.2 (the first certificate
/// reference identifies the signer). The signature is verified before any
/// Reference (W3C XML Signature Best Practices BP1): when it fails or
/// verification stops before it, `XAdES` never runs; a verified signature with a
/// failing Reference reaches `XAdES`, which refuses its invalid status.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub(crate) fn xades_outcome(name: &str, expected_valid: bool, xades: &str) -> bool {
    if !expected_valid && SIGNATURE_LEVEL.contains(&name) {
        xades == "not run or blocked"
    } else if !expected_valid {
        xades.starts_with("Err(Prepare(Binding(Signature {")
            && xades.ends_with("status: Invalid })))")
    } else if name == "baseline-wrong-target" {
        xades.contains("Binding(Target")
    } else if [
        "baseline-untyped-signed-properties",
        "wrong-properties-type",
    ]
    .contains(&name)
    {
        xades.contains("Binding(Missing")
    } else if name == "baseline-certificate-digest-mismatch" {
        xades == "Ok(Assessed((false, false)))"
    } else {
        xades == "Ok(Assessed((true, true)))"
    }
}

/// The diagnostic that names the level at which an invalid case must fail.
fn failure_marker(name: &str) -> &'static str {
    match name {
        "unknown-algorithm" => "ParseSignedInfo(Transform(UnsupportedTransform(",
        "malformed-xpath" => "ParseSignedInfo(Transform(XPath(",
        "external-http" | "external-file" => "Policy(Uri {",
        "duplicate-id" => "Invalid(ReferenceProcessingFailure { ref_index: 0 })",
        "keyinfo-certificate-substituted" => "KeyResolution(",
        "signature-value-tampered" => "Invalid(SignatureMismatch)",
        _ => "Invalid(ReferenceDigestMismatch {",
    }
}

/// What the oracle established for one case.
struct Oracle<'a> {
    octets: &'a Octets,
    values: &'a [String],
}

/// One probe mode's facts for one case.
fn mode_facts(
    name: &str,
    valid: bool,
    mode: &str,
    out: &Path,
    oracle: &Oracle<'_>,
) -> Result<Map<String, Value>, String> {
    let text = xml::read(&out.join("result.txt"))?;
    let actual_valid = text.contains("all_valid=true\n");
    // The here() fixture was signed under the independent engine's documented
    // legacy interpretation; there is no automatic mode retry.
    let expected_valid = valid && !(name == "here-legacy" && mode == "spec");
    let mut facts = Map::new();
    let verdict = |ok: bool| Value::from(if ok { "verified" } else { "failed" });
    facts.insert("xml_dsig".into(), verdict(actual_valid == expected_valid));
    facts.insert("actual_valid".into(), actual_valid.into());
    facts.insert("expected_valid".into(), expected_valid.into());
    let diagnostics: Vec<Value> = text
        .lines()
        .filter(|line| {
            line.contains(".error=")
                || line.contains(".status=")
                || line.starts_with("replay.refused=")
        })
        .map(Into::into)
        .collect();
    let mut references = Vec::new();
    for (index, expected) in oracle.octets.references.iter().enumerate() {
        let actual_path = out.join(format!("reference-{index}.bin"));
        if !actual_path.exists() {
            references.push(json!({ "status": "not run or blocked", "reason": "fail-fast or processing error" }));
            continue;
        }
        let actual = read(&actual_path)?;
        let mut result = compare(expected, &actual);
        let written = base64(oracle.values.get(index).ok_or("missing DigestValue")?)?;
        result.insert("digest_value_hex".into(), super::hex(&written).into());
        result.insert("oracle_digest_hex".into(), digest(expected).into());
        result.insert("rust_digest_hex".into(), digest(&actual).into());
        result.insert(
            "digest_matches".into(),
            (super::hex(&written) == digest(&actual)).into(),
        );
        let replay = out.join(format!("replay-{index}.bin"));
        let replay = if replay.exists() {
            Value::Object(compare(&actual, &read(&replay)?))
        } else {
            json!({ "status": "not run or blocked", "reason": "signature not authenticated" })
        };
        result.insert("replay".into(), replay);
        references.push(Value::Object(result));
    }
    facts.insert("references".into(), Value::Array(references));
    let signature = out.join("signature-0.bin");
    let signed_info = match oracle.octets.signed_info.as_deref() {
        Some(expected) if signature.exists() => {
            Value::Object(compare(expected, &read(&signature)?))
        }
        _ => json!({ "status": "not run or blocked" }),
    };
    facts.insert("signed_info".into(), signed_info);
    let xades = text
        .lines()
        .find_map(|line| line.strip_prefix("xades="))
        .unwrap_or("not run or blocked")
        .to_owned();
    facts.insert("diagnostics".into(), Value::Array(diagnostics.clone()));
    facts.insert("xades".into(), xades.clone().into());
    facts.insert(
        "xades_expected_outcome".into(),
        verdict(xades_outcome(name, expected_valid, &xades)),
    );
    if !expected_valid {
        let marker = failure_marker(name);
        let found = diagnostics
            .iter()
            .any(|line| line.as_str().is_some_and(|line| line.contains(marker)));
        facts.insert("failure_level_status".into(), verdict(found));
    }
    // A valid result requires every byte artifact and replay; a missing
    // artifact never counts as a pass.
    let complete = !expected_valid || complete_evidence(&facts);
    facts.insert("complete_valid_evidence".into(), complete.into());
    Ok(facts)
}

fn complete_evidence(facts: &Map<String, Value>) -> bool {
    let references = facts["references"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    references.len() == 2
        && facts["signed_info"]["status"] == "verified"
        && references.iter().all(|reference| {
            reference["status"] == "verified"
                && reference["digest_matches"] == true
                && reference["replay"]["status"] == "verified"
        })
}

/// Whether a row or one of its modes has an unexpected result.
fn unexpected(row: &Value, mode: &str, facts: &Value) -> bool {
    let failed = |value: &Value| *value == "failed";
    let references = facts["references"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    failed(&facts["xml_dsig"])
        || failed(&facts["signed_info"]["status"])
        || failed(&facts["xades_expected_outcome"])
        || failed(&row["oracle_status"])
        || failed(&facts["failure_level_status"])
        || facts["complete_valid_evidence"] != true
        || (references
            .iter()
            .any(|reference| failed(&reference["status"]))
            && !(row["name"] == "here-legacy" && mode == "spec"))
        || row["expected_targets"]
            .as_object()
            .is_some_and(|targets| targets.values().any(|target| failed(&target["status"])))
}

/// Verifies every retained case; returns the names of unexpected outcomes.
pub(crate) fn run_all(corpus: &Corpus, results: &Path) -> Result<Vec<String>, String> {
    if results.exists() {
        return Err(
            "results already exist; archive them or choose a fresh checkout before rerunning"
                .into(),
        );
    }
    std::fs::create_dir_all(results)
        .map_err(|error| format!("create {}: {error}", results.display()))?;
    let versions = versions(corpus, results)?;
    let binary = corpus.build_probe(&results.join("build"))?;
    let package = corpus.package();
    let cases: Value = serde_json::from_str(&xml::read(&package.join("cases.json"))?)
        .map_err(|error| error.to_string())?;
    let summary = cases
        .as_array()
        .into_iter()
        .flatten()
        .map(|case| verify_case(corpus, &binary, results, case))
        .collect::<Result<Vec<Value>, String>>()?;
    write_json(&results.join("versions.json"), &Value::Object(versions))?;
    let summary = Value::Array(summary);
    write_json(&results.join("summary.json"), &summary)?;
    let rows = summary.as_array().map_or(&[][..], Vec::as_slice);
    let failures: Vec<String> = rows
        .iter()
        .flat_map(|row| {
            row["modes"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(mode, facts)| unexpected(row, mode, facts))
                .map(|(mode, _)| format!("{}/{mode}", row["name"].as_str().unwrap_or_default()))
                .collect::<Vec<_>>()
        })
        .collect();
    let listed: Vec<String> = failures
        .iter()
        .map(|failure| Value::from(failure.as_str()).to_string())
        .collect();
    println!(
        r#"{{"cases": {}, "unexpected_failures": [{}]}}"#,
        rows.len(),
        listed.join(", ")
    );
    Ok(failures)
}

/// Verifies one case with the oracle and both probe modes; returns its row.
fn verify_case(
    corpus: &Corpus,
    binary: &Path,
    results: &Path,
    case: &Value,
) -> Result<Value, String> {
    let package = corpus.package();
    let root_der = package.join("fixtures/baseline/root.der");
    let name = case["name"].as_str().ok_or("case without a name")?;
    let valid = case["valid"] == true;
    let fixture = package.join(case["file"].as_str().ok_or("case without a file")?);
    let folder = results.join(name);
    std::fs::create_dir(&folder)
        .map_err(|error| format!("create {}: {error}", folder.display()))?;
    let mut args = corpus.oracle_args("--verify");
    args.push(fixture.clone().into());
    let oracle = corpus.command(&args, &folder.join("oracle"))?;
    let values = xml::digest_values(&xml::read(&fixture)?, name)?;
    let octets = oracle_octets(&oracle.stdout, oracle.success(), &values)?;
    if oracle.success() && (octets.references.len() != 2 || octets.signed_info.is_none()) {
        return Err(format!(
            "oracle byte extraction incomplete: {name}; inspect raw diagnostics"
        ));
    }
    for (index, data) in octets.references.iter().enumerate() {
        write(
            &folder.join(format!("expected-reference-{index}.bin")),
            data,
        )?;
    }
    if let Some(signed_info) = &octets.signed_info {
        write(&folder.join("expected-signedinfo.bin"), signed_info)?;
    }
    let mut row = Map::new();
    row.insert("name".into(), name.into());
    row.insert("fixture_sha256".into(), digest(&read(&fixture)?).into());
    row.insert("expected_xml_dsig_valid".into(), valid.into());
    row.insert("oracle_exit".into(), oracle.code.into());
    let oracle_status = if oracle.success() == valid {
        "verified"
    } else {
        "failed"
    };
    row.insert("oracle_status".into(), oracle_status.into());
    let evidence = Oracle {
        octets: &octets,
        values: &values,
    };
    let mut modes = Map::new();
    for mode in ["spec", "legacy"] {
        let out = folder.join(mode);
        let probe = line(&[&binary, &fixture, &root_der, &out, &mode, &"-"]);
        if !corpus
            .command(&probe, &folder.join(format!("probe-{mode}")))?
            .success()
        {
            return Err(format!("probe crashed: {name}/{mode}"));
        }
        modes.insert(
            mode.into(),
            Value::Object(mode_facts(name, valid, mode, &out, &evidence)?),
        );
    }
    row.insert("modes".into(), Value::Object(modes));
    if let Some(targets) = expected_targets(corpus, name, binary, &fixture, &folder)? {
        row.insert("expected_targets".into(), Value::Object(targets));
    }
    Ok(Value::Object(row))
}

/// Explicit application-target requirements, checked on identities of the
/// same immutable document. Arbitrary Filter2 coverage stays conservative.
fn expected_targets(
    corpus: &Corpus,
    name: &str,
    binary: &Path,
    fixture: &Path,
    folder: &Path,
) -> Result<Option<Map<String, Value>>, String> {
    const CHECKED: [&str; 6] = [
        "enveloped-control",
        "filter2-subtract",
        "empty-result",
        "filter2-sequence",
        "id-reference",
        "wrapped-object",
    ];
    if !CHECKED.contains(&name) {
        return Ok(None);
    }
    let candidates = if name == "wrapped-object" {
        ["payload", "replacement"]
    } else {
        ["payload", "wrong"]
    };
    let root_der = corpus.package().join("fixtures/baseline/root.der");
    let mut targets = Map::new();
    for target in candidates {
        let out = folder.join(format!("expected-{target}"));
        let probe = line(&[&binary, &fixture, &root_der, &out, &"spec", &target]);
        if !corpus
            .command(&probe, &folder.join(format!("target-{target}")))?
            .success()
        {
            return Err(format!("target probe crashed: {name}/{target}"));
        }
        let actual = xml::read(&out.join("result.txt"))?.contains("accepted=true\n");
        let expected = name == "enveloped-control"
            || (["id-reference", "wrapped-object"].contains(&name) && target == "payload");
        let status = if actual == expected {
            "verified"
        } else {
            "failed"
        };
        targets.insert(
            target.into(),
            json!({ "actual_accepted": actual, "expected_accepted": expected, "status": status }),
        );
    }
    Ok(Some(targets))
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut generate_inputs = false;
    let mut results = corpus.root.join("target/xades-interop-results");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--generate" => generate_inputs = true,
            "--results" => results = absolute(args.next().ok_or("--results needs a directory")?)?,
            _ => return Err("usage: xades corpus [--generate] [--results DIR]".into()),
        }
    }
    if generate_inputs {
        return Ok(generate(corpus)?);
    }
    let failures = run_all(corpus, &results)?;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("unexpected outcomes: {}", failures.join(", ")).into())
    }
}
