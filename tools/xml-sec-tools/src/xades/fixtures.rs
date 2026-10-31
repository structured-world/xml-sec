//! `xades fixtures [--output DIR] [--work DIR]`: regenerates the `XAdES`
//! baseline fixtures of `crates/xml-sec-xades`. OpenSSL issues a real root,
//! intermediate and signer path; this tool writes the qualifying properties
//! and xmlsec1, an independent XML signature implementation, computes every
//! reference digest and signature value. Adversarial fixtures are still valid
//! XML signatures: only their `XAdES` properties violate EN 319 132-1.

use super::{DS, EXC, SP, write};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(test)]
mod tests;

pub(crate) const SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

/// Every certificate has the same fixed validity, independent of the run
/// date. It contains the claimed signing time and the instant the tests
/// verify at (Unix time `1_800_000_000`, 2027-01-15T08:00:00Z).
pub(crate) const NOT_BEFORE: &str = "20260101000000Z";
pub(crate) const NOT_AFTER: &str = "20450101000000Z";
const TIME: &str = "2026-10-18T12:00:00Z";
pub(crate) const TIME_COMPACT: &str = "20261018120000Z";
pub(crate) const TEST_INSTANT: &str = "20270115080000Z";

/// The digest and signature algorithms a template's references use.
#[derive(Clone, Copy)]
pub(crate) struct Algorithms {
    pub(crate) digest: &'static str,
    pub(crate) signature: &'static str,
}

pub(crate) const RSA_SHA256_PROFILE: Algorithms = Algorithms {
    digest: SHA256,
    signature: RSA_SHA256,
};
const RSA_SHA384_PROFILE: Algorithms = Algorithms {
    digest: SHA384,
    signature: RSA_SHA384,
};

/// The parts of one `XAdES` signature template.
pub(crate) struct Signature<'a> {
    pub(crate) id: &'a str,
    pub(crate) properties: &'a str,
    pub(crate) data_reference: String,
    pub(crate) mime: &'a str,
    pub(crate) time: &'a str,
    pub(crate) method: &'a str,
    pub(crate) value: &'a str,
    pub(crate) cert_attributes: &'a str,
    pub(crate) target: &'a str,
    pub(crate) reference_type: &'a str,
    pub(crate) objects: String,
    /// `DataObjectFormat` properties of further signed data objects.
    pub(crate) formats: String,
    pub(crate) x509: &'a str,
    pub(crate) unsigned: String,
}

impl Signature<'_> {
    /// The template text, ending with a newline.
    pub(crate) fn render(&self, algorithms: Algorithms) -> String {
        let Self {
            id,
            properties,
            data_reference,
            mime,
            time,
            method,
            value,
            cert_attributes,
            target,
            reference_type,
            objects,
            formats,
            x509,
            unsigned,
        } = self;
        let (digest, signature) = (algorithms.digest, algorithms.signature);
        format!(
            r##"<ds:Signature xmlns:ds="{DS}" Id="{id}">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="{EXC}"/>
    <ds:SignatureMethod Algorithm="{signature}"/>
    {data_reference}
    <ds:Reference {reference_type} URI="#{properties}">
      <ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms>
      <ds:DigestMethod Algorithm="{digest}"/>
      <ds:DigestValue/>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="{id}-value"/>
  <ds:KeyInfo><ds:X509Data>{x509}</ds:X509Data></ds:KeyInfo>
  {objects}
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="{SP}" Target="{target}">
      <xades:SignedProperties Id="{properties}">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>{time}</xades:SigningTime>
          <xades:SigningCertificateV2>
            <xades:Cert{cert_attributes}>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="{method}"/>
                <ds:DigestValue>{value}</ds:DigestValue>
              </xades:CertDigest>
            </xades:Cert>
          </xades:SigningCertificateV2>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#{id}-data">
            <xades:MimeType>{mime}</xades:MimeType>
          </xades:DataObjectFormat>{formats}
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
      {unsigned}
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
"##
        )
    }
}

/// An enveloped-signature reference to the whole document.
pub(crate) fn enveloped_reference(id: &str, algorithms: Algorithms) -> String {
    let digest = algorithms.digest;
    format!(
        r#"<ds:Reference Id="{id}-data" URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="{ENVELOPED}"/>
        <ds:Transform Algorithm="{EXC}"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="{digest}"/>
      <ds:DigestValue/>
    </ds:Reference>"#
    )
}

/// A canonicalized reference to `uri` in the same document.
pub(crate) fn target_reference(id: &str, uri: &str, algorithms: Algorithms) -> String {
    let digest = algorithms.digest;
    format!(
        r#"<ds:Reference Id="{id}-data" URI="{uri}">
      <ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms>
      <ds:DigestMethod Algorithm="{digest}"/>
      <ds:DigestValue/>
    </ds:Reference>"#
    )
}

/// A reference to the caller-supplied external resource `uri`.
pub(crate) fn detached_reference(id: &str, uri: &str, algorithms: Algorithms) -> String {
    let digest = algorithms.digest;
    format!(
        r#"<ds:Reference Id="{id}-data" URI="{uri}">
      <ds:DigestMethod Algorithm="{digest}"/>
      <ds:DigestValue/>
    </ds:Reference>"#
    )
}

/// A plain XML signature over the element with ID `element`.
pub(crate) fn plain_signature(
    id: &str,
    element: &str,
    attributes: &str,
    algorithms: Algorithms,
) -> String {
    let (digest, signature) = (algorithms.digest, algorithms.signature);
    format!(
        r##"<ds:Signature xmlns:ds="{DS}" Id="{id}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{EXC}"/>
                <ds:SignatureMethod Algorithm="{signature}"/>
                <ds:Reference {attributes} URI="#{element}">
                  <ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms>
                  <ds:DigestMethod Algorithm="{digest}"/>
                  <ds:DigestValue/>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue/>
              <ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>
            </ds:Signature>"##
    )
}

/// A plain countersignature over the parent's complete `SignatureValue`
/// element (EN 319 132-1 §5.2.7.2).
pub(crate) fn counter_signature(id: &str, element: &str, algorithms: Algorithms) -> String {
    let counter = plain_signature(
        id,
        element,
        r#"Type="http://uri.etsi.org/01903#CountersignedSignature""#,
        algorithms,
    );
    format!(
        r"<xades:UnsignedProperties>
        <xades:UnsignedSignatureProperties>
          <xades:CounterSignature>
            {counter}
          </xades:CounterSignature>
        </xades:UnsignedSignatureProperties>
      </xades:UnsignedProperties>"
    )
}

/// The certificate digests the templates reference, base64-encoded.
pub(crate) struct Digests {
    pub(crate) signer_sha256: String,
    signer_sha384: String,
    root_sha256: String,
    signer_md5: String,
}

/// One fixture run: the native signer, the scratch directory and the output.
pub(crate) struct Generator {
    pub(crate) xmlsec: OsString,
    pub(crate) work: PathBuf,
    pub(crate) output: PathBuf,
    /// Repeated payload elements of the level fixtures, for size measurements.
    pub(crate) units: usize,
}

/// Fails unless `command` succeeds; its diagnostics stay on stderr.
fn succeed(mut command: Command, what: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("{what}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed: {status}"))
    }
}

impl Generator {
    pub(crate) fn openssl(&self, args: &[&str]) -> Result<(), String> {
        let mut command = Command::new("openssl");
        command
            .args(args)
            .current_dir(&self.work)
            .stderr(Stdio::null());
        succeed(command, &format!("openssl {}", args[0]))
    }

    /// The test root, intermediate and signer certificates and keys.
    fn issue(&self) -> Result<(), String> {
        let validity = ["-not_before", NOT_BEFORE, "-not_after", NOT_AFTER];
        let mut root = vec![
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out",
            "root.pem",
        ];
        root.extend(validity);
        root.extend([
            "-subj",
            "/CN=xml-sec XAdES Test Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        self.openssl(&root)?;
        for (name, issuer, subject, extensions) in [
            (
                "intermediate",
                "root",
                "/CN=xml-sec XAdES Test Intermediate",
                "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
            ),
            (
                "signer",
                "intermediate",
                "/CN=xml-sec XAdES Test Signer",
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
            ),
        ] {
            let (key, request, extension_file) = (
                format!("{name}.key"),
                format!("{name}.csr"),
                format!("{name}.ext"),
            );
            self.openssl(&[
                "req", "-newkey", "rsa:2048", "-nodes", "-keyout", &key, "-out", &request, "-subj",
                subject,
            ])?;
            write(&self.work.join(&extension_file), extensions)?;
            let (ca, ca_key, certificate) = (
                format!("{issuer}.pem"),
                format!("{issuer}.key"),
                format!("{name}.pem"),
            );
            let mut sign = vec![
                "x509",
                "-req",
                "-in",
                &request,
                "-CA",
                &ca,
                "-CAkey",
                &ca_key,
                "-out",
                &certificate,
            ];
            sign.extend(validity);
            sign.extend(["-extfile", &extension_file]);
            self.openssl(&sign)?;
        }
        Ok(())
    }

    /// The DER encoding of `name.pem`.
    pub(crate) fn der(&self, name: &str) -> Result<Vec<u8>, String> {
        let output = Command::new("openssl")
            .args(["x509", "-in", &format!("{name}.pem"), "-outform", "DER"])
            .current_dir(&self.work)
            .output()
            .map_err(|error| format!("openssl x509: {error}"))?;
        if !output.status.success() {
            return Err(format!("openssl x509 {name} failed"));
        }
        Ok(output.stdout)
    }

    /// MD5 of `data`: a deliberately weak digest no product dependency offers here.
    fn md5(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut child = Command::new("openssl")
            .args(["dgst", "-md5", "-binary"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| format!("openssl dgst: {error}"))?;
        // The certificate is a few hundred bytes, far below a pipe's buffer.
        std::io::Write::write_all(&mut child.stdin.take().ok_or("openssl stdin")?, data)
            .map_err(|error| format!("openssl dgst: {error}"))?;
        let output = child
            .wait_with_output()
            .map_err(|error| format!("openssl dgst: {error}"))?;
        if !output.status.success() {
            return Err("openssl dgst -md5 failed".into());
        }
        Ok(output.stdout)
    }

    pub(crate) fn digests(&self) -> Result<Digests, String> {
        use sha2::Digest as _;
        let signer = self.der("signer")?;
        Ok(Digests {
            signer_sha256: STANDARD.encode(sha2::Sha256::digest(&signer)),
            signer_sha384: STANDARD.encode(sha2::Sha384::digest(&signer)),
            root_sha256: STANDARD.encode(sha2::Sha256::digest(self.der("root")?)),
            signer_md5: STANDARD.encode(Self::md5(&signer)?),
        })
    }

    /// Signs the node with ID `node` of `input` into `result` with xmlsec1.
    pub(crate) fn sign(
        &self,
        input: &str,
        result: &Path,
        node: &str,
        key: &str,
    ) -> Result<(), String> {
        let mut command = Command::new(&self.xmlsec);
        command
            .args(["--sign", "--lax-key-search", "--privkey-pem", key])
            .args(["--id-attr:Id", &format!("{DS}:Signature")])
            .args(["--id-attr:Id", &format!("{DS}:Object")])
            .args(["--id-attr:Id", &format!("{DS}:SignatureValue")])
            .args(["--id-attr:Id", &format!("{SP}:SignedProperties")])
            .args(["--id-attr:Id", "Data", "--node-id", node, "--output"])
            .arg(result)
            .arg(input)
            .current_dir(&self.work);
        succeed(command, &format!("signing {input}"))
    }

    /// Writes `template` and signs it as `name.xml` in the output.
    fn signed(&self, name: &str, template: &str, node: &str, key: &str) -> Result<(), String> {
        let source = format!("{name}.template.xml");
        write(&self.work.join(&source), template)?;
        self.sign(&source, &self.output.join(format!("{name}.xml")), node, key)
    }
}

const KEY: &str = "signer.key,signer.pem,intermediate.pem";

/// The conforming B-B signature `sig` the variants change one part of: an
/// enveloped reference, the signer's SHA-256 certificate digest and a typed
/// `SignedProperties` reference.
pub(crate) fn baseline<'a>(
    digests: &'a Digests,
    reference_type: &'a str,
    algorithms: Algorithms,
) -> Signature<'a> {
    Signature {
        id: "sig",
        properties: "sp",
        data_reference: enveloped_reference("sig", algorithms),
        mime: "text/xml",
        time: TIME,
        method: SHA256,
        value: &digests.signer_sha256,
        cert_attributes: "",
        target: "#sig",
        reference_type,
        objects: String::new(),
        formats: String::new(),
        x509: "<ds:X509Certificate/>",
        unsigned: String::new(),
    }
}

/// `signature` enveloped in a document holding one `Data` with `payload`.
pub(crate) fn document(payload: &str, signature: &Signature<'_>, algorithms: Algorithms) -> String {
    format!(
        "<Document><Data Id=\"payload\">{payload}</Data>\n{}</Document>\n",
        signature.render(algorithms)
    )
}

/// The enveloped variants: a baseline and the adversarial changes of one part.
fn enveloped(generator: &Generator, digests: &Digests, typed: &str) -> Result<(), String> {
    let payload = "Enveloped baseline payload";
    let base = || baseline(digests, typed, RSA_SHA256_PROFILE);
    // Reference/@Type and QualifyingProperties/@Target are xs:anyURI, whose
    // whiteSpace facet is collapse (XSD 1.0 §4.3.6): edge whitespace is legal.
    let padded = format!(r#"Type=" {SIGNED_PROPERTIES}  ""#);
    let variants = [
        ("enveloped", base()),
        (
            "signing-time-without-zone",
            Signature {
                time: "2026-10-18T12:00:00",
                ..base()
            },
        ),
        (
            "certificate-digest-mismatch",
            Signature {
                value: &digests.root_sha256,
                ..base()
            },
        ),
        (
            "certificate-digest-md5",
            Signature {
                method: MD5,
                value: &digests.signer_md5,
                ..base()
            },
        ),
        (
            "certificate-uri",
            Signature {
                cert_attributes: r#" URI="https://example.invalid/signer.cer""#,
                ..base()
            },
        ),
        (
            "wrong-target",
            Signature {
                target: "#payload",
                ..base()
            },
        ),
        (
            "untyped-signed-properties",
            Signature {
                reference_type: "",
                ..base()
            },
        ),
        (
            "padded-uris",
            Signature {
                target: "  #sig ",
                reference_type: &padded,
                ..base()
            },
        ),
    ];
    for (name, signature) in variants {
        generator.signed(
            name,
            &document(payload, &signature, RSA_SHA256_PROFILE),
            "sig",
            KEY,
        )?;
    }
    // SHA-384 throughout: no digest in the document uses SHA-256, which
    // certificate path identities are computed with.
    let sha384 = Signature {
        method: SHA384,
        value: &digests.signer_sha384,
        ..baseline(digests, typed, RSA_SHA384_PROFILE)
    };
    generator.signed(
        "sha384",
        &document(payload, &sha384, RSA_SHA384_PROFILE),
        "sig",
        KEY,
    )?;
    // The signing certificate is identified only by issuer and serial number;
    // B-B requires the certificate itself in KeyInfo (EN 319 132-1 §6.3(a)).
    let issuer_serial = Signature {
        x509: "<ds:X509IssuerSerial/>",
        ..base()
    };
    generator.signed(
        "issuer-serial-only",
        &document(payload, &issuer_serial, RSA_SHA256_PROFILE),
        "sig",
        "signer.key,signer.pem",
    )
}

/// Signed in two passes: the inner signature first, then `outer` over it.
fn twice(
    generator: &Generator,
    name: &str,
    template: &str,
    inner: (&str, &str),
    outer: &str,
) -> Result<(), String> {
    let (intermediate, node) = inner;
    let source = format!("{name}.template.xml");
    write(&generator.work.join(&source), template)?;
    generator.sign(&source, &generator.work.join(intermediate), node, KEY)?;
    generator.sign(
        intermediate,
        &generator.output.join(format!("{name}.xml")),
        outer,
        KEY,
    )
}

/// Countersigned, enveloping, nested, detached and parallel signatures.
fn structures(generator: &Generator, digests: &Digests, typed: &str) -> Result<(), String> {
    let profile = RSA_SHA256_PROFILE;
    let base = || baseline(digests, typed, profile);
    // The parent is signed first; the enveloped countersignature then covers
    // the parent's final SignatureValue.
    let countersigned = Signature {
        unsigned: counter_signature("counter", "sig-value", profile),
        ..base()
    };
    let template = document("Countersigned baseline payload", &countersigned, profile);
    twice(
        generator,
        "countersigned",
        &template,
        ("countersigned.parent.xml", "sig"),
        "counter",
    )?;
    // Enveloping: the payload is an Object inside the Signature.
    let enveloping = Signature {
        data_reference: target_reference("sig", "#object", profile),
        mime: "text/plain",
        objects: r#"<ds:Object Id="object">Enveloping baseline payload</ds:Object>"#.to_owned(),
        ..base()
    };
    generator.signed("enveloping", &enveloping.render(profile), "sig", KEY)?;
    // Nested: the enveloped payload inside the root Signature carries its own
    // independent signature, which is no countersignature of the root.
    let nested = Signature {
        data_reference: target_reference("sig", "#object", profile),
        objects: format!(
            r#"<ds:Object Id="object"><Data Id="inner-data">Inner payload</Data>{}</ds:Object>"#,
            plain_signature("inner", "inner-data", "", profile)
        ),
        ..base()
    };
    twice(
        generator,
        "nested",
        &nested.render(profile),
        ("nested.inner.xml", "inner"),
        "sig",
    )?;
    // Detached: the payload is a caller-supplied external resource.
    write(
        &generator.work.join("detached.txt"),
        "Detached baseline payload\n",
    )?;
    write(
        &generator.output.join("detached.txt"),
        "Detached baseline payload\n",
    )?;
    let detached = Signature {
        data_reference: detached_reference("sig", "detached.txt", profile),
        mime: "text/plain",
        ..base()
    };
    generator.signed(
        "detached",
        &format!("<Document>\n{}</Document>\n", detached.render(profile)),
        "sig",
        KEY,
    )?;
    // Parallel: two independent signatures over distinct payloads.
    let parallel =
        |id: &'static str, properties: &'static str, uri: &str, target: &'static str| Signature {
            id,
            properties,
            data_reference: target_reference(id, uri, profile),
            target,
            ..base()
        };
    let template = format!(
        "<Document><Data Id=\"first\">First payload</Data><Data Id=\"second\">Second payload</Data>\n{}{}</Document>\n",
        parallel("first-sig", "first-sp", "#first", "#first-sig").render(profile),
        parallel("second-sig", "second-sp", "#second", "#second-sig").render(profile)
    );
    twice(
        generator,
        "parallel",
        &template,
        ("parallel.first.xml", "first-sig"),
        "second-sig",
    )
}

/// Issues the test chain and writes every signed fixture and certificate.
pub(crate) fn generate(generator: &Generator) -> Result<(), String> {
    for instant in [TIME_COMPACT, TEST_INSTANT] {
        if !(NOT_BEFORE..NOT_AFTER).contains(&instant) {
            return Err(format!("certificate validity must contain {instant}"));
        }
    }
    for directory in [&generator.output, &generator.work] {
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
    }
    generator.issue()?;
    let digests = generator.digests()?;
    let typed = format!(r#"Type="{SIGNED_PROPERTIES}""#);
    enveloped(generator, &digests, &typed)?;
    structures(generator, &digests, &typed)?;
    for certificate in ["root", "intermediate", "signer"] {
        write(
            &generator.output.join(format!("{certificate}.der")),
            generator.der(certificate)?,
        )?;
    }
    Ok(())
}

pub(crate) fn run(corpus: &super::Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let usage = "usage: xades fixtures [--levels] [--units N] [--output DIR] [--work DIR]";
    let mut output = corpus.root.join("crates/xml-sec-xades/tests/fixtures");
    let mut work = None;
    let mut levels = false;
    let mut units = 0;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--levels" {
            levels = true;
            continue;
        }
        if arg == "--units" {
            units = args
                .next()
                .and_then(|value| value.parse().ok())
                .ok_or(usage)?;
            continue;
        }
        let value = super::absolute(args.next().ok_or(usage)?)?;
        match arg.as_str() {
            "--output" => output = value,
            "--work" => work = Some(value),
            _ => return Err(usage.into()),
        }
    }
    // Without --work the keys and templates are removed with the scratch directory.
    let scratch = tempfile::tempdir().map_err(|error| error.to_string())?;
    let work = work.unwrap_or_else(|| scratch.path().to_owned());
    let generator = Generator {
        xmlsec: corpus.xmlsec.clone(),
        work,
        output,
        units,
    };
    if levels {
        return Ok(super::levels::generate(&generator)?);
    }
    Ok(generate(&generator)?)
}
