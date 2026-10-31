//! `xades fixtures --levels`: B-T, B-LT and B-LTA signatures over a complete
//! test PKI. OpenSSL issues the certificates, CRLs, OCSP responses and RFC 3161
//! tokens, libxml2 computes every timestamp input and xmlsec1 the XML
//! signature; xml-sec takes no part. Unsigned properties are added after
//! signing, as a real signature gains them over its life.

use super::fixtures::{
    Digests, Generator, RSA_SHA256_PROFILE, Signature, TEST_INSTANT, baseline, counter_signature,
    detached_reference, document, target_reference,
};
use super::{DS, EXC, SP, write};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256, Sha512};
use std::process::{Command, Stdio};

const V141: &str = "http://uri.etsi.org/01903/v1.4.1#";
const KEY: &str = "signer.key,signer.pem,issuer.pem";

/// Name, issuing CA, subject and extensions of each end of the PKI.
const CERTIFICATES: [(&str, &str, &str, &str); 5] = [
    (
        "issuer",
        "root",
        "/CN=xml-sec XAdES Levels Issuer",
        "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    ),
    (
        "signer",
        "issuer",
        "/CN=xml-sec XAdES Levels Signer",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    ),
    (
        "tsa",
        "issuer",
        "/CN=xml-sec XAdES Levels TSA",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    ),
    (
        "responder",
        "issuer",
        "/CN=xml-sec XAdES Levels OCSP",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,OCSPSigning\nnoCheck=ignored\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    ),
    // Not issued by the signer's CA, so only local configuration authorizes it.
    (
        "outsider",
        "root",
        "/CN=xml-sec XAdES Levels Configured OCSP",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,OCSPSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    ),
];

const CA_CONFIG: &str = "[ca]\ndefault_ca=crl\n[crl]\ndatabase=NAME.index\ncrlnumber=NAME.crlnumber\ncertificate=NAME.pem\nprivate_key=NAME.key\ndefault_md=sha256\ndefault_crl_days=3650\ncrl_extensions=ext\n[ext]\nauthorityKeyIdentifier=keyid\n[delta]\nauthorityKeyIdentifier=keyid\n2.5.29.27=critical,DER:02:01:01\n";

const TSA_CONFIG: &str = "[tsa]\ndefault_tsa=levels\n[levels]\nserial=tsa.serial\ncrypto_device=builtin\nsigner_cert=tsa.pem\nsigner_key=tsa.key\nsigner_digest=sha256\ndefault_policy=1.3.6.1.4.1.13762.3\ndigests=sha256\naccuracy=secs:1\nclock_precision_digits=0\nordering=no\ntsa_name=no\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n";

/// Runs `xmllint --exc-c14n` over `xml`, in `generator`'s scratch directory.
fn canonical(generator: &Generator, xml: &str) -> Result<Vec<u8>, String> {
    let input = generator.work.join("c14n-input.xml");
    write(&input, xml)?;
    let output = Command::new("xmllint")
        .args(["--exc-c14n"])
        .arg(&input)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("xmllint: {error}"))?;
    if !output.status.success() {
        return Err("xmllint --exc-c14n failed".into());
    }
    Ok(output.stdout)
}

/// The element of `xml` starting at `open`, with the namespaces its ancestors
/// declared written on its own start tag: exclusive C14N renders only the ones
/// the element visibly uses, so unused declarations change nothing.
fn element(xml: &str, open: &str, close: &str) -> Result<String, String> {
    let start = xml
        .find(open)
        .ok_or_else(|| format!("{open} is not in the signature"))?;
    let end = xml[start..]
        .find(close)
        .ok_or_else(|| format!("{close} is not in the signature"))?
        + start
        + close.len();
    let tag = start + open.len();
    Ok(format!(
        r#"{} xmlns:ds="{DS}" xmlns:xades="{SP}" xmlns:xadesv141="{V141}"{}"#,
        &xml[start..tag],
        &xml[tag..end]
    ))
}

/// A signed document and its PKI in one scratch directory.
struct Levels<'a> {
    generator: &'a Generator,
}

impl Levels<'_> {
    fn write(&self, name: &str, data: impl AsRef<[u8]>) -> Result<(), String> {
        write(&self.generator.work.join(name), data)
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        super::read(&self.generator.work.join(name))
    }

    fn openssl(&self, args: &[&str]) -> Result<(), String> {
        self.generator.openssl(args)
    }

    fn issue(&self) -> Result<(), String> {
        let validity = [
            "-not_before",
            super::fixtures::NOT_BEFORE,
            "-not_after",
            super::fixtures::NOT_AFTER,
        ];
        let mut root = vec![
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out",
            "root.pem",
        ];
        root.extend(validity);
        root.extend([
            "-subj",
            "/CN=xml-sec XAdES Levels Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        self.openssl(&root)?;
        for (name, issuer, subject, extensions) in CERTIFICATES {
            let (key, request, file) = (
                format!("{name}.key"),
                format!("{name}.csr"),
                format!("{name}.ext"),
            );
            self.openssl(&[
                "req", "-newkey", "rsa:2048", "-nodes", "-keyout", &key, "-out", &request, "-subj",
                subject,
            ])?;
            self.write(&file, extensions)?;
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
            sign.extend(["-extfile", &file]);
            self.openssl(&sign)?;
        }
        Ok(())
    }

    /// The hexadecimal serial number of `subject`'s certificate.
    fn serial(&self, subject: &str) -> Result<String, String> {
        let certificate = format!("{subject}.pem");
        let serial = Command::new("openssl")
            .args(["x509", "-in", &certificate, "-noout", "-serial"])
            .current_dir(&self.generator.work)
            .output()
            .map_err(|error| format!("openssl x509: {error}"))?;
        let serial = String::from_utf8_lossy(&serial.stdout);
        Ok(serial.trim().trim_start_matches("serial=").to_owned())
    }

    /// An empty complete CRL of `issuer`, as DER.
    fn crl(&self, issuer: &str) -> Result<Vec<u8>, String> {
        self.crl_listing(issuer, "")
    }

    /// A complete CRL of `issuer` listing `subject` as revoked before the
    /// fixtures' test instant, as DER.
    fn crl_revoking(&self, issuer: &str, subject: &str) -> Result<Vec<u8>, String> {
        let serial = self.serial(subject)?;
        self.crl_listing(
            issuer,
            &format!("R\t450101000000Z\t261001000000Z\t{serial}\tunknown\t/CN={subject}\n"),
        )
    }

    fn crl_listing(&self, issuer: &str, index: &str) -> Result<Vec<u8>, String> {
        self.crl_numbered(issuer, index, "01\n", &[])
    }

    /// A delta over `issuer`'s complete CRL number 01 (RFC 5280 §5.2.4), naming
    /// `subject` as revoked when there is one.
    fn delta_crl(&self, issuer: &str, subject: Option<&str>) -> Result<Vec<u8>, String> {
        let index = match subject {
            Some(subject) => format!(
                "R\t450101000000Z\t261001000000Z\t{}\tunknown\t/CN={subject}\n",
                self.serial(subject)?
            ),
            None => String::new(),
        };
        self.crl_numbered(issuer, &index, "02\n", &["-crlexts", "delta"])
    }

    fn crl_numbered(
        &self,
        issuer: &str,
        index: &str,
        number: &str,
        extensions: &[&str],
    ) -> Result<Vec<u8>, String> {
        self.write(&format!("{issuer}.index"), index)?;
        self.write(&format!("{issuer}.crlnumber"), number)?;
        let config = format!("{issuer}.cnf");
        self.write(&config, CA_CONFIG.replace("NAME", issuer))?;
        let (pem, der) = (format!("{issuer}.crl.pem"), format!("{issuer}.crl.der"));
        let mut generate = vec!["ca", "-gencrl", "-config", &config, "-out", &pem];
        generate.extend(extensions);
        self.openssl(&generate)?;
        self.openssl(&["crl", "-in", &pem, "-outform", "DER", "-out", &der])?;
        self.read(&der)
    }

    /// A delegated OCSP response for `subject`, as a whole DER `OCSPResponse`,
    /// naming its responder by key hash (RFC 6960 §4.2.1) when `by_key` is set.
    fn ocsp(&self, subject: &str, by_key: bool) -> Result<Vec<u8>, String> {
        self.ocsp_from("responder", subject, by_key)
    }

    /// As [`Self::ocsp`], signed by `responder`.
    fn ocsp_from(&self, responder: &str, subject: &str, by_key: bool) -> Result<Vec<u8>, String> {
        self.ocsp_response(responder, subject, by_key, &[])
    }

    /// As [`Self::ocsp_from`], with no certificates: RFC 6960 §4.2.1 lets a
    /// responder omit them.
    fn ocsp_uncertified(&self, responder: &str, subject: &str) -> Result<Vec<u8>, String> {
        self.ocsp_response(responder, subject, false, &["-resp_no_certs"])
    }

    fn ocsp_response(
        &self,
        responder: &str,
        subject: &str,
        by_key: bool,
        options: &[&str],
    ) -> Result<Vec<u8>, String> {
        let (signer, signer_key) = (format!("{responder}.pem"), format!("{responder}.key"));
        let certificate = format!("{subject}.pem");
        let serial = self.serial(subject)?;
        self.write(
            "responder.index",
            format!("V\t450101000000Z\t\t{serial}\tunknown\t/CN={subject}\n"),
        )?;
        self.write("responder.index.attr", "unique_subject = no\n")?;
        let (request, response) = (format!("{subject}.ocsq"), format!("{subject}.ocsp"));
        self.openssl(&[
            "ocsp",
            "-issuer",
            "issuer.pem",
            "-sha256",
            "-cert",
            &certificate,
            "-no_nonce",
            "-reqout",
            &request,
        ])?;
        let mut respond = vec![
            "ocsp",
            "-index",
            "responder.index",
            "-CA",
            "issuer.pem",
            "-rsigner",
            &signer,
            "-rkey",
            &signer_key,
            "-rmd",
            "sha256",
            "-reqin",
            &request,
            "-respout",
            &response,
            "-ndays",
            "3650",
        ];
        if by_key {
            respond.push("-resp_key_id");
        }
        respond.extend(options);
        self.openssl(&respond)?;
        self.read(&response)
    }

    /// An RFC 3161 token over `input`, signed by the test TSA.
    fn token(&self, input: &[u8]) -> Result<String, String> {
        self.token_under(input, TSA_CONFIG)
    }

    /// An RFC 3161 token over `input`, issued under this TSA configuration.
    fn token_under(&self, input: &[u8], config: &str) -> Result<String, String> {
        self.token_requested(input, config, &["-cert"])
    }

    /// As [`Self::token`], without the signing certificate: RFC 3161 §2.4.1
    /// includes it only when the request asks.
    fn token_uncertified(&self, input: &[u8]) -> Result<String, String> {
        self.token_requested(input, TSA_CONFIG, &[])
    }

    fn token_requested(
        &self,
        input: &[u8],
        config: &str,
        options: &[&str],
    ) -> Result<String, String> {
        self.write("tsa.input", input)?;
        self.write("tsa.serial", "01\n")?;
        self.write("tsa.cnf", config)?;
        let mut query = vec!["ts", "-query", "-data", "tsa.input", "-sha256"];
        query.extend(options);
        query.extend(["-no_nonce", "-out", "tsa.tsq"]);
        self.openssl(&query)?;
        self.openssl(&[
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-queryfile",
            "tsa.tsq",
            "-token_out",
            "-out",
            "tsa.der",
        ])?;
        Ok(STANDARD.encode(self.read("tsa.der")?))
    }
}

fn certificate_values(generator: &Generator, names: &[&str]) -> Result<String, String> {
    let mut values = String::new();
    for name in names {
        let der = generator.der(name)?;
        values.push_str("<xades:EncapsulatedX509Certificate>");
        values.push_str(&STANDARD.encode(der));
        values.push_str("</xades:EncapsulatedX509Certificate>");
    }
    Ok(format!(
        "<xades:CertificateValues>{values}</xades:CertificateValues>"
    ))
}

fn revocation_values(crls: &[&Vec<u8>], responses: &[&Vec<u8>]) -> String {
    let encapsulated = |list: &str, tag: &str, values: &[&Vec<u8>]| {
        if values.is_empty() {
            return String::new();
        }
        let (open, close) = (format!("<xades:{tag}>"), format!("</xades:{tag}>"));
        let mut text = format!("<xades:{list}>");
        for value in values {
            text.push_str(&open);
            text.push_str(&STANDARD.encode(value));
            text.push_str(&close);
        }
        text + &format!("</xades:{list}>")
    };
    format!(
        "<xades:RevocationValues>{}{}</xades:RevocationValues>",
        encapsulated("CRLValues", "EncapsulatedCRLValue", crls),
        encapsulated("OCSPValues", "EncapsulatedOCSPValue", responses),
    )
}

fn stamped(token: &str) -> String {
    format!(
        r#"<ds:CanonicalizationMethod Algorithm="{EXC}"/><xades:EncapsulatedTimeStamp>{token}</xades:EncapsulatedTimeStamp>"#
    )
}

/// `signed` with these unsigned signature properties added after any it has.
fn with_properties(signed: &str, properties: &str) -> String {
    if signed.contains("</xades:UnsignedSignatureProperties>") {
        return signed
            .replacen(
                "<xades:UnsignedProperties>",
                &format!(r#"<xades:UnsignedProperties xmlns:xadesv141="{V141}">"#),
                1,
            )
            .replacen(
                "</xades:UnsignedSignatureProperties>",
                &format!("{properties}</xades:UnsignedSignatureProperties>"),
                1,
            );
    }
    signed.replacen(
        "</xades:QualifyingProperties>",
        &format!(
            r#"<xades:UnsignedProperties xmlns:xadesv141="{V141}"><xades:UnsignedSignatureProperties>{properties}</xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties>"#
        ),
        1,
    )
}

/// EN 319 132-1 V1.3.1 §5.5.2.3: reference outputs, `SignedInfo`,
/// `SignatureValue`, `KeyInfo`, then every earlier unsigned property.
fn archive_input(generator: &Generator, signed: &str, earlier: &str) -> Result<Vec<u8>, String> {
    let signature = signed
        .find("<ds:Signature ")
        .ok_or("the signature is not enveloped")?;
    let close = "</ds:Signature>";
    let end = signed.rfind(close).ok_or("unterminated signature")? + close.len();
    let payload = format!("{}{}", &signed[..signature], &signed[end..]);
    let data = canonical(generator, &payload)?;
    archive_input_over(generator, data, signed, earlier)
}

/// [`archive_input`] over the given output of the data reference.
fn archive_input_over(
    generator: &Generator,
    mut input: Vec<u8>,
    signed: &str,
    earlier: &str,
) -> Result<Vec<u8>, String> {
    for (open, close) in [
        ("<xades:SignedProperties", "</xades:SignedProperties>"),
        ("<ds:SignedInfo", "</ds:SignedInfo>"),
        ("<ds:SignatureValue", "</ds:SignatureValue>"),
        ("<ds:KeyInfo", "</ds:KeyInfo>"),
    ] {
        input.extend(canonical(generator, &element(signed, open, close)?)?);
    }
    for (open, close) in [
        ("<xades:SignatureTimeStamp", "</xades:SignatureTimeStamp>"),
        ("<xades:CertificateValues", "</xades:CertificateValues>"),
        ("<xades:RevocationValues", "</xades:RevocationValues>"),
        (
            "<xadesv141:TimeStampValidationData",
            "</xadesv141:TimeStampValidationData>",
        ),
    ] {
        input.extend(canonical(generator, &element(earlier, open, close)?)?);
    }
    let (open, close) = (
        "<xadesv141:ArchiveTimeStamp",
        "</xadesv141:ArchiveTimeStamp>",
    );
    if earlier.contains(open) {
        input.extend(canonical(generator, &element(earlier, open, close)?)?);
    }
    Ok(input)
}

/// The `SignatureTimeStamp` property of the first signature in `signed`.
fn signature_stamp(levels: &Levels<'_>, signed: &str, id: &str) -> Result<String, String> {
    let value = element(signed, "<ds:SignatureValue", "</ds:SignatureValue>")?;
    let token = levels.token(&canonical(levels.generator, &value)?)?;
    Ok(format!(
        r#"<xades:SignatureTimeStamp Id="{id}">{}</xades:SignatureTimeStamp>"#,
        stamped(&token)
    ))
}

/// Everything the structural variants share.
struct Shared<'a> {
    levels: &'a Levels<'a>,
    digests: &'a Digests,
    typed: &'a str,
    /// The validation material that follows a signature's timestamp.
    tail: &'a str,
    directory: &'a std::path::Path,
}

impl Shared<'_> {
    fn base(&self) -> Signature<'_> {
        baseline(self.digests, self.typed, RSA_SHA256_PROFILE)
    }

    /// Signs `template`'s `nodes` in order and returns the document.
    fn signed(&self, name: &str, template: &str, nodes: &[&str]) -> Result<String, String> {
        let generator = self.levels.generator;
        let mut source = format!("{name}.template.xml");
        write(&generator.work.join(&source), template)?;
        for (step, node) in nodes.iter().enumerate() {
            let result = format!("{name}.{step}.xml");
            generator.sign(&source, &generator.work.join(&result), node, KEY)?;
            source = result;
        }
        super::xml::read(&generator.work.join(source))
    }

    fn long_term(&self, signed: &str) -> Result<String, String> {
        let stamp = signature_stamp(self.levels, signed, "ts")?;
        Ok(with_properties(signed, &format!("{stamp}{}", self.tail)))
    }

    /// B-LTA whose signed `Manifest` names a detached object, with the renewal
    /// EN 319 132-1 §5.5.3 defines under a digest other than the Manifest's.
    fn write_renewed(&self, payload: &str) -> Result<(), String> {
        let profile = RSA_SHA256_PROFILE;
        let generator = self.levels.generator;
        let reference = format!(
            r#"<ds:Reference URI="detached.txt" Id="detached-object"><ds:DigestMethod Algorithm="{}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference>"#,
            profile.digest,
            STANDARD.encode(Sha256::digest(payload))
        );
        let signature = Signature {
            data_reference: target_reference("sig", "#manifest", profile),
            objects: format!(
                r#"<ds:Object><ds:Manifest Id="manifest">{reference}</ds:Manifest></ds:Object>"#
            ),
            // EN 319 132-1 §6.3(k), note 8: a Manifest reference is a signed object.
            formats: r##"<xades:DataObjectFormat ObjectReference="#detached-object"><xades:MimeType>text/plain</xades:MimeType></xades:DataObjectFormat>"##.to_owned(),
            ..self.base()
        };
        let template = document("Manifest payload", &signature, profile);
        let signed = self.signed("renewed", &template, &["sig"])?;
        let material = format!(
            "{}{}",
            signature_stamp(self.levels, &signed, "ts")?,
            self.tail
        );
        let earlier = with_properties(&signed, &material);
        let manifest = element(&signed, "<ds:Manifest", "</ds:Manifest>")?;
        let mut input = archive_input_over(
            generator,
            canonical(generator, &manifest)?,
            &signed,
            &earlier,
        )?;
        // §5.5.2.3 step 6: every ds:Object but the qualifying properties' own.
        let object = element(&signed, "<ds:Object", "</ds:Object>")?;
        input.extend(canonical(generator, &object)?);
        let instruction = element(
            &signed,
            r#"<ds:Reference URI="detached.txt""#,
            "</ds:Reference>",
        )?;
        let renewal = format!(
            r#"<xadesv141:ArchiveTimeStamp Id="archive">{}</xadesv141:ArchiveTimeStamp><xadesv141:RenewedDigestsV2><ds:CanonicalizationMethod Algorithm="{EXC}"/><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/><xadesv141:RecomputedDigestValue><xadesv141:NewSDODigestValue>{}</xadesv141:NewSDODigestValue><xadesv141:OriginalRefDigest>{}</xadesv141:OriginalRefDigest></xadesv141:RecomputedDigestValue></xadesv141:RenewedDigestsV2>"#,
            stamped(&self.levels.token(&input)?),
            STANDARD.encode(Sha512::digest(payload)),
            STANDARD.encode(Sha512::digest(canonical(generator, &instruction)?)),
        );
        write(
            &self.directory.join("b-lta-renewed-digests.xml"),
            with_properties(&signed, &format!("{material}{renewal}")),
        )
    }

    /// The acceptance structures, each with its own real tokens.
    fn write_all(&self) -> Result<(), String> {
        let profile = RSA_SHA256_PROFILE;
        let countersigned = Signature {
            unsigned: counter_signature("counter", "sig-value", profile),
            ..self.base()
        };
        let template = document("Countersigned payload", &countersigned, profile);
        write(
            &self.directory.join("b-lt-countersigned.xml"),
            self.long_term(&self.signed("countersigned", &template, &["sig", "counter"])?)?,
        )?;
        let payload = "Detached levels payload\n";
        write(&self.levels.generator.work.join("detached.txt"), payload)?;
        write(&self.directory.join("detached.txt"), payload)?;
        self.write_renewed(payload)?;
        let detached = Signature {
            data_reference: detached_reference("sig", "detached.txt", profile),
            mime: "text/plain",
            ..self.base()
        };
        let template = format!("<Document>\n{}</Document>\n", detached.render(profile));
        write(
            &self.directory.join("b-lt-detached.xml"),
            self.long_term(&self.signed("detached", &template, &["sig"])?)?,
        )?;
        let parallel = |id, properties, uri: &str, target| Signature {
            id,
            properties,
            data_reference: target_reference(id, uri, profile),
            target,
            ..self.base()
        };
        let template = format!(
            "<Document><Data Id=\"first\">First payload</Data><Data Id=\"second\">Second payload</Data>\n{}{}</Document>\n",
            parallel("first-sig", "first-sp", "#first", "#first-sig").render(profile),
            parallel("second-sig", "second-sp", "#second", "#second-sig").render(profile)
        );
        let signed = self.signed("parallel", &template, &["first-sig", "second-sig"])?;
        let second = signed
            .match_indices("<ds:Signature ")
            .nth(1)
            .ok_or("the second signature is missing")?
            .0;
        let (first, rest) = signed.split_at(second);
        let first = with_properties(first, &signature_stamp(self.levels, first, "ts-first")?);
        let rest = with_properties(rest, &signature_stamp(self.levels, rest, "ts-second")?);
        write(
            &self.directory.join("b-t-parallel.xml"),
            format!("{first}{rest}"),
        )
    }
}

/// One fixture and the conclusion an independent validator must reach, given
/// only its root as a trust anchor and the document's own material.
const VERDICTS: [(&str, &str, &str); 8] = [
    // A B-T signature carries no status, which DSS's default policy requires.
    ("b-t.xml", "XAdES-BASELINE-T", "INDETERMINATE"),
    ("b-t-parallel.xml", "XAdES-BASELINE-T", "INDETERMINATE"),
    ("b-lt.xml", "XAdES-BASELINE-LT", "TOTAL_PASSED"),
    ("b-lt-detached.xml", "XAdES-BASELINE-LT", "TOTAL_PASSED"),
    (
        "b-lt-responder-by-key.xml",
        "XAdES-BASELINE-LT",
        "TOTAL_PASSED",
    ),
    (
        "b-lt-countersigned.xml",
        "XAdES-BASELINE-LT",
        "TOTAL_PASSED",
    ),
    ("b-lta.xml", "XAdES-BASELINE-LTA", "TOTAL_PASSED"),
    ("b-lta-renewed.xml", "XAdES-BASELINE-LTA", "TOTAL_PASSED"),
];

/// The EU DSS release whose own test signatures are read at run time, the one
/// `interop/xades/dss/pom.xml` builds. They stay outside the repository.
const DSS_RELEASE: &str = "6.5.1";

/// A signature DSS produced, the instant and level to validate it at, and what
/// the adapter must report. Every token here omits accuracy, so the probe states
/// it; the chains carry their own ends as test anchors.
const DSS_SIGNATURES: [(&str, &str, &str, &str); 7] = [
    (
        "xades-lta-valid.xml",
        "1628861300",
        "t",
        "Ok(Assessed(true))",
    ),
    // EN 319 132-1 §6.3(x): the last archive's TSA has no status in the document.
    (
        "xades-lta-valid.xml",
        "1628861300",
        "lta",
        "Ok(Status(NoSource))",
    ),
    // A token copied from elsewhere covers other bytes.
    ("xades-t-copied-sigtst.xml", "1701944000", "t", "Rejected"),
    ("xades-lta-copied-atst.xml", "1628861300", "t", "Rejected"),
    (
        "xades-two-sig-copied-tst.xml",
        "1701960000",
        "t",
        "Rejected",
    ),
    // EN 319 132-1 §5.1.3: an unmarked token is DER, and this SET OF is unsorted.
    ("xades-t-with-tsvd.xml", "1701100000", "t", "SetOrder"),
    // The RFC 5652 reading admits the same token; the corpus anchors then end
    // at its signer, which is this setting's limit and not a token fact.
    ("xades-t-with-tsvd.xml", "1701100000", "t cms", "AnchorOnly"),
];

/// Checks the adapter's report on every signature of `DSS_SIGNATURES`.
fn dss_signatures(corpus: &super::Corpus, results: &std::path::Path) -> Result<(), String> {
    let directory = results.join("dss-signatures");
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let mut failures = Vec::new();
    for (file, at, level, expected) in DSS_SIGNATURES {
        let target = directory.join(file);
        if !target.exists() {
            let url = format!(
                "https://raw.githubusercontent.com/esig/dss/{DSS_RELEASE}/dss-xades/src/test/resources/validation/{file}"
            );
            let fetch = super::line(&[
                &"curl",
                &"--fail",
                &"--silent",
                &"--show-error",
                &"--output",
                &target,
                &url,
            ]);
            corpus.require(&fetch, &directory.join(format!("{file}-fetch")))?;
        }
        let mut probe = super::line(&[
            &"cargo",
            &"run",
            &"-q",
            &"-p",
            &"xml-sec-xades",
            &"--example",
            &"level_probe",
            &"--",
            &target,
            &"-",
            &at,
        ]);
        // The level, then "1" of stated accuracy, then the profile if a row names one.
        let mut words = level.split(' ');
        probe.extend(words.next().map(Into::into));
        probe.push("1".into());
        probe.extend(words.map(Into::into));
        let log = format!("{file}-{}", level.replace(' ', "-"));
        let run = corpus.require(&probe, &directory.join(log))?;
        let report = String::from_utf8_lossy(&run.stdout);
        println!("{file} {level}: expected {expected}");
        if !report.contains(expected) {
            failures.push(format!("{file} {level}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("DSS signature outcome mismatch: {failures:?}"))
    }
}

/// `xades levels [--results DIR]`: EU DSS's own conclusion on every fixture.
pub(crate) fn run(corpus: &super::Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut results = corpus.root.join("target/xades-levels-results");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--results" => {
                results = super::absolute(args.next().ok_or("--results needs a directory")?)?;
            }
            _ => return Err("usage: xades levels [--results DIR]".into()),
        }
    }
    Ok(execute(corpus, &results)?)
}

/// Compares DSS's conclusion on every fixture with `VERDICTS`.
pub(crate) fn execute(corpus: &super::Corpus, results: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    super::dss::build(corpus, results)?;
    let classpath = super::dss::classpath(corpus)?;
    let fixtures = corpus
        .root
        .join("crates/xml-sec-xades/tests/fixtures/levels");
    let mut failures = Vec::new();
    for (file, format, indication) in VERDICTS {
        let mut probe = super::line(&[
            &"java",
            &"-cp",
            &classpath,
            &"LevelProbe",
            &fixtures.join(file),
            &fixtures.join("root.der"),
            &"1800000000",
            &results.join(file),
        ]);
        if file == "b-lt-detached.xml" {
            probe.push(fixtures.join("detached.txt").into());
        }
        let run = corpus.require(&probe, &results.join(format!("{file}-run")))?;
        let report = String::from_utf8_lossy(&run.stdout).into_owned();
        println!("{file}: {}", report.trim());
        if !report.contains(&format!("format={format} "))
            || !report.contains(&format!("indication={indication} "))
        {
            failures.push(file);
        }
    }
    if !failures.is_empty() {
        return Err(format!("DSS verdict mismatch: {failures:?}"));
    }
    dss_signatures(corpus, results)
}

/// The signed payload: a short text, or `units` elements for a sized document.
fn payload(units: usize) -> String {
    if units == 0 {
        return "Levels payload".to_owned();
    }
    let mut items = String::new();
    for unit in 0..units {
        std::fmt::Write::write_fmt(
            &mut items,
            format_args!(r#"<Item name="attribute-{unit}" kind="text">value-{unit}</Item>"#),
        )
        .expect("writing to a String cannot fail");
    }
    items
}

/// Writes the level fixtures and their anchor into `levels/` of the output.
pub(crate) fn generate(generator: &Generator) -> Result<(), String> {
    let directory = generator.output.join("levels");
    for path in [&directory, &generator.work] {
        std::fs::create_dir_all(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
    }
    if !(super::fixtures::NOT_BEFORE..super::fixtures::NOT_AFTER).contains(&TEST_INSTANT) {
        return Err("certificate validity must contain the test instant".into());
    }
    let levels = Levels { generator };
    levels.issue()?;
    let digests = generator.digests()?;
    let typed = format!(r#"Type="{}""#, super::fixtures::SIGNED_PROPERTIES);
    let signature = baseline(&digests, &typed, RSA_SHA256_PROFILE);
    let payload = payload(generator.units);
    let template = document(&payload, &signature, RSA_SHA256_PROFILE);
    write(&generator.work.join("levels.template.xml"), &template)?;
    let target = generator.work.join("levels.xml");
    generator.sign("levels.template.xml", &target, "sig", KEY)?;
    let signed = super::xml::read(&target)?;
    let signature_stamp = signature_stamp(&levels, &signed, "ts")?;
    write(
        &directory.join("b-t.xml"),
        with_properties(&signed, &signature_stamp),
    )?;
    write_unstated_accuracy(&levels, &signed, &directory)?;
    let (root_crl, issuer_crl) = (levels.crl("root")?, levels.crl("issuer")?);
    let response = levels.ocsp("signer", false)?;
    // EN 319 132-1 V1.3.1 §6.3(x) requires a timestamp's own material in
    // validation-data properties or in its token, not in ordinary values.
    write(
        &directory.join("b-lt-tsa-material-misplaced.xml"),
        with_properties(
            &signed,
            &format!(
                "{signature_stamp}{}{}",
                certificate_values(generator, &["issuer", "root", "tsa", "responder"])?,
                revocation_values(&[&root_crl, &issuer_crl], &[&response]),
            ),
        ),
    )?;
    let tail = format!(
        "{}{}<xadesv141:TimeStampValidationData>{}{}</xadesv141:TimeStampValidationData>",
        certificate_values(generator, &["issuer", "root", "responder"])?,
        revocation_values(&[&root_crl], &[&response]),
        certificate_values(generator, &["tsa", "issuer", "root"])?,
        revocation_values(&[&issuer_crl, &root_crl], &[]),
    );
    let material = format!("{signature_stamp}{tail}");
    let long_term = with_properties(&signed, &material);
    write(&directory.join("b-lt.xml"), &long_term)?;
    let by_key = levels.ocsp("signer", true)?;
    write(
        &directory.join("b-lt-responder-by-key.xml"),
        with_properties(
            &signed,
            &material.replace(
                &revocation_values(&[&root_crl], &[&response]),
                &revocation_values(&[&root_crl], &[&by_key]),
            ),
        ),
    )?;
    write_status_variants(
        &levels,
        &signed,
        &material,
        [&root_crl, &issuer_crl, &response],
        &directory,
    )?;
    Shared {
        levels: &levels,
        digests: &digests,
        typed: &typed,
        tail: &tail,
        directory: &directory,
    }
    .write_all()?;
    let revoked = levels.crl_revoking("issuer", "tsa")?;
    write(
        &directory.join("b-lt-tsa-revoked.xml"),
        with_properties(
            &signed,
            &material.replace(
                &revocation_values(&[&issuer_crl, &root_crl], &[]),
                &revocation_values(&[&issuer_crl, &revoked, &root_crl], &[]),
            ),
        ),
    )?;
    write_archival(&levels, &signed, &material, &directory)?;
    for name in ["root", "issuer", "outsider"] {
        write(&directory.join(format!("{name}.der")), generator.der(name)?)?;
    }
    Ok(())
}

/// B-LT variants of `material`: a responder only local configuration authorizes,
/// conflicting complete and delta evidence, and a delta in the timestamp's data.
fn write_status_variants(
    levels: &Levels<'_>,
    signed: &str,
    material: &str,
    [root_crl, issuer_crl, response]: [&Vec<u8>; 3],
    directory: &std::path::Path,
) -> Result<(), String> {
    let generator = levels.generator;
    let good = revocation_values(&[root_crl], &[response]);
    let variant = |name: &str, material: String| {
        write(&directory.join(name), with_properties(signed, &material))
    };
    let configured = levels.ocsp_from("outsider", "signer", false)?;
    variant(
        "b-lt-configured-responder.xml",
        material
            .replace(&good, &revocation_values(&[root_crl], &[&configured]))
            .replace(
                &certificate_values(generator, &["issuer", "root", "responder"])?,
                &certificate_values(generator, &["issuer", "root"])?,
            ),
    )?;
    let uncertified = levels.ocsp_uncertified("outsider", "signer")?;
    let uncertified_tsa = levels.ocsp_uncertified("outsider", "tsa")?;
    variant(
        "b-lt-uncertified-responder.xml",
        material
            .replace(&good, &revocation_values(&[root_crl], &[&uncertified]))
            .replace(
                &revocation_values(&[issuer_crl, root_crl], &[]),
                &revocation_values(&[root_crl], &[&uncertified_tsa]),
            )
            .replace(
                &certificate_values(generator, &["issuer", "root", "responder"])?,
                &certificate_values(generator, &["issuer", "root"])?,
            ),
    )?;
    let value = element(signed, "<ds:SignatureValue", "</ds:SignatureValue>")?;
    let token = levels.token_uncertified(&canonical(generator, &value)?)?;
    let stamp = format!(
        r#"<xades:SignatureTimeStamp Id="ts">{}</xades:SignatureTimeStamp>"#,
        stamped(&token)
    );
    let start = material
        .find("<xades:CertificateValues>")
        .ok_or("no values")?;
    variant(
        "b-lt-uncertified-token.xml",
        format!("{stamp}{}", &material[start..]),
    )?;
    let revoked = levels.crl_revoking("issuer", "signer")?;
    variant(
        "b-lt-conflicting-status.xml",
        material.replace(
            &good,
            &revocation_values(&[root_crl, &revoked], &[response]),
        ),
    )?;
    let delta = levels.delta_crl("issuer", Some("signer"))?;
    variant(
        "b-lt-conflicting-delta.xml",
        material.replace(
            &good,
            &revocation_values(&[root_crl, issuer_crl, &delta], &[response]),
        ),
    )?;
    let quiet = levels.delta_crl("issuer", None)?;
    variant(
        "b-lt-tsa-delta.xml",
        material.replace(
            &revocation_values(&[issuer_crl, root_crl], &[]),
            &revocation_values(&[issuer_crl, &quiet, root_crl], &[]),
        ),
    )
}

/// RFC 3161 §2.4.2 makes accuracy optional; real TSAs often omit it.
fn write_unstated_accuracy(
    levels: &Levels<'_>,
    signed: &str,
    directory: &std::path::Path,
) -> Result<(), String> {
    let value = element(signed, "<ds:SignatureValue", "</ds:SignatureValue>")?;
    let unstated = levels.token_under(
        &canonical(levels.generator, &value)?,
        &TSA_CONFIG.replace("accuracy=secs:1\n", ""),
    )?;
    write(
        &directory.join("b-t-no-accuracy.xml"),
        with_properties(
            signed,
            &format!(
                r#"<xades:SignatureTimeStamp Id="ts">{}</xades:SignatureTimeStamp>"#,
                stamped(&unstated)
            ),
        ),
    )
}

/// B-LTA over `material`, then a later archive that covers the earlier one,
/// as renewal over time does.
fn write_archival(
    levels: &Levels<'_>,
    signed: &str,
    material: &str,
    directory: &std::path::Path,
) -> Result<(), String> {
    let generator = levels.generator;
    let long_term = with_properties(signed, material);
    let archive = levels.token(&archive_input(generator, signed, &long_term)?)?;
    let first_archive = format!(
        r#"{material}<xadesv141:ArchiveTimeStamp Id="archive">{}</xadesv141:ArchiveTimeStamp>"#,
        stamped(&archive)
    );
    let archival = with_properties(signed, &first_archive);
    write(&directory.join("b-lta.xml"), &archival)?;
    let renewal = levels.token(&archive_input(generator, signed, &archival)?)?;
    write(
        &directory.join("b-lta-renewed.xml"),
        with_properties(
            signed,
            &format!(
                r#"{first_archive}<xadesv141:ArchiveTimeStamp Id="renewal">{}</xadesv141:ArchiveTimeStamp>"#,
                stamped(&renewal)
            ),
        ),
    )
}
