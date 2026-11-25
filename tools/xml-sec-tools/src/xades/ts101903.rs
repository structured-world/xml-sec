//! `xades fixtures --ts101903`: signatures whose qualifying properties use ETSI
//! TS 101 903 V1.2.2, over their own root, intermediate and signer path.
//! OpenSSL issues the path; xmlsec1 computes every digest and signature value.
//! <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.02.02_60/ts_101903v010202p.pdf>

use super::fixtures::{Generator, RSA_SHA256_PROFILE, enveloped_reference};
use super::{DS, EXC, write};
use std::process::Command;
use structured_base64::STANDARD;

#[cfg(test)]
mod tests;

/// The V1.2.2 namespace (§5) and its `SignedProperties` reference type (§6.3.1).
const XADES_122: &str = "http://uri.etsi.org/01903/v1.2.2#";
const SIGNED_PROPERTIES_122: &str = "http://uri.etsi.org/01903/v1.2.2#SignedProperties";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const TIME: &str = "2026-10-18T12:00:00Z";
const KEY: &str = "signer.key,signer.pem,intermediate.pem";

/// A V1.2.2 BES (§4.4.1) template: the signer identified by `signing_certificate`
/// (a V1 `SigningCertificate`, or empty), with `key_info_reference` added to
/// `SignedInfo` when the signature protects its `KeyInfo` instead.
fn template(signing_certificate: &str, key_info_reference: &str) -> String {
    let data = enveloped_reference("sig", RSA_SHA256_PROFILE);
    format!(
        r##"<Document><Data Id="payload">TS 101 903 V1.2.2 payload</Data>
<ds:Signature xmlns:ds="{DS}" Id="sig">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="{EXC}"/>
    <ds:SignatureMethod Algorithm="{RSA_SHA256}"/>
    {data}
    <ds:Reference Type="{SIGNED_PROPERTIES_122}" URI="#sp">
      <ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms>
      <ds:DigestMethod Algorithm="{SHA256}"/>
      <ds:DigestValue/>
    </ds:Reference>{key_info_reference}
  </ds:SignedInfo>
  <ds:SignatureValue Id="sig-value"/>
  <ds:KeyInfo Id="key-info"><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="{XADES_122}" Target="#sig">
      <xades:SignedProperties Id="sp">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>{TIME}</xades:SigningTime>{signing_certificate}
          <xades:SignaturePolicyIdentifier><xades:SignaturePolicyImplied/></xades:SignaturePolicyIdentifier>
        </xades:SignedSignatureProperties>
      </xades:SignedProperties>
      <xades:UnsignedProperties/>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature></Document>
"##
    )
}

/// A V1 `SigningCertificate` (V1.2.2 §7.2.2) naming a certificate by its
/// SHA-256 `digest` and the signer's issuer and serial number.
fn signing_certificate(digest: &str, issuer: &str, serial: &str) -> String {
    format!(
        r#"
          <xades:SigningCertificate>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="{SHA256}"/>
                <ds:DigestValue>{digest}</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerial>
                <ds:X509IssuerName>{issuer}</ds:X509IssuerName>
                <ds:X509SerialNumber>{serial}</ds:X509SerialNumber>
              </xades:IssuerSerial>
            </xades:Cert>
          </xades:SigningCertificate>"#
    )
}

/// The decimal form of the big-endian unsigned integer `bytes`.
fn decimal(bytes: &[u8]) -> String {
    let mut number = bytes.to_vec();
    let mut digits = Vec::new();
    while number.iter().any(|byte| *byte != 0) {
        let mut remainder = 0_u32;
        for byte in &mut number {
            let value = (remainder << 8) | u32::from(*byte);
            // value < 10 * 256, so the quotient fits a byte.
            *byte = u8::try_from(value / 10).expect("quotient below 256");
            remainder = value % 10;
        }
        digits.push(char::from(
            b'0' + u8::try_from(remainder).expect("a decimal digit"),
        ));
    }
    if digits.is_empty() {
        digits.push('0');
    }
    digits.iter().rev().collect()
}

/// The serial number of `name.pem` in decimal.
fn serial(generator: &Generator, name: &str) -> Result<String, String> {
    let output = Command::new(&generator.openssl)
        .args(["x509", "-in", &format!("{name}.pem"), "-noout", "-serial"])
        .current_dir(&generator.work)
        .output()
        .map_err(|error| format!("openssl x509 -serial: {error}"))?;
    let text = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let hex = text
        .trim()
        .strip_prefix("serial=")
        .ok_or_else(|| format!("unexpected serial output {text:?}"))?;
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| {
            hex.get(index..index + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("unexpected serial {hex:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(decimal(&bytes))
}

/// Issues the path and writes each V1.2.2 signature and certificate.
pub(crate) fn generate(generator: &Generator) -> Result<(), String> {
    use sha2::Digest as _;
    for directory in [&generator.output, &generator.work] {
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
    }
    generator.issue()?;
    let encode = |bytes: &[u8]| STANDARD.encode(bytes).map_err(|error| error.to_string());
    let signer = encode(&sha2::Sha256::digest(generator.der("signer")?))?;
    let root = encode(&sha2::Sha256::digest(generator.der("root")?))?;
    // The intermediate's subject is a single common name, so its RFC 4514
    // string form is unambiguous.
    let issuer = "CN=xml-sec XAdES Test Intermediate";
    let number = serial(generator, "signer")?;
    let key_info = r##"
    <ds:Reference URI="#key-info">
      <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue/>
    </ds:Reference>"##;
    for (name, template) in [
        (
            "signing-certificate",
            template(&signing_certificate(&signer, issuer, &number), ""),
        ),
        (
            "other-certificate",
            template(&signing_certificate(&root, issuer, &number), ""),
        ),
        ("key-info", template("", key_info)),
    ] {
        let source = format!("{name}.template.xml");
        write(&generator.work.join(&source), &template)?;
        generator.sign(
            &source,
            &generator.output.join(format!("{name}.xml")),
            "sig",
            KEY,
        )?;
    }
    for certificate in ["root", "intermediate", "signer"] {
        write(
            &generator.output.join(format!("{certificate}.der")),
            generator.der(certificate)?,
        )?;
    }
    Ok(())
}
