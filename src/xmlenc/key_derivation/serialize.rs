//! Bounded serialization of the normalized KDF contract.

use std::io::{self, Write};

use crate::xml_input::lexical::Writer;
use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::{CONCAT, HKDF, KeyDerivationMethod, MORE_NS, PBKDF2, XMLDSIG_NS, XMLENC11_NS};
use crate::xmlenc::{XmlEncError, parse::validate_metadata_len};

struct CountingSink {
    length: usize,
}

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("KDF XML size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Fields {
    concat: [Option<String>; 5],
    salt: String,
    info: String,
    iterations: String,
    key_length: Option<String>,
}

pub(super) fn validate_metadata(
    method: &KeyDerivationMethod,
    maximum: usize,
) -> Result<(), XmlEncError> {
    validate_metadata_len(method.algorithm.len(), maximum)?;
    validate_metadata_len(method.digest.len(), maximum)?;
    let encoded_fields = if method.algorithm == HKDF {
        [method.salt.as_slice(), method.context.as_slice()]
    } else {
        [method.salt.as_slice(), &[]]
    };
    validate_metadata_len(method.context.len(), maximum)?;
    for bytes in encoded_fields {
        let encoded = bytes
            .len()
            .checked_add(2)
            .and_then(|n| (n / 3).checked_mul(4))
            .ok_or_else(|| super::invalid("KDF encoding size overflow"))?;
        validate_metadata_len(encoded, maximum)?;
    }
    for (_, bits) in method.concat_fields.iter().flatten() {
        let encoded = bits
            .div_ceil(8)
            .checked_add(1)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| super::invalid("ConcatKDF encoding size overflow"))?;
        validate_metadata_len(encoded, maximum)?;
    }
    Ok(())
}

pub(super) fn serialize(
    method: &KeyDerivationMethod,
    resources: &crate::policy::ResourcePolicy,
) -> Result<String, XmlEncError> {
    resources.validate()?;
    validate_metadata(method, resources.max_encryption_metadata_bytes)?;
    // All scratch encodings are bounded before allocation. The five Concat
    // fields partition one context, rather than copying it five times.
    let mut fields = Fields {
        concat: core::array::from_fn(|_| None),
        salt: STANDARD.encode(&method.salt),
        info: if method.algorithm == HKDF {
            STANDARD.encode(&method.context)
        } else {
            String::new()
        },
        iterations: method.iterations.to_string(),
        key_length: method.key_length.map(|length| length.to_string()),
    };
    for (index, boundary) in method.concat_fields.iter().enumerate() {
        let Some((start, bits)) = boundary else {
            continue;
        };
        let mut encoded = String::with_capacity((bits.div_ceil(8) + 1) * 2);
        push_hex(&mut encoded, ((8 - bits % 8) % 8) as u8);
        // XMLEnc 1.1 §5.4.1 encodes each field's padding count separately.
        // Repack from significant bits: the normalized arena is not octet aligned.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
        for offset in (0..*bits).step_by(8) {
            let mut byte = 0;
            for bit in 0..(*bits - offset).min(8) {
                let source = start + offset + bit;
                byte |= ((method.context[source / 8] >> (7 - source % 8)) & 1) << (7 - bit);
            }
            push_hex(&mut encoded, byte);
        }
        fields.concat[index] = Some(encoded);
    }
    let mut counter = Writer::new(CountingSink { length: 0 });
    write(method, &fields, &mut counter).map_err(serialize_error)?;
    let length = counter.into_inner().length;
    resources.validate_xml_document_len(length)?;
    let mut writer = Writer::new(Vec::with_capacity(length));
    write(method, &fields, &mut writer).map_err(serialize_error)?;
    String::from_utf8(writer.into_inner())
        .map_err(|error| XmlEncError::XmlSerialize(error.to_string()))
}

fn push_hex(output: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 15) as usize] as char);
}

fn serialize_error(error: io::Error) -> XmlEncError {
    XmlEncError::XmlSerialize(error.to_string())
}

fn text<W: Write>(writer: &mut Writer<W>, name: &str, value: &str) -> io::Result<()> {
    writer.start(name, [])?;
    writer.text(value)?;
    writer.end(name)
}

fn write<W: Write>(
    method: &KeyDerivationMethod,
    fields: &Fields,
    writer: &mut Writer<W>,
) -> io::Result<()> {
    writer.start(
        "xenc11:KeyDerivationMethod",
        [
            ("xmlns:xenc11", XMLENC11_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:more", MORE_NS),
            ("Algorithm", method.algorithm.as_str()),
        ],
    )?;
    match method.algorithm.as_str() {
        CONCAT => {
            let names = [
                "AlgorithmID",
                "PartyUInfo",
                "PartyVInfo",
                "SuppPubInfo",
                "SuppPrivInfo",
            ];
            writer.start(
                "xenc11:ConcatKDFParams",
                names
                    .iter()
                    .zip(&fields.concat)
                    .filter_map(|(name, value)| value.as_deref().map(|value| (*name, value))),
            )?;
            writer.empty("ds:DigestMethod", [("Algorithm", method.digest.as_str())])?;
            writer.end("xenc11:ConcatKDFParams")?;
        }
        PBKDF2 => {
            writer.start("xenc11:PBKDF2-params", [])?;
            writer.start("xenc11:Salt", [])?;
            text(writer, "xenc11:Specified", &fields.salt)?;
            writer.end("xenc11:Salt")?;
            text(writer, "xenc11:IterationCount", &fields.iterations)?;
            text(
                writer,
                "xenc11:KeyLength",
                fields
                    .key_length
                    .as_deref()
                    .ok_or_else(|| io::Error::other("missing PBKDF2 key width"))?,
            )?;
            writer.empty("xenc11:PRF", [("Algorithm", method.digest.as_str())])?;
            writer.end("xenc11:PBKDF2-params")?;
        }
        HKDF => {
            writer.start("more:HKDFParams", [])?;
            writer.empty("more:PRF", [("Algorithm", method.digest.as_str())])?;
            text(writer, "more:Salt", &fields.salt)?;
            text(writer, "more:Info", &fields.info)?;
            if let Some(length) = &fields.key_length {
                text(writer, "more:KeyLength", length)?;
            }
            writer.end("more:HKDFParams")?;
        }
        _ => return Err(io::Error::other("unsupported KDF serialization")),
    }
    writer.end("xenc11:KeyDerivationMethod")
}
