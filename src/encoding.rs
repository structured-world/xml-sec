//! XML byte-encoding detection shared by process and transform boundaries.

use crate::xml_input as xml_sec_xml_input;
use alloc::borrow::Cow;

/// Shared decoder errors, including unsupported encodings and decoded-size limits.
/// This replaces the former XML-only error variants rather than collapsing new
/// failure classes into misleading legacy variants.
pub use crate::xml_input_shared::Error as XmlEncodingError;

#[cfg(feature = "xmldsig")]
#[derive(Debug)]
pub(crate) enum DecodeError {
    Encoding(XmlEncodingError),
    Label(XmlEncodingError<structured_asn1::memory::OwnedText>),
    Execution(structured_asn1::memory::MemoryError),
}

#[cfg(feature = "xmldsig")]
impl From<XmlEncodingError> for DecodeError {
    fn from(error: XmlEncodingError) -> Self {
        Self::Encoding(error)
    }
}

#[cfg(feature = "xmldsig")]
impl From<structured_asn1::memory::MemoryError> for DecodeError {
    fn from(error: structured_asn1::memory::MemoryError) -> Self {
        Self::Execution(error)
    }
}

#[cfg(feature = "xmldsig")]
pub(crate) struct AccountedDecoder<'w, W: structured_asn1::memory::Work>(pub &'w W);

#[cfg(feature = "xmldsig")]
impl<W: structured_asn1::memory::Work> crate::xml_input_shared::DecodeStorage
    for AccountedDecoder<'_, W>
{
    type Text = structured_asn1::memory::OwnedText<W>;
    type Buffer = structured_asn1::memory::OwnedVec<u8, W>;
    type Error = DecodeError;

    fn label_error(&self, kind: crate::xml_input_shared::LabelError, label: &str) -> DecodeError {
        use crate::xml_input_shared::LabelError;
        let text = match structured_asn1::memory::OwnedText::try_from_str(label, self.0) {
            Ok(text) => text.into_owned(),
            Err(error) => return DecodeError::Execution(error),
        };
        DecodeError::Label(match kind {
            LabelError::Unsupported => XmlEncodingError::UnsupportedEncoding(text),
            LabelError::Forbidden => XmlEncodingError::ForbiddenEncoding(text),
            LabelError::Conflicting => XmlEncodingError::ConflictingEncoding(text),
        })
    }

    fn charge(&self, bytes: usize) -> Result<(), DecodeError> {
        self.0.charge_work(
            u64::try_from(bytes).map_err(|_| structured_asn1::memory::MemoryError::WorkExceeded)?,
        )?;
        Ok(())
    }
    fn buffer(&self) -> Self::Buffer {
        self.0.vector()
    }
    fn len(&self, buffer: &Self::Buffer) -> usize {
        buffer.len()
    }
    fn append(&self, buffer: &mut Self::Buffer, text: &str) -> Result<(), DecodeError> {
        buffer.try_extend_from_slice(text.as_bytes())?;
        Ok(())
    }
    fn finish(&self, buffer: Self::Buffer) -> Result<Self::Text, DecodeError> {
        use structured_asn1::memory::{OwnedText, TextErrorKind};
        OwnedText::from_utf8(buffer).map_err(|error| match error.kind() {
            TextErrorKind::Resource(error) => DecodeError::Execution(error),
            TextErrorKind::Utf8(_) => unreachable!("decoder appends only valid UTF-8 fragments"),
        })
    }
    fn replace(
        &self,
        text: Self::Text,
        range: core::ops::Range<usize>,
        replacement: &str,
    ) -> Result<Self::Text, DecodeError> {
        // The common grammar supplied character boundaries from this exact
        // retained text. Reuse its allocation, admitting moves before mutation.
        let tail = text.len() - range.end;
        let old_length = text.len();
        let new_length = old_length - range.len() + replacement.len();
        self.charge(tail)?;
        self.charge(replacement.len())?;
        self.charge(old_length.saturating_sub(new_length))?;
        let mut bytes = text.into_bytes();
        while bytes.len() < new_length {
            bytes.try_push(0)?;
        }
        bytes.copy_within(range.end..old_length, range.start + replacement.len());
        bytes[range.start..range.start + replacement.len()].copy_from_slice(replacement.as_bytes());
        while bytes.len() > new_length {
            bytes.pop();
        }
        self.finish(bytes)
    }
}

#[cfg(all(test, feature = "xmldsig"))]
fn decode_xml_octets_in<'a, W: structured_asn1::memory::Work>(
    bytes: &'a [u8],
    maximum: usize,
    work: &W,
) -> Result<crate::xml_input_shared::Decoded<'a, structured_asn1::memory::OwnedText<W>>, DecodeError>
{
    crate::xml_input_shared::decode_xml_in(bytes, maximum, |_, _| Ok(()), &AccountedDecoder(work))
}

/// Decode XML 1.0 octets into the backend-neutral Unicode parser contract.
///
/// UTF-8 input remains borrowed. Other declared XML encodings are decoded
/// strictly and their declaration is normalized to UTF-8 before parsing.
/// Callers must supply a size ceiling; an implicit unbounded compatibility path
/// would permit untrusted input to allocate without the operation's budget.
///
/// # Errors
/// Returns an encoding error for invalid or unsupported input, conflicting
/// declarations, allocation failure, or an exceeded decoded-byte ceiling.
pub fn decode_xml_octets(
    bytes: &[u8],
    maximum_decoded_bytes: usize,
) -> Result<Cow<'_, str>, XmlEncodingError> {
    xml_sec_xml_input::decode_xml_bounded(bytes, None, maximum_decoded_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_transcoding_retains_actual_capacity_until_text_is_dropped() {
        // Non-UTF-8 output must belong to the requesting operation, including
        // declaration rewriting; returning the native Cow loses that ownership.
        use structured_asn1::memory::{Memory, MemoryAccount};
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(4096, 100_000)));
        let input = b"<?xml version='1.0' encoding='ISO-8859-1'?><r>caf\xe9</r>";
        let decoded = decode_xml_octets_in(input, 4096, &memory).expect("Latin-1 output fits");
        assert_eq!(
            decoded.as_ref(),
            "<?xml version='1.0' encoding='UTF-8'?><r>café</r>"
        );
        assert!(memory.used() >= decoded.as_ref().len());
        drop(decoded);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_transcoding_refuses_capacity_but_borrows_valid_utf8() {
        // A zero-capacity caller can consume UTF-8 without copying, but must
        // refuse a real transcoding buffer, before exposing a partial document.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 100_000)));
        let utf8 = b"<r>text</r>";
        let decoded = decode_xml_octets_in(utf8, 4096, &memory).expect("UTF-8 stays borrowed");
        assert_eq!(decoded.as_ref().as_ptr(), utf8.as_ptr());
        let input = b"<?xml version='1.0' encoding='ISO-8859-1'?><r>\xe9</r>";
        assert!(matches!(
            decode_xml_octets_in(input, 4096, &memory),
            Err(DecodeError::Execution(MemoryError::LimitExceeded))
        ));
        assert_eq!(memory.used(), 0);
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_encoding_diagnostics_do_not_escape_the_capacity_account() {
        // An attacker-controlled invalid label is itself retained data. A
        // syntax failure must not allocate a native String outside the query.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let label = "Unregistered-".repeat(1024);
        let input = format!("<?xml version='1.0' encoding='{label}'?><r/>");
        let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 20)));
        assert!(matches!(
            decode_xml_octets_in(input.as_bytes(), 1 << 20, &denied),
            Err(DecodeError::Execution(MemoryError::LimitExceeded))
        ));
        assert_eq!(denied.used(), 0);
        let admitted = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let Err(error) = decode_xml_octets_in(input.as_bytes(), 1 << 20, &admitted) else {
            panic!("unsupported label must not decode");
        };
        assert!(
            matches!(&error, DecodeError::Label(XmlEncodingError::UnsupportedEncoding(text)) if text.as_str() == label)
        );
        assert!(admitted.used() >= label.len());
        drop(error);
        assert_eq!(admitted.used(), 0);
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_transcoding_preserves_local_query_refusal_before_decode() {
        // Aggregate room must not bypass a zero-work *current* query, even
        // when malformed input would otherwise allocate a diagnostic label.
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(4096, 100_000)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 0,
                ..Default::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).expect("empty query carrier");
        for input in [
            b"<r/>".as_slice(),
            b"<?xml version='1.0' encoding='not-supported'?><r/>",
        ] {
            assert!(matches!(
                decode_xml_octets_in(input, 4096, &reader.execution()),
                Err(DecodeError::Execution(MemoryError::WorkExceeded))
            ));
        }
        assert_eq!(memory.used(), 0);
        assert_eq!(memory.work_used(), 0);
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_transcoding_admits_exact_work_and_refuses_one_less() {
        // Derive the boundary from actual execution, not a hard-coded charge:
        // every refused partial output must relinquish its retained capacity.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let input = b"<?xml version='1.0' encoding='ISO-8859-1'?><r>\xe9</r>";
        let baseline = Memory::new(std::sync::Arc::new(MemoryAccount::new(4096, 100_000)));
        let output = decode_xml_octets_in(input, 4096, &baseline).expect("baseline fits");
        let used = baseline.work_used();
        let exact = Memory::new(std::sync::Arc::new(MemoryAccount::new(4096, used)));
        assert_eq!(
            decode_xml_octets_in(input, 4096, &exact)
                .expect("exact work fits")
                .as_ref(),
            output.as_ref()
        );
        assert_eq!(exact.used(), 0);
        let short = Memory::new(std::sync::Arc::new(MemoryAccount::new(4096, used - 1)));
        assert!(matches!(
            decode_xml_octets_in(input, 4096, &short),
            Err(DecodeError::Execution(MemoryError::WorkExceeded))
        ));
        assert_eq!(short.used(), 0);
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_declaration_rewrite_reuses_the_normalization_allocation() {
        // Both shrink and growth within existing room must move the suffix in
        // place, not allocate/copy a second complete decoded representation.
        use crate::xml_input_shared::DecodeStorage;
        use structured_asn1::memory::{Memory, MemoryAccount, OwnedText};
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(4096, 100_000)));
        let storage = AccountedDecoder(&memory);
        for label in ["ISO-8859-1", "x"] {
            let mut bytes = memory.vector();
            bytes.try_reserve_exact(128).expect("test capacity fits");
            bytes
                .try_extend_from_slice(b"before:")
                .expect("prefix fits");
            bytes
                .try_extend_from_slice(label.as_bytes())
                .expect("label fits");
            bytes.try_extend_from_slice(b":after").expect("suffix fits");
            let pointer = bytes.as_ptr();
            let capacity = bytes.capacity();
            let text = OwnedText::from_utf8(bytes).expect("ASCII test text");
            let rewritten = storage
                .replace(text, 7..7 + label.len(), "UTF-8")
                .expect("rewrite fits");
            assert_eq!(rewritten.as_str(), "before:UTF-8:after");
            assert_eq!(rewritten.as_str().as_ptr(), pointer);
            assert_eq!(memory.used(), capacity);
            drop(rewritten);
            assert_eq!(memory.used(), 0);
        }
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_transcoding_preserves_state_across_bounded_input_chunks() {
        // Split a UTF-16 surrogate pair at the input-chunk boundary. Decoder
        // state must carry it across without replacement or an early EOF.
        use structured_asn1::memory::{Memory, MemoryAccount};
        let prefix = "<?xml version='1.0' encoding='UTF-16'?><r>";
        let xml = format!("{prefix}{}😀</r>", "x".repeat(2047 - prefix.len()));
        for little_endian in [false, true] {
            let bytes = utf16_bytes(&xml, little_endian, true);
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
            let decoded =
                decode_xml_octets_in(&bytes, 1 << 20, &memory).expect("split pair is valid");
            assert_eq!(decoded.as_ref(), xml.replace("UTF-16", "UTF-8"));
            assert_eq!(
                decode_xml_octets(&bytes, 1 << 20).expect("native split pair is valid"),
                decoded.as_ref()
            );
        }
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_transcoding_keeps_stateful_escape_sequences_across_chunks() {
        // A boundary inside ISO-2022-JP's escape state must neither reset the
        // decoder nor mistake an input-chunk EOF for the complete entity EOF.
        use structured_asn1::memory::{Memory, MemoryAccount};
        let xml = format!(
            "<?xml version='1.0' encoding='ISO-2022-JP'?><r>{}</r>",
            "aあbい".repeat(4096)
        );
        let (bytes, _, malformed) = encoding_rs::ISO_2022_JP.encode(&xml);
        assert!(!malformed);
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let decoded = decode_xml_octets_in(&bytes, 1 << 20, &memory).expect("valid stateful XML");
        assert_eq!(decoded.as_ref(), xml.replace("ISO-2022-JP", "UTF-8"));
        assert_eq!(
            decode_xml_octets(&bytes, 1 << 20).expect("same native decoder"),
            decoded.as_ref()
        );
        drop(decoded);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    #[cfg(feature = "xmldsig")]
    fn scoped_transcoding_releases_partial_output_on_a_malformed_tail() {
        // A decoder that has already produced several output buffers must
        // preserve the strict byte error and release every retained byte.
        use structured_asn1::memory::{Memory, MemoryAccount};
        let xml = format!(
            "<?xml version='1.0' encoding='UTF-16'?><r>{}",
            "x".repeat(8192)
        );
        let mut bytes = utf16_bytes(&xml, true, true);
        bytes.extend_from_slice(&0xd800_u16.to_le_bytes());
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        assert!(matches!(
            decode_xml_octets_in(&bytes, 1 << 20, &memory),
            Err(DecodeError::Encoding(XmlEncodingError::InvalidBytes(
                "UTF-16LE"
            )))
        ));
        assert_eq!(memory.used(), 0);
    }

    fn utf16_bytes(xml: &str, little_endian: bool, bom: bool) -> Vec<u8> {
        let mut bytes = if bom {
            if little_endian {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            }
        } else {
            Vec::new()
        };
        bytes.extend(xml.encode_utf16().flat_map(|value| {
            if little_endian {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            }
        }));
        bytes
    }

    #[test]
    fn transcoding_normalizes_non_utf8_declarations() {
        for bytes in [
            utf16_bytes(
                "<?xml version=\"1.0\" encoding=\"UTF-16\"?><root/>",
                true,
                true,
            ),
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>".to_vec(),
        ] {
            let decoded =
                decode_xml_octets(&bytes, 1_024).expect("declared XML encoding must decode");
            assert!(decoded.contains("encoding=\"UTF-8\"") || decoded.contains("encoding='UTF-8'"));
        }
    }

    #[test]
    fn declared_single_byte_xml_is_transcoded_strictly() {
        // XML permits declared encodings beyond its mandatory UTF-8/UTF-16 baseline.
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
        let decoded = decode_xml_octets(latin1, 1_024).expect("declared Latin-1 XML must decode");
        assert!(decoded.contains("<root>café</root>"));
        assert!(decoded.contains("encoding=\"UTF-8\""));
    }

    #[test]
    fn byte_signatures_and_declarations_must_agree() {
        let conflicting = utf16_bytes(
            "<?xml version=\"1.0\" encoding=\"UTF-16BE\"?><root/>",
            true,
            true,
        );
        assert!(matches!(
            decode_xml_octets(&conflicting, 1_024),
            Err(XmlEncodingError::ConflictingEncoding(_))
        ));

        let matching_signature = utf16_bytes(
            "<?xml version=\"1.0\" encoding=\"UTF-16BE\"?><root/>",
            false,
            true,
        );
        assert!(decode_xml_octets(&matching_signature, 1_024).is_ok());

        let bomless_generic = utf16_bytes(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><root/>",
            true,
            false,
        );
        assert!(matches!(
            decode_xml_octets(&bomless_generic, 1_024),
            Err(XmlEncodingError::MissingUtf16ByteOrder)
        ));
    }

    #[test]
    fn utf8_is_borrowed_and_malformed_bytes_are_rejected() {
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>";
        assert!(matches!(
            decode_xml_octets(xml, xml.len()),
            Ok(Cow::Borrowed(_))
        ));
        assert!(decode_xml_octets(b"<root>\xff</root>", 1_024).is_err());
    }

    #[test]
    fn declaration_detection_ignores_other_processing_instructions() {
        for xml in [
            r#"<?xml-stylesheet encoding="ISO-8859-1"?><root/>"#,
            r#"<root data-encoding="ISO-8859-1"/>"#,
        ] {
            decode_xml_octets(xml.as_bytes(), 1_024)
                .expect("ordinary content does not select encoding");
        }
    }

    #[test]
    fn transcoding_stops_at_the_decoded_document_limit() {
        let bytes = utf16_bytes("<?xml version=\"1.0\"?><root>expanded</root>", true, true);
        assert!(matches!(
            decode_xml_octets(&bytes, 16),
            Err(XmlEncodingError::DecodedLimit { maximum: 16, .. })
        ));
    }
}
