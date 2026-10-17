//! The tokenizer compatibility rewrite, without a character-vector copy.

use crate::c14n::scratch::{Scratch, Text, TextBuilder};
use crate::sxd_document::XmlChar as _;
use crate::xmldsig::types::TransformError;
use std::ops::Range;

pub(super) enum Normalized<'a, T> {
    Original(&'a str),
    Rewritten(T),
}

impl<T: Text> Normalized<'_, T> {
    pub(super) fn view(&self) -> Result<&str, TransformError> {
        match self {
            Self::Original(source) => Ok(source),
            Self::Rewritten(source) => Ok(source.view()?),
        }
    }
}

struct Cuts<'a> {
    source: &'a str,
    offset: usize,
    quote: Option<char>,
    name_start: Option<usize>,
}

impl<'a> Cuts<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            offset: 0,
            quote: None,
            name_start: None,
        }
    }
}

impl Iterator for Cuts<'_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.source.len() {
            let start = self.offset;
            let character = self.source[start..]
                .chars()
                .next()
                .expect("nonempty suffix");
            self.offset += character.len_utf8();
            if let Some(quote) = self.quote {
                if character == quote {
                    self.quote = None;
                }
                continue;
            }
            if matches!(character, '\'' | '"') {
                self.quote = Some(character);
                self.name_start = None;
            } else if super::is_xpath_whitespace(character) {
                while self.offset < self.source.len()
                    && matches!(
                        self.source.as_bytes()[self.offset],
                        b' ' | b'\t' | b'\r' | b'\n'
                    )
                {
                    self.offset += 1;
                }
                let name_start = self.name_start.take();
                if let Some(name_start) = name_start
                    && self.source.as_bytes().get(self.offset) == Some(&b'(')
                    && !matches!(
                        &self.source[name_start..start],
                        "and" | "or" | "div" | "mod"
                    )
                {
                    return Some(start..self.offset);
                }
            } else if character.is_name_char() {
                // XPath 1.0 §3.7 FunctionName uses QName/NCName. Share the
                // tokenizer's XML NameChar predicate, including combining marks.
                // https://www.w3.org/TR/1999/REC-xpath-19991116/#NT-FunctionName
                if self.name_start.is_none() {
                    self.name_start = Some(start);
                }
            } else {
                self.name_start = None;
            }
        }
        None
    }
}

pub(super) fn normalize<'a, S: Scratch>(
    source: &'a str,
    scratch: &S,
) -> Result<Normalized<'a, S::Text>, TransformError> {
    // XPath 1.0 §3.7 permits ExprWhitespace between tokens, including the
    // FunctionName and '(' in §3.2. Preserve literals and operator separation;
    // this only adapts SXD's token boundary.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    scratch.charge(source.len())?;
    let mut removed = 0_usize;
    for cut in Cuts::new(source) {
        removed += cut.len();
    }
    if removed == 0 {
        return Ok(Normalized::Original(source));
    }
    // The second scan is known now; admit it before allocating the actual join.
    // The storage strategy charges the copied bytes and UTF-8 validation itself.
    scratch.charge(source.len())?;
    let mut output = scratch.builder();
    output.reserve(source.len() - removed)?;
    let mut start = 0;
    for cut in Cuts::new(source) {
        output.append(&source[start..cut.start])?;
        start = cut.end;
    }
    output.append(&source[start..])?;
    Ok(Normalized::Rewritten(output.finish()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c14n::scratch::Accounted;
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

    #[test]
    fn function_spacing_recognizes_the_tokenizers_full_name_character_set() {
        // XML NameChar includes combining marks and extenders that are not
        // alphanumeric. A valid function name ending in one still admits S.
        for name in ["f\u{0301}", "f\u{203F}", "f\u{00B7}"] {
            let text = format!("{name} ()");
            let source =
                normalize(&text, &crate::c14n::scratch::Native).expect("valid XML name spelling");
            assert_eq!(
                source.view().expect("normalized source"),
                format!("{name}()")
            );
        }
    }

    #[test]
    fn unchanged_source_needs_no_query_capacity() {
        // Literals and word operators retain their exact bytes, without even a
        // temporary character array or output buffer under a zero-capacity query.
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        for text in ["contains('not (', 'x')", "2 div (3)", "true()", "β:fn()"] {
            let source = normalize(text, &Accounted(&memory)).expect("borrowed normalization");
            assert!(matches!(source, Normalized::Original(_)));
            assert_eq!(source.view().expect("validated source"), text);
        }
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn rewrite_pays_only_the_current_owner_and_preserves_unicode() {
        // QName spelling and literal contents must survive the same rewrite on
        // the paid and native paths; the new owner releases its actual capacity.
        let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 4096)));
        let source = normalize("β:fn \t('x (')", &Accounted(&memory)).expect("admitted rewrite");
        assert_eq!(source.view().expect("validated source"), "β:fn('x (')");
        assert!(memory.used() > 0);
        drop(source);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn rewrite_refuses_the_second_scan_before_capacity() {
        // With exactly one scan admitted, a needed rewrite refuses Work before
        // touching a zero-capacity allocator; that first failure must survive.
        let text = "true ()";
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, text.len())));
        let error = normalize(text, &Accounted(&memory))
            .err()
            .expect("second scan is unpaid");
        assert!(matches!(
            error,
            TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                MemoryError::WorkExceeded
            ))
        ));
        assert_eq!(memory.used(), 0);
    }
}
