//! Original `XPath` parameter text, borrowed unless XML text nodes require a join.

use alloc::{borrow::ToOwned, string::String};

use super::{TransformError, is_xpath_whitespace, transform_resource_limit};
use crate::c14n::scratch::{Text, TextBuilder};
use crate::xml::dom::Node;

pub(crate) enum Source<'a, T> {
    Borrowed(&'a str),
    Joined {
        text: T,
        range: core::ops::Range<usize>,
    },
}

impl<T: core::ops::Deref<Target = str>> AsRef<str> for Source<'_, T> {
    fn as_ref(&self) -> &str {
        match self {
            Self::Borrowed(text) => text,
            Self::Joined { text, range } => &text[range.clone()],
        }
    }
}

impl<'a, T> Source<'a, T> {
    pub(super) fn map_owned<U>(self, convert: impl FnOnce(T) -> U) -> Source<'a, U> {
        match self {
            Self::Borrowed(text) => Source::Borrowed(text),
            Self::Joined { text, range } => Source::Joined {
                text: convert(text),
                range,
            },
        }
    }
}

impl<T: Text> Source<'_, T> {
    pub(super) fn view(&self) -> Result<&str, TransformError> {
        Ok(match self {
            Self::Borrowed(text) => text,
            Self::Joined { text, range } => &text.view()?[range.clone()],
        })
    }
}

impl Source<'_, String> {
    pub(super) fn into_string(self) -> String {
        match self {
            Self::Borrowed(text) => text.to_owned(),
            Self::Joined { mut text, range } => {
                text.truncate(range.end);
                text.drain(..range.start);
                text
            }
        }
    }
}

pub(super) fn read<'a, S: super::parameters::ParseStorage<'a>>(
    node: Node<'a, 'a>,
    maximum: usize,
    scratch: &S,
) -> Result<Source<'a, S::Text>, TransformError> {
    scratch.charge(node.children().len())?;
    let mut first = None;
    let mut fragments = 0_usize;
    let mut bytes = 0_usize;
    for child in node.children() {
        if child.is_text() {
            let text = child.text().unwrap_or_default();
            bytes = bytes.checked_add(text.len()).ok_or_else(|| {
                transform_resource_limit(
                    crate::policy::resource_name::XPATH_EXPRESSION_BYTES,
                    maximum,
                    usize::MAX,
                )
            })?;
            if bytes > maximum {
                return Err(transform_resource_limit(
                    crate::policy::resource_name::XPATH_EXPRESSION_BYTES,
                    maximum,
                    bytes,
                ));
            }
            if first.is_none() {
                first = Some(text);
            }
            fragments += 1;
        } else if child.is_element() {
            return Err(
                scratch.xpath_error(format_args!("XPath expressions must contain text only"))
            );
        }
    }
    // XMLDSig 1.1 §6.6.3: the XPath string is the text-node content of
    // ds:XPath. Comments/processing instructions do not insert separators.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-XPath
    // Trimming is a separate traversal from copying. The buffer strategy pays
    // its actual copy, growth and UTF-8 validation; do not charge them twice.
    scratch.charge(bytes)?;
    if fragments <= 1 {
        return Ok(Source::Borrowed(
            first.unwrap_or_default().trim_matches(is_xpath_whitespace),
        ));
    }
    scratch.charge(node.children().len())?;
    let mut buffer = scratch.builder();
    buffer.reserve(bytes)?;
    for child in node.children() {
        if child.is_text() {
            buffer.append(child.text().unwrap_or_default())?;
        }
    }
    let text = buffer.finish()?;
    let raw = text.view()?;
    let suffix = raw.trim_start_matches(is_xpath_whitespace);
    let start = raw.len() - suffix.len();
    let end = start + suffix.trim_end_matches(is_xpath_whitespace).len();
    Ok(Source::Joined {
        text,
        range: start..end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c14n::scratch::{Accounted, Native};
    use crate::xml::dom::Document;
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

    #[test]
    fn single_fragment_borrows_the_original_parameter_with_zero_capacity() {
        // The parsed document owns this text already. A later query pays its
        // scan but cannot need a duplicate allocation just to read a parameter.
        let document = Document::parse("<XPath> \t//β\n </XPath>").expect("valid parameter XML");
        let node = document.root_element();
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1024)));
        let source =
            read(node, 1024, &Accounted(&memory)).expect("borrowed source needs no capacity");
        assert!(matches!(source, Source::Borrowed(_)));
        assert_eq!(source.view().expect("validated source"), "//β");
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn joined_fragments_retain_and_release_current_storage() {
        // XML comments and PIs split source nodes, not XPath tokens. The join
        // must preserve their exact adjacent text and release its actual owner.
        let document = Document::parse("<XPath> \t/<!--split-->/β<?p x?>\n </XPath>")
            .expect("valid split parameter XML");
        let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 4096)));
        let source = read(document.root_element(), 1024, &Accounted(&memory))
            .expect("admitted parameter join");
        assert!(matches!(source, Source::Joined { .. }));
        assert_eq!(source.view().expect("validated source"), "//β");
        assert!(memory.used() > 0);
        let native = read(document.root_element(), 1024, &Native).expect("native parameter join");
        assert_eq!(native.into_string(), "//β");
        drop(source);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn joined_parameter_capacity_refusal_preserves_the_resource_cause() {
        // The producer's native DOM must not fund current-query concatenation.
        let document =
            Document::parse("<XPath>/<!--split-->/β</XPath>").expect("valid parameter XML");
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        let error = read(document.root_element(), 1024, &Accounted(&memory))
            .err()
            .expect("joining disjoint text requires admitted storage");
        assert!(matches!(
            error,
            TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                MemoryError::LimitExceeded
            ))
        ));
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn parameter_refuses_work_before_join_capacity() {
        // With both allowances exhausted the first traversal is refused before
        // a join is allocated. Memory failure cannot disguise that work cause.
        let document =
            Document::parse("<XPath>/<!--split-->/β</XPath>").expect("valid parameter XML");
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let error = read(document.root_element(), 1024, &Accounted(&memory))
            .err()
            .expect("parameter traversal requires current work");
        assert!(matches!(
            error,
            TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                MemoryError::WorkExceeded
            ))
        ));
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn parameter_join_keeps_both_current_and_aggregate_work_ceilings() {
        // Identical sealed Execution-backed layouts must consume the aggregate
        // exactly once. Neither freezing the joined UTF-8 nor borrowing its view
        // may substitute the roomy aggregate for the current local ceiling.
        use structured_asn1::{Encoding, Limits, Parser};

        let document =
            Document::parse("<XPath> /<!--split-->/β </XPath>").expect("valid split parameter XML");
        let run = |maximum, aggregate| {
            let memory = Memory::new(Arc::new(MemoryAccount::new(1024, aggregate)));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: maximum,
                    ..Default::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 0).expect("empty query cursor");
            let work = reader.execution();
            let result =
                read(document.root_element(), 1024, &Accounted(&work)).and_then(|source| {
                    assert_eq!(source.view()?, "//β");
                    Ok(())
                });
            assert_eq!(memory.used(), 0);
            (result, memory.work_used())
        };
        let (result, needed) = run(4096, 4096);
        result.expect("ample current query");
        assert!(needed > 0);
        let (result, used) = run(needed as u64, needed);
        result.expect("exact local and aggregate query");
        assert_eq!(used, needed);
        for (local, aggregate) in [(0, 4096), (needed - 1, 4096), (4096, needed - 1)] {
            let (result, _) = run(local as u64, aggregate);
            assert!(matches!(
                result,
                Err(TransformError::C14n(
                    crate::c14n::C14nError::SharedExecution(MemoryError::WorkExceeded)
                ))
            ));
        }
    }
}
