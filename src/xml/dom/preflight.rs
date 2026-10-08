//! Shared lexical preflight and source-position sidecar for every DOM backend.

use crate::xml_input as xml_sec_xml_input;
use std::collections::HashMap;
use std::ops::Range;

use xml_sec_xml_input::lexical::{Event, Scanner};

use super::ParseError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SourceKind {
    Element,
    Text,
    CData,
    EntityRef,
    Comment,
    Pi,
}

struct SourceNode {
    kind: SourceKind,
    range: Range<usize>,
}

type DtdAttributeName<'a> = (Option<&'a str>, &'a str, Option<&'a str>, &'a str);

pub(super) struct LexicalPreflight<'input> {
    nodes: Vec<SourceNode>,
    attributes: HashMap<DtdAttributeName<'input>, crate::document::DtdAttributeType>,
    #[cfg(feature = "xml-backend-roxmltree")]
    doctype: Option<Range<usize>>,
}

impl<'input> LexicalPreflight<'input> {
    pub(super) fn scan(input: &'input str, allow_dtd: bool) -> Result<Self, ParseError> {
        let mut reader = Scanner::new(input);
        let mut nodes: Vec<SourceNode> = Vec::new();
        let mut elements = Vec::new();
        let mut attributes = HashMap::new();
        #[cfg(feature = "xml-backend-roxmltree")]
        let mut doctype = None;
        while let Some(event) = reader.next_event().map_err(|error| ParseError::Backend {
            backend: "xml-preflight",
            message: error.to_string(),
        })? {
            match event {
                Event::Start(element) => {
                    let depth = elements.len() + 1;
                    enforce_depth(depth)?;
                    let index = nodes.len();
                    nodes.push(SourceNode {
                        kind: SourceKind::Element,
                        range: element.range.clone(),
                    });
                    elements.push(index);
                }
                Event::Empty(element) => {
                    enforce_depth(elements.len() + 1)?;
                    nodes.push(SourceNode {
                        kind: SourceKind::Element,
                        range: element.range,
                    });
                }
                Event::End { range, .. } => {
                    if let Some(index) = elements.pop() {
                        nodes[index].range.end = range.end;
                    }
                }
                // Both supported DOMs omit whitespace outside the document
                // element, so it must not shift the semantic sidecar.
                Event::Text { range, .. } if !elements.is_empty() => {
                    push_text_position(&mut nodes, range);
                }
                Event::Text { .. } => {}
                Event::CData { range, .. } => nodes.push(SourceNode {
                    kind: SourceKind::CData,
                    range,
                }),
                Event::Reference { name, range } if is_builtin_or_character_reference(name) => {
                    push_text_position(&mut nodes, range);
                }
                Event::Reference { range, .. } => nodes.push(SourceNode {
                    kind: SourceKind::EntityRef,
                    range,
                }),
                Event::Comment { range, .. } => nodes.push(SourceNode {
                    kind: SourceKind::Comment,
                    range,
                }),
                Event::ProcessingInstruction { range, .. } => nodes.push(SourceNode {
                    kind: SourceKind::Pi,
                    range,
                }),
                Event::DocType { .. } if !allow_dtd => return Err(ParseError::DtdDetected),
                Event::DocType { range, .. } => {
                    crate::document::visit_dtd_attributes(
                        &input[range.clone()],
                        |element, attribute, kind| {
                            let (element_prefix, element_local) = split_name(element);
                            let (attribute_prefix, attribute_local) = split_name(attribute);
                            // XML 1.0 section 3.3: the first declaration is binding.
                            // https://www.w3.org/TR/2008/REC-xml-20081126/#attdecls
                            attributes
                                .entry((
                                    element_prefix,
                                    element_local,
                                    attribute_prefix,
                                    attribute_local,
                                ))
                                .or_insert(kind);
                        },
                    );
                    #[cfg(feature = "xml-backend-roxmltree")]
                    {
                        doctype = Some(range);
                    }
                }
                _ => {}
            }
            let actual = nodes.len();
            let maximum = crate::hard_limits::XML_SOURCE_POSITION_CEILING;
            if actual > maximum {
                return Err(ParseError::SourcePositionLimitReached { maximum, actual });
            }
        }
        Ok(Self {
            nodes,
            attributes,
            #[cfg(feature = "xml-backend-roxmltree")]
            doctype,
        })
    }

    pub(super) fn attribute_type(
        &self,
        element_prefix: Option<&str>,
        element_local: &str,
        attribute_prefix: Option<&str>,
        attribute_local: &str,
    ) -> Option<crate::document::DtdAttributeType> {
        self.attributes
            .get(&(
                element_prefix,
                element_local,
                attribute_prefix,
                attribute_local,
            ))
            .copied()
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn doctype_range(&self) -> Option<&Range<usize>> {
        self.doctype.as_ref()
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn folded_character_data_range(&self, start: usize) -> Option<(Range<usize>, bool)> {
        let first = self.nodes.partition_point(|node| node.range.start < start);
        let node = self.nodes.get(first)?;
        if node.range.start != start || !node.kind.is_character_data() {
            return None;
        }

        let mut range = node.range.clone();
        let mut actionable = node.kind != SourceKind::EntityRef;
        for node in &self.nodes[first + 1..] {
            if !node.kind.is_character_data() || node.range.start != range.end {
                break;
            }
            range.end = range.end.max(node.range.end);
            actionable &= node.kind != SourceKind::EntityRef;
        }
        Some((range, actionable))
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn positions(&self) -> PositionCursor<'_> {
        PositionCursor {
            positions: &self.nodes,
            next: 0,
        }
    }
}

fn split_name(name: &str) -> (Option<&str>, &str) {
    match name.split_once(':') {
        Some((prefix, local)) => (Some(prefix), local),
        None => (None, name),
    }
}

#[cfg(feature = "xml-backend-roxmltree")]
impl SourceKind {
    fn is_character_data(self) -> bool {
        matches!(self, Self::Text | Self::CData | Self::EntityRef)
    }
}

fn enforce_depth(actual: usize) -> Result<(), ParseError> {
    let maximum = crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING;
    if actual > maximum {
        Err(ParseError::DepthLimitReached { maximum, actual })
    } else {
        Ok(())
    }
}

fn push_text_position(nodes: &mut Vec<SourceNode>, range: Range<usize>) {
    if let Some(previous) = nodes.last_mut()
        && previous.kind == SourceKind::Text
        && previous.range.end == range.start
    {
        previous.range.end = range.end;
    } else {
        nodes.push(SourceNode {
            kind: SourceKind::Text,
            range,
        });
    }
}

fn is_builtin_or_character_reference(reference: &str) -> bool {
    reference.starts_with('#') || matches!(reference, "amp" | "lt" | "gt" | "apos" | "quot")
}

#[cfg(feature = "xml-backend-xmloxide")]
pub(super) struct PositionCursor<'a> {
    positions: &'a [SourceNode],
    next: usize,
}

#[cfg(feature = "xml-backend-xmloxide")]
impl PositionCursor<'_> {
    pub(super) fn take(&mut self, expected: SourceKind) -> Result<Range<usize>, ParseError> {
        let Some(node) = self.positions.get(self.next) else {
            return Err(source_map_mismatch(format!(
                "expected {expected:?}, but the lexical stream ended"
            )));
        };
        if node.kind != expected {
            return Err(source_map_mismatch(format!(
                "expected {expected:?}, found {:?}",
                node.kind
            )));
        }
        self.next += 1;
        Ok(node.range.clone())
    }

    pub(super) fn finish(&self) -> Result<(), ParseError> {
        if let Some(node) = self.positions.get(self.next) {
            Err(source_map_mismatch(format!(
                "unmapped lexical {:?} node remains",
                node.kind
            )))
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "xml-backend-xmloxide")]
fn source_map_mismatch(message: String) -> ParseError {
    ParseError::Backend {
        backend: "xmloxide-source-map",
        message,
    }
}
