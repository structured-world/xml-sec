//! Shared lexical preflight and source-position sidecar for every DOM backend.

use std::ops::Range;

use quick_xml::{Reader, events::Event};

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

pub(super) struct LexicalPreflight {
    nodes: Vec<SourceNode>,
    #[cfg(feature = "xml-backend-roxmltree")]
    doctype: Option<Range<usize>>,
}

impl LexicalPreflight {
    pub(super) fn scan(input: &str, allow_dtd: bool) -> Result<Self, ParseError> {
        let mut reader = Reader::from_str(input);
        let mut nodes: Vec<SourceNode> = Vec::new();
        let mut elements = Vec::new();
        let mut namespace_scopes = Vec::new();
        let mut active_namespace_bindings = 0usize;
        #[cfg(feature = "xml-backend-roxmltree")]
        let mut doctype = None;
        loop {
            let start = source_offset(reader.buffer_position())?;
            let event = reader.read_event().map_err(|error| ParseError::Backend {
                backend: "xml-preflight",
                message: error.to_string(),
            })?;
            let end = source_offset(reader.buffer_position())?;
            match event {
                Event::Start(element) => {
                    let depth = elements.len() + 1;
                    enforce_depth(depth)?;
                    let declarations = namespace_declaration_count(&element)?;
                    active_namespace_bindings = active_namespace_bindings
                        .checked_add(declarations)
                        .ok_or(ParseError::NamespaceBindingLimitReached {
                            maximum: crate::hard_limits::XML_NAMESPACE_BINDING_CEILING,
                            actual: usize::MAX,
                        })?;
                    enforce_namespace_bindings(active_namespace_bindings)?;
                    let index = nodes.len();
                    nodes.push(SourceNode {
                        kind: SourceKind::Element,
                        range: start..end,
                    });
                    elements.push(index);
                    namespace_scopes.push(declarations);
                }
                Event::Empty(element) => {
                    enforce_depth(elements.len() + 1)?;
                    let declarations = namespace_declaration_count(&element)?;
                    let active = active_namespace_bindings.checked_add(declarations).ok_or(
                        ParseError::NamespaceBindingLimitReached {
                            maximum: crate::hard_limits::XML_NAMESPACE_BINDING_CEILING,
                            actual: usize::MAX,
                        },
                    )?;
                    enforce_namespace_bindings(active)?;
                    nodes.push(SourceNode {
                        kind: SourceKind::Element,
                        range: start..end,
                    });
                }
                Event::End(_) => {
                    if let Some(index) = elements.pop() {
                        nodes[index].range.end = end;
                    }
                    if let Some(declarations) = namespace_scopes.pop() {
                        active_namespace_bindings -= declarations;
                    }
                }
                // Both supported DOMs omit whitespace outside the document
                // element, so it must not shift the semantic sidecar.
                Event::Text(_) if !elements.is_empty() => {
                    push_text_position(&mut nodes, start..end);
                }
                Event::Text(_) => {}
                Event::CData(_) => nodes.push(SourceNode {
                    kind: SourceKind::CData,
                    range: start..end,
                }),
                Event::GeneralRef(reference)
                    if is_builtin_or_character_reference(reference.as_ref()) =>
                {
                    push_text_position(&mut nodes, start..end);
                }
                Event::GeneralRef(_) => nodes.push(SourceNode {
                    kind: SourceKind::EntityRef,
                    range: start..end,
                }),
                Event::Comment(_) => nodes.push(SourceNode {
                    kind: SourceKind::Comment,
                    range: start..end,
                }),
                Event::PI(_) => nodes.push(SourceNode {
                    kind: SourceKind::Pi,
                    range: start..end,
                }),
                Event::DocType(_) if !allow_dtd => return Err(ParseError::DtdDetected),
                #[cfg(feature = "xml-backend-roxmltree")]
                Event::DocType(_) => doctype = Some(start..end),
                Event::Eof => break,
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
            #[cfg(feature = "xml-backend-roxmltree")]
            doctype,
        })
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

fn enforce_namespace_bindings(actual: usize) -> Result<(), ParseError> {
    let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
    if actual > maximum {
        Err(ParseError::NamespaceBindingLimitReached { maximum, actual })
    } else {
        Ok(())
    }
}

fn namespace_declaration_count(
    element: &quick_xml::events::BytesStart<'_>,
) -> Result<usize, ParseError> {
    element
        .attributes()
        .map(|attribute| {
            attribute
                .map(|attribute| {
                    let name = attribute.key.as_ref();
                    usize::from(name == "xmlns" || name.starts_with("xmlns:"))
                })
                .map_err(|error| ParseError::Backend {
                    backend: "xml-preflight",
                    message: error.to_string(),
                })
        })
        .try_fold(0usize, |count, declaration| {
            declaration.and_then(|declaration| {
                count
                    .checked_add(declaration)
                    .ok_or(ParseError::NamespaceBindingLimitReached {
                        maximum: crate::hard_limits::XML_NAMESPACE_BINDING_CEILING,
                        actual: usize::MAX,
                    })
            })
        })
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

fn source_offset(offset: u64) -> Result<usize, ParseError> {
    usize::try_from(offset).map_err(|_| ParseError::Backend {
        backend: "xml-preflight",
        message: "XML source offset exceeds the platform address space".to_owned(),
    })
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
