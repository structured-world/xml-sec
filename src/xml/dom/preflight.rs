//! Shared lexical preflight and source-position sidecar for every DOM backend.

use std::{collections::HashMap, ops::Range};

use xml_sec_xml_input::lexical::{Event, Scanner, StartTag};

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
        let mut reader = Scanner::new(input);
        let mut nodes: Vec<SourceNode> = Vec::new();
        let mut elements = Vec::new();
        let mut namespace_scopes = Vec::new();
        let mut active_namespace_bindings = HashMap::new();
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
                    let changes =
                        apply_namespace_declarations(&element, &mut active_namespace_bindings);
                    enforce_namespace_bindings(active_namespace_bindings.len())?;
                    let index = nodes.len();
                    nodes.push(SourceNode {
                        kind: SourceKind::Element,
                        range: element.range.clone(),
                    });
                    elements.push(index);
                    namespace_scopes.push(changes);
                }
                Event::Empty(element) => {
                    enforce_depth(elements.len() + 1)?;
                    let changes =
                        apply_namespace_declarations(&element, &mut active_namespace_bindings);
                    enforce_namespace_bindings(active_namespace_bindings.len())?;
                    restore_namespace_bindings(changes, &mut active_namespace_bindings);
                    nodes.push(SourceNode {
                        kind: SourceKind::Element,
                        range: element.range,
                    });
                }
                Event::End { range, .. } => {
                    if let Some(index) = elements.pop() {
                        nodes[index].range.end = range.end;
                    }
                    if let Some(changes) = namespace_scopes.pop() {
                        restore_namespace_bindings(changes, &mut active_namespace_bindings);
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
                #[cfg(feature = "xml-backend-roxmltree")]
                Event::DocType { range, .. } => doctype = Some(range),
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

fn apply_namespace_declarations<'a>(
    element: &StartTag<'a>,
    active: &mut HashMap<&'a str, &'a str>,
) -> Vec<(&'a str, Option<&'a str>)> {
    let mut changes = Vec::new();
    for attribute in &element.attributes {
        let prefix = if attribute.name.prefix().is_none() && attribute.name.local() == "xmlns" {
            ""
        } else if attribute.name.prefix() == Some("xmlns") {
            attribute.name.local()
        } else {
            continue;
        };
        let previous = if attribute.value.is_empty() {
            active.remove(prefix)
        } else {
            active.insert(prefix, attribute.value)
        };
        changes.push((prefix, previous));
    }
    changes
}

fn restore_namespace_bindings<'a>(
    changes: Vec<(&'a str, Option<&'a str>)>,
    active: &mut HashMap<&'a str, &'a str>,
) {
    for (prefix, previous) in changes.into_iter().rev() {
        if let Some(uri) = previous {
            active.insert(prefix, uri);
        } else {
            active.remove(prefix);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_shadowing_does_not_inflate_active_binding_count() {
        // Namespace Namespaces in XML 1.0 section 6.1 defines a prefix binding by its nearest
        // declaration; shadowing replaces that active binding rather than adding another one.
        // https://www.w3.org/TR/REC-xml-names/#scoping-defaulting
        let mut xml = String::new();
        for depth in 0..220 {
            xml.push_str("<n");
            for prefix in 0..5 {
                xml.push_str(&format!(r#" xmlns:p{prefix}="urn:{depth}:{prefix}""#));
            }
            xml.push('>');
        }
        xml.push_str(&"</n>".repeat(220));

        LexicalPreflight::scan(&xml, false)
            .expect("five repeatedly shadowed prefixes remain five active bindings");
    }

    #[test]
    fn distinct_active_namespace_bindings_still_hit_the_ceiling() {
        let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
        let declarations = (0..=maximum)
            .map(|index| format!(r#" xmlns:p{index}="urn:{index}""#))
            .collect::<String>();
        let xml = format!("<root{declarations}/>");

        assert!(matches!(
            LexicalPreflight::scan(&xml, false),
            Err(ParseError::NamespaceBindingLimitReached {
                maximum: observed_maximum,
                actual,
            }) if observed_maximum == maximum && actual == maximum + 1
        ));
    }
}
