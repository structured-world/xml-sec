use std::collections::HashSet;

use crate::budget::Meter;
use crate::{BudgetKind, Document, Error, NodeId, NodeKind, Result};

/// XSLT output method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMethod {
    #[default]
    Xml,
    Html,
    Text,
}

/// Compiled `xsl:output` properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDefinition {
    pub method: OutputMethod,
    pub version: Option<String>,
    pub encoding: String,
    pub omit_xml_declaration: bool,
    pub standalone: Option<bool>,
    pub doctype_public: Option<String>,
    pub doctype_system: Option<String>,
    pub indent: bool,
    pub media_type: Option<String>,
    pub cdata_section_elements: HashSet<crate::ExpandedName>,
    pub(crate) method_explicit: bool,
}

impl Default for OutputDefinition {
    fn default() -> Self {
        Self {
            method: OutputMethod::Xml,
            version: Some("1.0".into()),
            encoding: "UTF-8".into(),
            omit_xml_declaration: false,
            standalone: None,
            doctype_public: None,
            doctype_system: None,
            indent: false,
            media_type: None,
            cdata_section_elements: HashSet::new(),
            method_explicit: false,
        }
    }
}

/// Exact serialized result bytes and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedOutput {
    pub bytes: Vec<u8>,
    pub encoding: String,
    pub media_type: Option<String>,
}

pub(crate) fn serialize(
    document: &Document,
    definition: &OutputDefinition,
    meter: &mut Meter,
) -> Result<SerializedOutput> {
    let mut definition = definition.clone();
    if !definition.method_explicit
        && document
            .node(document.root())
            .and_then(|root| root.children.first())
            .and_then(|id| document.node(*id))
            .is_some_and(|node| matches!(&node.kind, NodeKind::Element { name, .. } if name.namespace.is_none() && name.local.eq_ignore_ascii_case("html")))
    {
        definition.method = OutputMethod::Html;
    }
    let mut text = String::new();
    if definition.method == OutputMethod::Xml && !definition.omit_xml_declaration {
        text.push_str("<?xml version=\"");
        text.push_str(definition.version.as_deref().unwrap_or("1.0"));
        text.push_str("\" encoding=\"");
        text.push_str(&definition.encoding);
        text.push('"');
        if let Some(standalone) = definition.standalone {
            text.push_str(if standalone {
                " standalone=\"yes\""
            } else {
                " standalone=\"no\""
            });
        }
        text.push_str("?>");
        if definition.indent {
            text.push('\n');
        }
    }
    if let Some(root_name) = document
        .node(document.root())
        .and_then(|root| root.children.iter().find_map(|id| document.node(*id)))
        .and_then(|node| match &node.kind {
            NodeKind::Element { name, prefix, .. } => {
                Some((prefix.as_deref(), name.local.as_str()))
            }
            _ => None,
        })
        && (definition.doctype_public.is_some() || definition.doctype_system.is_some())
    {
        text.push_str("<!DOCTYPE ");
        push_name(root_name.0, root_name.1, &mut text);
        match (&definition.doctype_public, &definition.doctype_system) {
            (Some(public), system) => {
                text.push_str(" PUBLIC \"");
                text.push_str(public);
                text.push('"');
                if let Some(system) = system {
                    text.push_str(" \"");
                    text.push_str(system);
                    text.push('"');
                }
            }
            (None, Some(system)) => {
                text.push_str(" SYSTEM \"");
                text.push_str(system);
                text.push('"');
            }
            (None, None) => {}
        }
        text.push('>');
        if definition.indent {
            text.push('\n');
        }
    }
    for child in &document
        .node(document.root())
        .ok_or_else(|| Error::Serialization("missing result root".into()))?
        .children
    {
        serialize_node(document, *child, &definition, &mut text, 0, None)?;
    }
    let bytes = encode(&text, &definition.encoding)?;
    meter.charge(BudgetKind::SerializedBytes, bytes.len())?;
    Ok(SerializedOutput {
        bytes,
        encoding: definition.encoding.clone(),
        media_type: definition.media_type.clone(),
    })
}

fn serialize_node(
    document: &Document,
    id: NodeId,
    definition: &OutputDefinition,
    output: &mut String,
    depth: usize,
    parent_name: Option<&crate::ExpandedName>,
) -> Result<()> {
    let node = document
        .node(id)
        .ok_or_else(|| Error::Serialization("invalid result node".into()))?;
    match &node.kind {
        NodeKind::Root => {
            for child in &node.children {
                serialize_node(document, *child, definition, output, depth, parent_name)?;
            }
        }
        NodeKind::Text {
            value,
            disable_output_escaping,
        } => {
            if definition.method == OutputMethod::Text
                || *disable_output_escaping
                || parent_name.is_some_and(|name| {
                    definition.method == OutputMethod::Html
                        && matches!(name.local.to_ascii_lowercase().as_str(), "script" | "style")
                })
            {
                output.push_str(value);
            } else if parent_name
                .is_some_and(|name| definition.cdata_section_elements.contains(name))
            {
                output.push_str("<![CDATA[");
                output.push_str(&value.replace("]]>", "]]><![CDATA[>"));
                output.push_str("]]>");
            } else {
                escape_text(value, output);
            }
        }
        NodeKind::Comment(value) if definition.method != OutputMethod::Text => {
            output.push_str("<!--");
            output.push_str(value);
            output.push_str("-->");
        }
        NodeKind::ProcessingInstruction { target, value }
            if definition.method != OutputMethod::Text =>
        {
            output.push_str("<?");
            output.push_str(target);
            if let Some(value) = value {
                output.push(' ');
                output.push_str(value);
            }
            output.push_str("?>");
        }
        NodeKind::Element { .. } if definition.method == OutputMethod::Text => {
            for child in &node.children {
                serialize_node(document, *child, definition, output, depth, parent_name)?;
            }
        }
        NodeKind::Element {
            name,
            prefix,
            attributes,
            namespaces,
        } if definition.method != OutputMethod::Text => {
            if definition.indent && depth > 0 {
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
            }
            output.push('<');
            push_name(prefix.as_deref(), &name.local, output);
            for namespace in namespaces {
                output.push_str(" xmlns");
                if let Some(prefix) = &namespace.prefix {
                    output.push(':');
                    output.push_str(prefix);
                }
                output.push_str("=\"");
                escape_attribute(&namespace.uri, output);
                output.push('"');
            }
            for attribute in attributes {
                output.push(' ');
                push_name(attribute.prefix.as_deref(), &attribute.name.local, output);
                output.push_str("=\"");
                escape_attribute(&attribute.value, output);
                output.push('"');
            }
            output.push('>');
            for child in &node.children {
                serialize_node(document, *child, definition, output, depth + 1, Some(name))?;
            }
            if definition.indent
                && node.children.iter().any(|child| {
                    matches!(
                        document.node(*child).map(|node| &node.kind),
                        Some(NodeKind::Element { .. })
                    )
                })
            {
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
            }
            let html_void = definition.method == OutputMethod::Html
                && name.namespace.is_none()
                && matches!(
                    name.local.to_ascii_lowercase().as_str(),
                    "area"
                        | "base"
                        | "basefont"
                        | "br"
                        | "col"
                        | "frame"
                        | "hr"
                        | "img"
                        | "input"
                        | "isindex"
                        | "link"
                        | "meta"
                        | "param"
                );
            if !html_void {
                output.push_str("</");
                push_name(prefix.as_deref(), &name.local, output);
                output.push('>');
            }
        }
        _ => {}
    }
    Ok(())
}

fn push_name(prefix: Option<&str>, local: &str, output: &mut String) {
    if let Some(prefix) = prefix {
        output.push_str(prefix);
        output.push(':');
    }
    output.push_str(local);
}

fn escape_text(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(character),
        }
    }
}

fn escape_attribute(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            '\r' => output.push_str("&#13;"),
            '\n' => output.push_str("&#10;"),
            '\t' => output.push_str("&#9;"),
            _ => output.push(character),
        }
    }
}

fn encode(value: &str, label: &str) -> Result<Vec<u8>> {
    if label.eq_ignore_ascii_case("utf-8") {
        return Ok(value.as_bytes().to_vec());
    }
    if label.eq_ignore_ascii_case("iso-8859-1") || label.eq_ignore_ascii_case("latin1") {
        return value
            .chars()
            .map(|character| {
                u8::try_from(u32::from(character)).map_err(|_| {
                    Error::Serialization(format!(
                        "character U+{:04X} is not representable in ISO-8859-1",
                        u32::from(character)
                    ))
                })
            })
            .collect();
    }
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes())
        .ok_or_else(|| Error::Serialization(format!("unsupported output encoding {label}")))?;
    let (bytes, _, had_errors) = encoding.encode(value);
    if had_errors {
        return Err(Error::Serialization(format!(
            "output is not representable in {label}"
        )));
    }
    Ok(bytes.into_owned())
}
