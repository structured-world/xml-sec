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
    serialize_charged(document, definition, meter, BudgetKind::SerializedBytes)
}

pub(crate) fn serialize_projection(document: &Document, meter: &mut Meter) -> Result<String> {
    let definition = OutputDefinition {
        omit_xml_declaration: true,
        method_explicit: true,
        ..OutputDefinition::default()
    };
    let output = serialize_charged(document, &definition, meter, BudgetKind::OwnedBytes)?;
    String::from_utf8(output.bytes)
        .map_err(|_| Error::Serialization("semantic projection is not UTF-8".into()))
}

fn serialize_charged(
    document: &Document,
    definition: &OutputDefinition,
    meter: &mut Meter,
    budget_kind: BudgetKind,
) -> Result<SerializedOutput> {
    let mut definition = definition.clone();
    if !definition.method_explicit
        && first_element(document)
            .is_some_and(|node| matches!(&node.kind, NodeKind::Element { name, .. } if name.namespace.is_none() && name.local.eq_ignore_ascii_case("html")))
    {
        definition.method = OutputMethod::Html;
    }
    let mut counter = RenderBuffer::Count(EncodingCounter::new(&definition.encoding)?);
    render(document, &definition, &mut counter)?;
    let text_bytes = counter.len();
    let encoded_bytes = counter.encoded_len();
    meter.check_additional(budget_kind, encoded_bytes)?;
    meter.charge(BudgetKind::OwnedBytes, text_bytes)?;
    let mut text = RenderBuffer::Text(String::with_capacity(text_bytes));
    render(document, &definition, &mut text)?;
    let text = text.into_string();
    validate_xml_characters(&text, definition.version.as_deref().unwrap_or("1.0"))?;
    let bytes = encode(&text, &definition.encoding, meter, budget_kind)?;
    Ok(SerializedOutput {
        bytes,
        encoding: definition.encoding.clone(),
        media_type: definition.media_type.clone(),
    })
}

fn render(
    document: &Document,
    definition: &OutputDefinition,
    text: &mut RenderBuffer,
) -> Result<()> {
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
        && definition.doctype_system.is_some()
    {
        text.push_str("<!DOCTYPE ");
        push_name(root_name.0, root_name.1, text);
        match (&definition.doctype_public, &definition.doctype_system) {
            (Some(public), Some(system)) => {
                text.push_str(" PUBLIC \"");
                text.push_str(public);
                text.push('"');
                text.push_str(" \"");
                text.push_str(system);
                text.push('"');
            }
            (Some(_), None) => {}
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
        serialize_node(document, *child, definition, text, 0, None, false)?;
    }
    Ok(())
}

enum RenderBuffer {
    Count(EncodingCounter),
    Text(String),
}

impl RenderBuffer {
    fn push_str(&mut self, value: &str) {
        match self {
            Self::Count(counter) => counter.push_str(value),
            Self::Text(output) => output.push_str(value),
        }
    }

    fn push(&mut self, value: char) {
        match self {
            Self::Count(counter) => counter.push(value),
            Self::Text(output) => output.push(value),
        }
    }

    const fn len(&self) -> usize {
        match self {
            Self::Count(counter) => counter.utf8_bytes,
            Self::Text(output) => output.len(),
        }
    }

    fn into_string(self) -> String {
        match self {
            Self::Text(output) => output,
            Self::Count(_) => unreachable!("counting buffer does not contain rendered text"),
        }
    }

    fn encoded_len(&mut self) -> usize {
        match self {
            Self::Count(counter) => counter.finish(),
            Self::Text(output) => output.len(),
        }
    }
}

enum EncodingCounterKind {
    Utf8,
    Latin1,
    Utf16,
    Other(encoding_rs::Encoder),
}

struct EncodingCounter {
    utf8_bytes: usize,
    encoded_bytes: usize,
    kind: EncodingCounterKind,
    finished: bool,
}

impl EncodingCounter {
    fn new(label: &str) -> Result<Self> {
        let kind = if label.eq_ignore_ascii_case("utf-8") {
            EncodingCounterKind::Utf8
        } else if label.eq_ignore_ascii_case("iso-8859-1") || label.eq_ignore_ascii_case("latin1") {
            EncodingCounterKind::Latin1
        } else if matches!(
            label.to_ascii_lowercase().as_str(),
            "utf-16" | "utf-16le" | "utf-16be"
        ) {
            EncodingCounterKind::Utf16
        } else {
            let encoding = encoding_rs::Encoding::for_label(label.as_bytes()).ok_or_else(|| {
                Error::Serialization(format!("unsupported output encoding {label}"))
            })?;
            EncodingCounterKind::Other(encoding.new_encoder())
        };
        let encoded_bytes = matches!(kind, EncodingCounterKind::Utf16)
            .then_some(2)
            .unwrap_or(0);
        Ok(Self {
            utf8_bytes: 0,
            encoded_bytes,
            kind,
            finished: false,
        })
    }

    fn push(&mut self, character: char) {
        let mut buffer = [0_u8; 4];
        self.push_str(character.encode_utf8(&mut buffer));
    }

    fn push_str(&mut self, value: &str) {
        self.utf8_bytes = self.utf8_bytes.saturating_add(value.len());
        match &mut self.kind {
            EncodingCounterKind::Utf8 => {
                self.encoded_bytes = self.encoded_bytes.saturating_add(value.len())
            }
            EncodingCounterKind::Latin1 => {
                for character in value.chars() {
                    self.encoded_bytes = self.encoded_bytes.saturating_add(
                        u8::try_from(u32::from(character))
                            .map_or_else(|_| format!("&#{};", u32::from(character)).len(), |_| 1),
                    );
                }
            }
            EncodingCounterKind::Utf16 => {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_add(value.encode_utf16().count().saturating_mul(2));
            }
            EncodingCounterKind::Other(encoder) => {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_add(count_encoded(encoder, value, false));
            }
        }
    }

    fn finish(&mut self) -> usize {
        if !self.finished {
            if let EncodingCounterKind::Other(encoder) = &mut self.kind {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_add(count_encoded(encoder, "", true));
            }
            self.finished = true;
        }
        self.encoded_bytes
    }
}

fn count_encoded(encoder: &mut encoding_rs::Encoder, mut source: &str, last: bool) -> usize {
    let mut total = 0usize;
    let mut buffer = [0_u8; 4096];
    loop {
        let (result, read, written, _) = encoder.encode_from_utf8(source, &mut buffer, last);
        total = total.saturating_add(written);
        source = &source[read..];
        match result {
            encoding_rs::CoderResult::InputEmpty => break,
            encoding_rs::CoderResult::OutputFull => {}
        }
    }
    total
}

fn serialize_node(
    document: &Document,
    id: NodeId,
    definition: &OutputDefinition,
    output: &mut RenderBuffer,
    depth: usize,
    parent_name: Option<&crate::ExpandedName>,
    parent_mixed: bool,
) -> Result<()> {
    let node = document
        .node(id)
        .ok_or_else(|| Error::Serialization("invalid result node".into()))?;
    match &node.kind {
        NodeKind::Root => {
            for child in &node.children {
                serialize_node(
                    document,
                    *child,
                    definition,
                    output,
                    depth,
                    parent_name,
                    parent_mixed,
                )?;
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
                serialize_node(
                    document,
                    *child,
                    definition,
                    output,
                    depth,
                    parent_name,
                    parent_mixed,
                )?;
            }
        }
        NodeKind::Element {
            name,
            prefix,
            attributes,
            namespaces,
        } if definition.method != OutputMethod::Text => {
            let mixed = node.children.iter().any(|child| {
                matches!(
                    document.node(*child).map(|child| &child.kind),
                    Some(NodeKind::Text { value, .. }) if !value.is_empty()
                )
            });
            if definition.indent && depth > 0 && !parent_mixed {
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
                serialize_node(
                    document,
                    *child,
                    definition,
                    output,
                    depth + 1,
                    Some(name),
                    mixed,
                )?;
            }
            if definition.indent
                && !mixed
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

fn push_name(prefix: Option<&str>, local: &str, output: &mut RenderBuffer) {
    if let Some(prefix) = prefix {
        output.push_str(prefix);
        output.push(':');
    }
    output.push_str(local);
}

fn escape_text(value: &str, output: &mut RenderBuffer) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(character),
        }
    }
}

fn escape_attribute(value: &str, output: &mut RenderBuffer) {
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

fn encode(value: &str, label: &str, meter: &mut Meter, budget_kind: BudgetKind) -> Result<Vec<u8>> {
    if label.eq_ignore_ascii_case("utf-8") {
        meter.charge(budget_kind, value.len())?;
        return Ok(value.as_bytes().to_vec());
    }
    if label.eq_ignore_ascii_case("iso-8859-1") || label.eq_ignore_ascii_case("latin1") {
        let mut bytes = Vec::new();
        for character in value.chars() {
            if let Ok(byte) = u8::try_from(u32::from(character)) {
                meter.charge(budget_kind, 1)?;
                bytes.push(byte);
            } else {
                let reference = format!("&#{};", u32::from(character));
                meter.charge(budget_kind, reference.len())?;
                bytes.extend_from_slice(reference.as_bytes());
            }
        }
        return Ok(bytes);
    }
    if label.eq_ignore_ascii_case("utf-16") || label.eq_ignore_ascii_case("utf-16le") {
        let units = value.encode_utf16().count();
        let length = units
            .checked_mul(2)
            .and_then(|length| length.checked_add(2))
            .unwrap_or(usize::MAX);
        meter.charge(budget_kind, length)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        return Ok(bytes);
    }
    if label.eq_ignore_ascii_case("utf-16be") {
        let units = value.encode_utf16().count();
        let length = units
            .checked_mul(2)
            .and_then(|length| length.checked_add(2))
            .unwrap_or(usize::MAX);
        meter.charge(budget_kind, length)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(&[0xFE, 0xFF]);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        return Ok(bytes);
    }
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes())
        .ok_or_else(|| Error::Serialization(format!("unsupported output encoding {label}")))?;
    let mut encoder = encoding.new_encoder();
    let mut source = value;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let (result, read, written, _) = encoder.encode_from_utf8(source, &mut buffer, true);
        meter.charge(budget_kind, written)?;
        bytes.extend_from_slice(&buffer[..written]);
        source = &source[read..];
        match result {
            encoding_rs::CoderResult::InputEmpty => break,
            encoding_rs::CoderResult::OutputFull => {}
        }
    }
    Ok(bytes)
}

fn first_element(document: &Document) -> Option<&crate::Node> {
    document
        .node(document.root())?
        .children
        .iter()
        .filter_map(|id| document.node(*id))
        .find(|node| matches!(node.kind, NodeKind::Element { .. }))
}

fn validate_xml_characters(value: &str, version: &str) -> Result<()> {
    for character in value.chars() {
        let code = u32::from(character);
        let valid = if version == "1.1" {
            matches!(code, 0x1..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
        } else {
            matches!(code, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
        };
        if !valid {
            return Err(Error::Serialization(format!(
                "character U+{code:04X} is forbidden by XML {version}"
            )));
        }
    }
    Ok(())
}
